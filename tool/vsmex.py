#!/usr/bin/env python3
# vsmex.py — incremental sync (APPLIES CHANGES)
# For each new flagged extension:
#  - appends ONE row to msft_vscode_flagged_extensions.csv → public GitHub repo
#  - for ALL versions found in marketplace/: copies VSIX to vsmex-dataset/
#    and appends a row to vsmex_metadata.csv → public GitHub repo

from __future__ import annotations
import base64
import csv
import hashlib
import io
import json
import os
import shutil
import time
import zipfile
from datetime import datetime, timezone

import requests

import config

GH_API           = "https://api.github.com"
GITHUB_PAT       = os.environ.get("GITHUB_PAT")
if not GITHUB_PAT:
    raise RuntimeError("GITHUB_PAT not set. Source ~/.vsmex_env or export it.")
GITHUB_USERNAME  = os.environ.get("GITHUB_USERNAME", "your-github-username")
GITHUB_REPO      = os.environ.get("GITHUB_REPO", "vsmex")
GIT_BRANCH       = "main"
CSV_FLAGGED      = "metadata/msft_vscode_flagged_extensions.csv"
CSV_DATASET      = "metadata/vsmex_metadata.csv"
GH_STATS_PATH    = "stats.json"
LOG_FILE         = os.path.join(config.MARKETPLACE_DIR, "logs", "vsmex.log")


# ---------- GitHub (Contents API) ----------

def gh_headers():
    return {
        "Authorization": f"token {GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
    }

def gh_request(method, url, **kwargs):
    last_r = None
    for attempt in range(1, config.MAX_RETRIES + 1):
        r = requests.request(method, url, **kwargs)
        last_r = r
        if r.status_code == 429 or r.status_code >= 500:
            wait = config.RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            print(f"[github] {r.status_code} attempt {attempt}/{config.MAX_RETRIES}, retry in {wait:.1f}s")
            time.sleep(wait)
            continue
        return r
    return last_r

def gh_get_content(path):
    url = f"{GH_API}/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/{path}"
    r = gh_request("GET", url, headers=gh_headers(), params={"ref": GIT_BRANCH}, timeout=30)
    if r.status_code == 404:
        return None, None
    r.raise_for_status()
    data = r.json()
    return base64.b64decode(data["content"]), data.get("sha")

def gh_put_content(path, content_bytes, message, sha):
    url = f"{GH_API}/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/{path}"
    payload = {
        "message": message,
        "content": base64.b64encode(content_bytes).decode("ascii"),
        "branch": GIT_BRANCH,
    }
    if sha:
        payload["sha"] = sha
    r = gh_request("PUT", url, headers=gh_headers(), json=payload, timeout=180)
    if r.status_code >= 400:
        print(f"[github] PUT failed path={path} status={r.status_code} body={r.text}")
    r.raise_for_status()
    return r.json()


# ---------- Microsoft sources ----------

def fetch_text(url, timeout=30):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text

def parse_marketplace_json(txt):
    try:
        data = json.loads(txt)
        arr = data.get("malicious") or []
        return {s.strip() for s in arr if isinstance(s, str) and s.strip()}
    except Exception:
        return set()

def _norm_ms_date(s):
    from datetime import datetime as _dt
    try:
        return _dt.strptime(s.strip(), "%m/%d/%Y").strftime("%Y-%m-%d")
    except Exception:
        return s.strip()

def parse_removed_md(txt):
    out = {}
    for raw in io.StringIO(txt):
        line = raw.strip()
        if not line.startswith("|") or "---" in line:
            continue
        parts = [p.strip() for p in line.split("|") if p.strip() != ""]
        if len(parts) >= 3 and not parts[0].lower().startswith("extension identifier"):
            out[parts[0]] = (_norm_ms_date(parts[1]), parts[2])
    return out


# ---------- Local metadata index ----------

def build_master_index():
    path = config.MASTER_METADATA_FILE
    by_version = {}
    latest_by_id = {}
    all_by_id = {}

    if not os.path.isfile(path):
        raise SystemExit(f"[FATAL] metadata_master.jsonl not found at {path}")

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            vkey = rec.get("_versionKey")
            eid = rec.get("_extKey")
            if vkey:
                by_version[vkey] = rec
            if eid:
                latest_by_id[eid] = rec
                all_by_id.setdefault(eid, []).append(rec)

    return by_version, latest_by_id, all_by_id


# ---------- Local file helpers ----------

def marketplace_vsix_path(eid, version, vsix_name):
    return os.path.join(config.VSIX_DIR, eid, version, vsix_name)

def dataset_vsix_path(eid, version, vsix_name):
    return os.path.join(config.DATASET_EXTENSIONS_DIR, eid, version, vsix_name)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def copy_vsix(src, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".tmp"
    try:
        shutil.copy2(src, tmp)
        os.replace(tmp, dest)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

def extract_vscode_engine_from_vsix(vsix_path):
    try:
        with zipfile.ZipFile(vsix_path, "r") as z:
            with z.open("extension/package.json") as f:
                pkg = json.load(f)
        engines = pkg.get("engines") or {}
        val = engines.get("vscode")
        return str(val).strip() if val else "null"
    except Exception:
        return "null"


# ---------- CSV helpers (local source of truth, GitHub mirror) ----------

LOCAL_CSV_FLAGGED = os.path.join(config.DATASET_DIR, "metadata", "msft_vscode_flagged_extensions.csv")
LOCAL_CSV_DATASET = os.path.join(config.DATASET_DIR, "metadata", "vsmex_metadata.csv")

def load_csv(local_path, header):
    rows = []
    if os.path.isfile(local_path):
        with open(local_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append({k: (v or "").strip() for k, v in r.items()})
    return rows

def save_csv(local_path, rows, header):
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    tmp = local_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in header})
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, local_path)

def push_csv_to_github(local_path, gh_path, message):
    with open(local_path, "rb") as f:
        local_bytes = f.read()
    gh_raw, gh_sha = gh_get_content(gh_path)
    if gh_raw is not None and gh_raw == local_bytes:
        print(f"  No changes for {gh_path} -- skipping push.")
        return
    gh_put_content(gh_path, local_bytes, message, sha=gh_sha)


# ---------- small helpers ----------

def str_bool(v):
    if v is True: return "true"
    if v is False: return "false"
    return "unknown"

def fmt_num(n):
    if n is None: return "null"
    s = str(n).strip()
    if not s or s.lower() in {"null", "none", "n/a", "na"}: return "null"
    try:
        f = float(s)
        return str(int(f)) if f.is_integer() else str(f).rstrip("0").rstrip(".")
    except Exception:
        return "null"

def join_cats(cats):
    if not isinstance(cats, list) or not cats: return "Other"
    return ";".join(cats)

def norm_date(val):
    if not val: return "unknown"
    s = str(val)
    return s[:10] if len(s) >= 10 else s

def normalize_flags_field(value):
    if not value: return ""
    if isinstance(value, list):
        return ";".join([str(x).strip() for x in value if str(x).strip()])
    parts = [p.strip() for chunk in str(value).split(";") for p in chunk.split(",")]
    seen = []
    for p in parts:
        if p and p not in seen:
            seen.append(p)
    return ";".join(seen)

def normalize_msft_classification(s):
    if not s: return s
    raw = s.replace(";", ",")
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return ";".join(out)


# ---------- main ----------

FLAG_HEADER = [
    "source", "checked_date", "extension_identifier", "msft_classification_type",
    "msft_removed_date", "captured", "version_count", "latest_version", "capture_date",
]

META_HEADER = [
    "captured_date", "source", "msft_classification_type", "extension_identifier",
    "publisher_name", "version", "artifact", "sha256", "size_mb",
    "published_date", "last_updated_date", "verified_publisher",
    "installation_count", "average_rating", "rating_count",
    "categories", "repository_url", "flags", "engines_vscode", "exists_in_dataset",
]


def _now():
    return datetime.now(timezone.utc)

def now_stamp():
    return _now().strftime("%Y-%m-%d %H:%M:%S")

def _ensure_parent(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def append_log(msg):
    _ensure_parent(LOG_FILE)
    line = f"{now_stamp()} | {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())

def load_stats():
    if os.path.isfile(config.STATS_FILE):
        with open(config.STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_stats(stats):
    _ensure_parent(config.STATS_FILE)
    tmp = config.STATS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(stats, indent=2) + "\n")
    os.replace(tmp, config.STATS_FILE)


def main():
    today = _now().strftime("%Y-%m-%d")
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    # 1) Build index from local metadata
    print("Building metadata index ...")
    by_version, latest_by_id, all_by_id = build_master_index()
    print(f"  {len(by_version)} version records, {len(all_by_id)} extensions")
    append_log(f"RUN START versions={len(by_version)} extensions={len(all_by_id)}")

    # 2) Microsoft lists
    try:
        malicious_set = parse_marketplace_json(fetch_text(config.MSFT_MALICIOUS_URL))
    except Exception as e:
        print(f"[warn] marketplace.json fetch failed: {e}")
        malicious_set = set()
    try:
        removed_map = parse_removed_md(fetch_text(config.MSFT_REMOVED_URL))
    except Exception as e:
        print(f"[warn] RemovedPackages.md fetch failed: {e}")
        removed_map = {}

    print(f"Microsoft lists: {len(malicious_set)} malicious, {len(removed_map)} removed")

    # 3) Load current CSVs from local files
    flagged_rows = load_csv(LOCAL_CSV_FLAGGED, FLAG_HEADER)
    meta_rows = load_csv(LOCAL_CSV_DATASET, META_HEADER)

    existing_ids = {r.get("extension_identifier", "") for r in flagged_rows if r.get("extension_identifier")}
    existing_ids_low = {e.lower() for e in existing_ids}
    meta_keys = {(r.get("extension_identifier", ""), r.get("version", "")) for r in meta_rows}

    # 4) New identifiers only
    removed_new = {eid for eid in removed_map if eid.lower() not in existing_ids_low}
    malicious_new = {eid for eid in malicious_set if eid.lower() not in existing_ids_low}

    print(f"Existing flagged: {len(existing_ids)} | New removed: {len(removed_new)} | New malicious: {len(malicious_new)}")

    worklist = []
    for eid in sorted(removed_new | malicious_new):
        if eid in removed_new:
            source = "removed_list"
            classification = normalize_msft_classification(removed_map.get(eid, ("none", "Malware"))[1])
        else:
            source = "malicious_list"
            classification = "Malicious"
        worklist.append((source, eid, classification))

    downloaded_vsix = 0
    downloaded_bytes = 0
    new_meta_rows = 0
    appended_flagged = 0
    new_unique_extensions = set()

    try:
        for source, eid, classification in worklist:
            recs = all_by_id.get(eid, [])
            msft_removed_date = removed_map.get(eid, ("none", ""))[0] if source == "removed_list" else "none"

            if not recs:
                flagged_rows.append({
                    "source": source, "checked_date": today,
                    "extension_identifier": eid,
                    "msft_classification_type": classification,
                    "msft_removed_date": msft_removed_date,
                    "captured": "no", "version_count": "0",
                    "latest_version": "none", "capture_date": "none",
                })
                appended_flagged += 1
                print(f"[add] {eid}: not in metadata -> captured=no")
                continue

            captured_versions = []

            for rec in recs:
                version = rec.get("version")
                vsix_name = rec.get("vsixFileName")
                if not version or not vsix_name:
                    continue

                src_path = marketplace_vsix_path(eid, version, vsix_name)
                if not os.path.isfile(src_path):
                    print(f"  [skip] {eid}@{version}: not in marketplace storage")
                    continue

                size_bytes = os.path.getsize(src_path)
                size_val = size_bytes / 1_000_000
                size_mb = f"{max(size_val, 0.01):.2f}".rstrip("0").rstrip(".")

                dest = dataset_vsix_path(eid, version, vsix_name)

                if os.path.isfile(dest):
                    sha256_hex = sha256_file(dest)
                    engines_vscode = extract_vscode_engine_from_vsix(dest)
                    print(f"  [exists] {eid}@{version}: already in dataset")
                else:
                    try:
                        print(f"  [copy] {eid}@{version}: {size_mb} MB marketplace -> dataset ...")
                        copy_vsix(src_path, dest)
                        sha256_hex = sha256_file(dest)
                        downloaded_vsix += 1
                        downloaded_bytes += size_bytes
                        new_unique_extensions.add(eid)
                    except Exception as e:
                        print(f"  [warn] copy failed for {eid}@{version}: {e}")
                        append_log(f"COPY FAILED {eid}@{version}: {e}")
                        sha256_hex = "N/A"
                    engines_vscode = extract_vscode_engine_from_vsix(dest) if os.path.isfile(dest) else "null"

                if (eid, version) not in meta_keys:
                    pub = rec.get("publisher") or {}
                    stats = rec.get("statistics") or {}
                    meta_rows.append({
                        "captured_date": today,
                        "source": source,
                        "msft_classification_type": classification,
                        "extension_identifier": eid,
                        "publisher_name": pub.get("publisherName", "") or "",
                        "version": version,
                        "artifact": vsix_name,
                        "sha256": sha256_hex,
                        "size_mb": size_mb,
                        "published_date": norm_date(rec.get("publishedDate")),
                        "last_updated_date": norm_date(rec.get("lastUpdated")),
                        "verified_publisher": str_bool(pub.get("isDomainVerified")),
                        "installation_count": fmt_num(stats.get("install")),
                        "average_rating": fmt_num(stats.get("averagerating")),
                        "rating_count": fmt_num(stats.get("ratingcount")),
                        "categories": join_cats(rec.get("categories", [])),
                        "repository_url": rec.get("repository", "") or "none",
                        "flags": normalize_flags_field(rec.get("flags", "")),
                        "engines_vscode": engines_vscode,
                        "exists_in_dataset": "vsmex",
                    })
                    meta_keys.add((eid, version))
                    new_meta_rows += 1

                captured_versions.append(version)
                print(f"  [add] {eid}@{version}: size={size_mb}MB sha256={sha256_hex[:16]}...")

            latest_version = recs[-1].get("version", "none") if recs else "none"
            flagged_rows.append({
                "source": source,
                "checked_date": today,
                "extension_identifier": eid,
                "msft_classification_type": classification,
                "msft_removed_date": msft_removed_date,
                "captured": "yes" if captured_versions else "no",
                "version_count": str(len(captured_versions)),
                "latest_version": latest_version,
                "capture_date": today if captured_versions else "none",
            })
            appended_flagged += 1

        # 5) No-op guard
        if appended_flagged == 0 and new_meta_rows == 0 and downloaded_vsix == 0:
            print("No changes detected -- nothing to commit.")
            append_log("RUN END no changes")
            return

        # 6) Save locally first
        save_csv(LOCAL_CSV_FLAGGED, flagged_rows, FLAG_HEADER)
        save_csv(LOCAL_CSV_DATASET, meta_rows, META_HEADER)
        print(f"  Local CSVs saved ({len(flagged_rows)} flagged, {len(meta_rows)} metadata)")

        # 7) Push to GitHub
        push_csv_to_github(LOCAL_CSV_FLAGGED, CSV_FLAGGED,
                           f"sync: +{appended_flagged} new flagged extensions")
        push_csv_to_github(LOCAL_CSV_DATASET, CSV_DATASET,
                           f"sync: +{new_meta_rows} metadata rows, {downloaded_vsix} VSIX copies")

    except KeyboardInterrupt:
        print("\nInterrupted.")
        append_log("RUN INTERRUPTED by user")
    except OSError as e:
        print(f"\nDisk error: {e}")
        append_log(f"RUN ABORTED disk error: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        append_log(f"RUN ABORTED unexpected: {e}")
    finally:
        summary = (f"RUN END flagged={appended_flagged} meta={new_meta_rows} "
                    f"copies={downloaded_vsix} unique={len(new_unique_extensions)}")
        print(f"\n{summary}")
        try:
            append_log(summary)
        except OSError:
            pass

        try:
            stats = load_stats()
            ds = stats.get("dataset", {})
            ds["total_flagged"] = len(flagged_rows)
            ds["total_captured"] = len(meta_rows)
            vsix_count = 0
            vsix_bytes = 0
            ext_dirs = set()
            ds_ext_dir = config.DATASET_EXTENSIONS_DIR
            if os.path.isdir(ds_ext_dir):
                for eid in os.listdir(ds_ext_dir):
                    eid_dir = os.path.join(ds_ext_dir, eid)
                    if not os.path.isdir(eid_dir):
                        continue
                    ext_dirs.add(eid)
                    for ver in os.listdir(eid_dir):
                        ver_dir = os.path.join(eid_dir, ver)
                        if not os.path.isdir(ver_dir):
                            continue
                        for fname in os.listdir(ver_dir):
                            if fname.endswith(".vsix"):
                                vsix_count += 1
                                vsix_bytes += os.path.getsize(os.path.join(ver_dir, fname))
            ds["total_vsix_files"] = vsix_count
            ds["unique_extensions"] = len(ext_dirs)
            ds["total_size_gb"] = round(vsix_bytes / 1e9, 2)
            ds["last_sync"] = now_stamp()
            stats["dataset"] = ds
            save_stats(stats)

            if appended_flagged > 0 or new_meta_rows > 0 or downloaded_vsix > 0:
                stats_bytes = json.dumps(stats, indent=2).encode("utf-8")
                gh_put_content(
                    GH_STATS_PATH, stats_bytes,
                    message=f"stats: update {now_stamp()}",
                    sha=gh_get_content(GH_STATS_PATH)[1],
                )
        except Exception as e:
            print(f"WARNING: failed to update stats: {e}")


if __name__ == "__main__":
    main()
