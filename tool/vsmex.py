#!/usr/bin/env python3
# vsmex.py — incremental sync (APPLIES CHANGES)
# Only processes *new* identifiers from Microsoft lists (not already in msft_vscode_flagged_extensions.csv).
# For each new ID:
#  - appends ONE row to msft_vscode_flagged_extensions.csv (one row per extension)
#  - for ALL versions found in Azure: uploads artifact to vsmex-dataset/dataset/<id>/<ver>/<file>.vsix
#    and appends a row to vsmex_metadata.csv (skips duplicates by (identifier, version))
# Dates are YYYY-MM-DD; size_mb has a min of 0.01 for non-empty files.
# Large files (>= LARGE_FILE_THRESHOLD_MB) are uploaded via GitHub LFS Batch API (streamed from Azure).

from __future__ import annotations
import base64
import csv
import hashlib
import io
import json
import os
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

import requests
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError

# VSIX files >= this size are not uploaded via GitHub Contents API — use Git LFS instead
LARGE_FILE_THRESHOLD_MB = 100.0

try:
    import config
except ModuleNotFoundError:
    raise RuntimeError("Missing config.py — see config.py for required environment variables.")

GH_API = "https://api.github.com"


# ---------- GitHub (Contents API) ----------

def gh_headers():
    return {
        "Authorization": f"token {config.GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
    }


def gh_request(method: str, url: str, **kwargs) -> requests.Response:
    """GitHub API call with exponential backoff on 429 / 5xx."""
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


def gh_get_content(path: str, repo: str | None = None) -> Tuple[Optional[bytes], Optional[str]]:
    repo = repo or config.GITHUB_REPO
    url = f"{GH_API}/repos/{config.GITHUB_USERNAME}/{repo}/contents/{path}"
    r = gh_request("GET", url, headers=gh_headers(), params={"ref": config.GIT_BRANCH}, timeout=30)
    if r.status_code == 404:
        return None, None
    r.raise_for_status()
    data = r.json()
    return base64.b64decode(data["content"]), data.get("sha")


def gh_put_content(path: str, content_bytes: bytes, message: str, sha: Optional[str],
                   repo: str | None = None):
    repo = repo or config.GITHUB_REPO
    url = f"{GH_API}/repos/{config.GITHUB_USERNAME}/{repo}/contents/{path}"
    payload = {
        "message": message,
        "content": base64.b64encode(content_bytes).decode("ascii"),
        "branch": config.GIT_BRANCH,
    }
    if sha:
        payload["sha"] = sha
    r = gh_request("PUT", url, headers=gh_headers(), json=payload, timeout=180)
    if r.status_code >= 400:
        print(f"[github] PUT failed path={path} status={r.status_code} body={r.text}")
    r.raise_for_status()
    return r.json()


# ---------- Microsoft sources ----------

def fetch_text(url: str, timeout=30) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def parse_marketplace_json(txt: str) -> set[str]:
    try:
        data = json.loads(txt)
        arr = data.get("malicious") or []
        return {s.strip() for s in arr if isinstance(s, str) and s.strip()}
    except Exception:
        return set()


def parse_removed_md(txt: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in io.StringIO(txt):
        line = raw.strip()
        if not line.startswith("|") or "---" in line:
            continue
        parts = [p.strip() for p in line.split("|") if p.strip() != ""]
        if len(parts) >= 3 and not parts[0].lower().startswith("extension identifier"):
            out[parts[0]] = parts[2]
    return out


# ---------- Azure ----------

def get_cc():
    svc = BlobServiceClient.from_connection_string(config.AZURE_CONNECTION_STRING)
    return svc.get_container_client(config.AZURE_CONTAINER_NAME)


def blob_exists(cc, blob_path: str) -> bool:
    try:
        cc.get_blob_client(blob_path).get_blob_properties()
        return True
    except ResourceNotFoundError:
        return False


def get_blob_size_mb(cc, blob_path: str) -> float:
    props = cc.get_blob_client(blob_path).get_blob_properties()
    return props["size"] / 1_000_000


def download_blob_bytes(cc, blob_path: str) -> bytes:
    return cc.get_blob_client(blob_path).download_blob().readall()


def stream_azure_to_temp(cc, blob_path: str) -> Tuple[str, str, int]:
    """Stream blob to a temp file. Returns (tmp_path, sha256_hex, size_bytes)."""
    h = hashlib.sha256()
    size = 0
    with tempfile.NamedTemporaryFile(delete=False, suffix=".vsix") as f:
        tmp_path = f.name
        for chunk in cc.get_blob_client(blob_path).download_blob().chunks():
            f.write(chunk)
            h.update(chunk)
            size += len(chunk)
    return tmp_path, h.hexdigest(), size


def upload_lfs_object(repo: str, oid: str, size: int, tmp_path: str) -> bool:
    """Upload file to GitHub LFS via Batch API. Returns True if newly uploaded."""
    batch_url = f"https://github.com/{config.GITHUB_USERNAME}/{repo}.git/info/lfs/objects/batch"
    auth = base64.b64encode(f"{config.GITHUB_USERNAME}:{config.GITHUB_PAT}".encode()).decode()
    lfs_hdrs = {
        "Accept": "application/vnd.git-lfs+json",
        "Content-Type": "application/vnd.git-lfs+json",
        "Authorization": f"Basic {auth}",
    }
    r = requests.post(batch_url, json={
        "operation": "upload", "transfers": ["basic"],
        "objects": [{"oid": oid, "size": size}],
    }, headers=lfs_hdrs, timeout=30)
    r.raise_for_status()
    obj = r.json()["objects"][0]
    if "error" in obj:
        raise RuntimeError(f"LFS batch error: {obj['error']}")
    upload_info = obj.get("actions", {}).get("upload")
    if not upload_info:
        return False  # already exists in LFS
    with open(tmp_path, "rb") as f:
        requests.put(upload_info["href"], data=f,
                     headers=upload_info.get("header", {}), timeout=600).raise_for_status()
    verify_info = obj.get("actions", {}).get("verify")
    if verify_info:
        requests.post(verify_info["href"], json={"oid": oid, "size": size},
                      headers={**lfs_hdrs, **verify_info.get("header", {})},
                      timeout=30).raise_for_status()
    return True


def commit_lfs_pointer(dataset_path: str, oid: str, size: int,
                       existing_sha: Optional[str], repo: str):
    """Commit an LFS pointer file to the GitHub repo."""
    pointer = f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {size}\n"
    gh_put_content(dataset_path, pointer.encode("utf-8"),
                   message=f"Add LFS pointer {dataset_path.split('/')[-1]}",
                   sha=existing_sha, repo=repo)


# ---------- metadata_master.jsonl index (Azure) ----------

def build_master_index(cc):
    by_version:   Dict[str, dict]        = {}
    latest_by_id: Dict[str, dict]        = {}
    all_by_id:    Dict[str, List[dict]]  = {}

    bc = cc.get_blob_client(config.MASTER_METADATA_BLOB)
    try:
        stream = bc.download_blob()
    except ResourceNotFoundError:
        raise SystemExit("[FATAL] Azure blob metadata_master.jsonl not found.")

    for chunk in stream.chunks():
        for line in chunk.splitlines():
            if not line:
                continue
            try:
                rec = json.loads(line.decode("utf-8"))
            except Exception:
                continue
            vkey = rec.get("_versionKey")
            eid  = rec.get("_extKey")
            if vkey:
                by_version[vkey] = rec
            if eid:
                latest_by_id[eid] = rec
                all_by_id.setdefault(eid, []).append(rec)

    return by_version, latest_by_id, all_by_id


# ---------- CSV helpers ----------

def load_csv_from_github(path: str, repo: str | None = None) -> Tuple[list[dict], Optional[str], list[str]]:
    raw, sha = gh_get_content(path, repo=repo)
    rows: list[dict] = []
    header: list[str] = []
    if raw:
        txt = raw.decode("utf-8")
        reader = csv.DictReader(io.StringIO(txt))
        header = list(reader.fieldnames or [])
        for r in reader:
            rows.append({k: (v or "").strip() for k, v in r.items()})
    return rows, sha, header


def write_csv_to_github(path: str, rows: list[dict], header: list[str], message: str,
                        repo: str | None = None):
    old_raw, old_sha = gh_get_content(path, repo=repo)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in header})
    new_bytes = buf.getvalue().encode("utf-8")
    if old_raw is not None and old_raw == new_bytes:
        print(f"No changes for {path} — skipping commit.")
        return
    gh_put_content(path, new_bytes, message, sha=old_sha, repo=repo)


# ---------- small helpers ----------

def str_bool(v) -> str:
    if v is True:  return "true"
    if v is False: return "false"
    return "unknown"


def fmt_num(n):
    if n is None:
        return "null"
    s = str(n).strip()
    if not s or s.lower() in {"null", "none", "n/a", "na"}:
        return "null"
    try:
        f = float(s)
        return str(int(f)) if f.is_integer() else str(f).rstrip("0").rstrip(".")
    except Exception:
        return "null"


def join_cats(cats) -> str:
    if not isinstance(cats, list) or not cats: return "Other"
    return ";".join(cats)


def norm_date(val) -> str:
    if not val: return "unknown"
    s = str(val)
    return s[:10] if len(s) >= 10 else s


def normalize_flags_field(value) -> str:
    if not value:
        return ""
    if isinstance(value, list):
        return ";".join([str(x).strip() for x in value if str(x).strip()])
    parts = [p.strip() for chunk in str(value).split(";") for p in chunk.split(",")]
    seen = []
    for p in parts:
        if p and p not in seen:
            seen.append(p)
    return ";".join(seen)


def normalize_msft_classification(s: str) -> str:
    if not s:
        return s
    raw = s.replace(";", ",")
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return ";".join(out)


def extract_vscode_engine_from_vsix(vsix_bytes: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(vsix_bytes), "r") as z:
            with z.open("extension/package.json") as f:
                pkg = json.load(f)
        engines = pkg.get("engines") or {}
        val = engines.get("vscode")
        return str(val).strip() if val else "null"
    except Exception:
        return "null"


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


def main():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cc = get_cc()

    # 1) Build index from Azure master metadata (all versions per extension)
    print("Building Azure metadata index …")
    by_version, latest_by_id, all_by_id = build_master_index(cc)
    print(f"  {len(by_version)} version records, {len(all_by_id)} extensions")

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

    # 3) Load current CSVs
    flagged_rows, _, _ = load_csv_from_github(config.CSV_FLAGGED, repo=config.GITHUB_REPO)
    meta_rows,    _, _ = load_csv_from_github(config.CSV_DATASET,  repo=config.GITHUB_DATASET_REPO)

    existing_ids = {r.get("extension_identifier", "") for r in flagged_rows if r.get("extension_identifier")}
    meta_keys    = {(r.get("extension_identifier", ""), r.get("version", "")) for r in meta_rows}

    # 4) Compute *new* identifiers only
    removed_new   = {eid for eid in removed_map  if eid not in existing_ids}
    malicious_new = {eid for eid in malicious_set if eid not in existing_ids}

    print(f"Existing flagged: {len(existing_ids)} | New removed: {len(removed_new)} | New malicious: {len(malicious_new)}")

    # Prefer removed_list when an ID appears in both
    worklist = []
    for eid in sorted(removed_new | malicious_new):
        if eid in removed_new:
            source         = "removed_list"
            classification = normalize_msft_classification(removed_map.get(eid, "Malware"))
        else:
            source         = "malicious_list"
            classification = "Malicious"
        worklist.append((source, eid, classification))

    uploaded_vsix    = 0
    new_meta_rows    = 0
    appended_flagged = 0

    for source, eid, classification in worklist:
        recs = all_by_id.get(eid, [])
        msft_removed_date = removed_map.get(eid, "none") if source == "removed_list" else "none"

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
            print(f"[add] {eid}: not in Azure metadata → captured=no")
            continue

        captured_versions: List[str] = []

        for rec in recs:
            version   = rec.get("version")
            vsix_name = rec.get("vsixFileName")
            if not version or not vsix_name:
                continue

            blob_path = f"{config.VSIX_PREFIX}/{vsix_name}"
            if not blob_exists(cc, blob_path):
                print(f"  [skip] {eid}@{version}: not in Azure blob storage")
                continue

            # Check size BEFORE downloading
            size_val = get_blob_size_mb(cc, blob_path)
            is_large = size_val >= LARGE_FILE_THRESHOLD_MB
            size_mb  = f"{max(size_val, 0.01):.2f}".rstrip("0").rstrip(".")

            dataset_path = f"{config.DATASET_ROOT}/{eid}/{version}/{vsix_name}"
            _, existing_sha = gh_get_content(dataset_path, repo=config.GITHUB_DATASET_REPO)

            if is_large:
                tmp_path = None
                try:
                    print(f"  [lfs] {eid}@{version}: streaming {size_mb} MB from Azure …")
                    tmp_path, sha256_hex, size_bytes = stream_azure_to_temp(cc, blob_path)
                    upload_lfs_object(config.GITHUB_DATASET_REPO, sha256_hex, size_bytes, tmp_path)
                    if existing_sha is None:
                        commit_lfs_pointer(dataset_path, sha256_hex, size_bytes,
                                           None, repo=config.GITHUB_DATASET_REPO)
                        uploaded_vsix += 1
                except Exception as e:
                    print(f"  [warn] LFS upload failed for {eid}@{version}: {e}")
                    sha256_hex = "N/A (large file)"
                finally:
                    if tmp_path and os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                engines_vscode = "null"
            else:
                vsix_bytes     = download_blob_bytes(cc, blob_path)
                sha256_hex     = hashlib.sha256(vsix_bytes).hexdigest()
                engines_vscode = extract_vscode_engine_from_vsix(vsix_bytes)
                if existing_sha is None:
                    try:
                        gh_put_content(
                            dataset_path, vsix_bytes,
                            message=f"Add VSIX {eid}@{version}",
                            sha=None, repo=config.GITHUB_DATASET_REPO,
                        )
                        uploaded_vsix += 1
                    except requests.exceptions.HTTPError as e:
                        print(f"  [warn] VSIX upload failed for {eid}@{version}: {e}")

            # Metadata row
            if (eid, version) not in meta_keys:
                pub   = rec.get("publisher") or {}
                stats = rec.get("statistics") or {}
                meta_rows.append({
                    "captured_date":            today,
                    "source":                   source,
                    "msft_classification_type": classification,
                    "extension_identifier":     eid,
                    "publisher_name":           pub.get("publisherName", "") or "",
                    "version":                  version,
                    "artifact":                 vsix_name,
                    "sha256":                   sha256_hex,
                    "size_mb":                  size_mb,
                    "published_date":           norm_date(rec.get("publishedDate")),
                    "last_updated_date":        norm_date(rec.get("lastUpdated")),
                    "verified_publisher":       str_bool(pub.get("isDomainVerified")),
                    "installation_count":       fmt_num(stats.get("install")),
                    "average_rating":           fmt_num(stats.get("averagerating")),
                    "rating_count":             fmt_num(stats.get("ratingcount")),
                    "categories":               join_cats(rec.get("categories", [])),
                    "repository_url":           rec.get("repository", "") or "none",
                    "flags":                    normalize_flags_field(rec.get("flags", "")),
                    "engines_vscode":           engines_vscode,
                    "exists_in_dataset":        "vsmex",
                })
                meta_keys.add((eid, version))
                new_meta_rows += 1

            captured_versions.append(version)
            print(f"  [add] {eid}@{version}: large={is_large} size={size_mb}MB sha256={sha256_hex[:16]}…")

        # One flagged row per extension (after processing all versions)
        latest_version = recs[-1].get("version", "none") if recs else "none"
        flagged_rows.append({
            "source":                   source,
            "checked_date":             today,
            "extension_identifier":     eid,
            "msft_classification_type": classification,
            "msft_removed_date":        msft_removed_date,
            "captured":                 "yes" if captured_versions else "no",
            "version_count":            str(len(captured_versions)),
            "latest_version":           latest_version,
            "capture_date":             today if captured_versions else "none",
        })
        appended_flagged += 1

    # 5) No-op guard
    if appended_flagged == 0 and new_meta_rows == 0 and uploaded_vsix == 0:
        print("No changes detected — nothing to commit.")
        return

    # 6) Write back CSVs
    write_csv_to_github(
        config.CSV_FLAGGED, flagged_rows, FLAG_HEADER,
        message=f"sync: +{appended_flagged} new flagged extensions",
        repo=config.GITHUB_REPO,
    )
    write_csv_to_github(
        config.CSV_DATASET, meta_rows, META_HEADER,
        message=f"sync: +{new_meta_rows} metadata rows, {uploaded_vsix} VSIX uploads",
        repo=config.GITHUB_DATASET_REPO,
    )

    print(f"✅ Done | +flagged:{appended_flagged} | +meta:{new_meta_rows} | uploads:{uploaded_vsix}")


if __name__ == "__main__":
    main()
