#!/usr/bin/env python3
# vsmex.py — incremental sync (APPLIES CHANGES)
# Only processes *new* identifiers from Microsoft lists (not already in msft_vscode_flagged_extensions.csv).
# For each new ID:
#  - append a row to msft_vscode_flagged_extensions.csv (exists_in_dataset yes/no)
#  - if VSIX exists in Azure: upload artifact to dataset/<id>/<version>/<file>.vsix (if missing)
#    and append a row to vsmex_metadata.csv (skips duplicates by (identifier, version))
# Dates are YYYY-MM-DD; captured_date = today; size_mb has a min of 0.01 for non-empty files.

from __future__ import annotations
import base64
import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Dict, Tuple, Optional

import requests
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError

# VSIX files larger than this (in MB) are treated as "large" and not auto-uploaded to GitHub.
LARGE_FILE_THRESHOLD_MB = 70.0

try:
    import config
except ModuleNotFoundError:
    raise RuntimeError(
        "Missing config.py. Copy config_template.py → config.py and fill in your credentials."
    )

GH_API = "https://api.github.com"

# ---------- GitHub (Contents API) ----------
def gh_headers():
    return {
        "Authorization": f"token {config.GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
    }

def gh_get_content(path: str) -> Tuple[Optional[bytes], Optional[str]]:
    url = f"{GH_API}/repos/{config.GITHUB_USERNAME}/{config.GITHUB_REPO}/contents/{path}"
    r = requests.get(url, headers=gh_headers(), params={"ref": config.GIT_BRANCH}, timeout=30)
    if r.status_code == 404:
        return None, None
    r.raise_for_status()
    data = r.json()
    return base64.b64decode(data["content"]), data.get("sha")

def gh_put_content(path: str, content_bytes: bytes, message: str, sha: Optional[str]):
    url = f"{GH_API}/repos/{config.GITHUB_USERNAME}/{config.GITHUB_REPO}/contents/{path}"
    payload = {
        "message": message,
        "content": base64.b64encode(content_bytes).decode("ascii"),
        "branch": config.GIT_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(url, headers=gh_headers(), json=payload, timeout=180)
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
            out[parts[0]] = parts[2]  # classification
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

def download_blob_bytes(cc, blob_path: str) -> bytes:
    bc = cc.get_blob_client(blob_path)
    return bc.download_blob().readall()

# ---------- metadata_master.jsonl index (Azure) ----------
def build_master_index(cc):
    by_version: Dict[str, dict] = {}
    latest_by_id: Dict[str, dict] = {}
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
            eid = rec.get("_extKey")
            if vkey:
                by_version[vkey] = rec
            if eid:
                latest_by_id[eid] = rec
    return by_version, latest_by_id

# ---------- CSV helpers ----------
def load_csv_from_github(path: str) -> Tuple[list[dict], Optional[str], list[str]]:
    raw, sha = gh_get_content(path)
    rows: list[dict] = []
    header: list[str] = []
    if raw:
        txt = raw.decode("utf-8")
        reader = csv.DictReader(io.StringIO(txt))
        header = list(reader.fieldnames or [])
        for r in reader:
            rows.append({k: (v or "").strip() for k, v in r.items()})
    return rows, sha, header

def write_csv_to_github(path: str, rows: list[dict], header: list[str], message: str):
    old_raw, old_sha = gh_get_content(path)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in header})
    new_bytes = buf.getvalue().encode("utf-8")
    if old_raw is not None and old_raw == new_bytes:
        print(f"No changes for {path} — skipping commit.")
        return
    gh_put_content(path, new_bytes, message, sha=old_sha)

# ---------- small helpers ----------
def str_bool(v) -> str:
    if v is True: return "true"
    if v is False: return "false"
    return "unknown"

def fmt_num(n):
    if n is None or n == "": return "none"
    try:
        f = float(n)
        return str(int(f)) if f.is_integer() else str(f).rstrip("0").rstrip(".")
    except Exception:
        return str(n)
    
def fmt_num_zero(n):
    """
    Marketplace numeric fields:
    - Missing / unavailable → 0
    - Otherwise preserve numeric formatting
    """
    if n is None or n == "":
        return "0"
    try:
        f = float(n)
        return str(int(f)) if f.is_integer() else str(f).rstrip("0").rstrip(".")
    except Exception:
        return "0"

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
    """
    Normalize Microsoft classification to semicolon-separated.
    Examples:
      "Typo-squatting, Malware" → "Typo-squatting;Malware"
      "Typos; Malware"          → "Typos;Malware"
    Dedupe while preserving order.
    """
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

# ---------- main ----------
def main():
    if not getattr(config, "GITHUB_PAT", "") or "yourTokenHere" in config.GITHUB_PAT:
        raise SystemExit("[FATAL] Set a valid GITHUB_PAT in config.py")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cc = get_cc()

    # 1) Build index from Azure master metadata
    by_version, latest_by_id = build_master_index(cc)

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

    # 3) Load current CSVs
    flagged_rows, _, flagged_hdr = load_csv_from_github(config.CSV_FLAGGED)
    meta_rows,    _, meta_hdr    = load_csv_from_github(config.CSV_DATASET)

    # Ensure flagged CSV header (unchanged)
    FLAG_HEADER = ["source","checked_date","extension_identifier","msft_classification_type","exists_in_dataset"]
    flagged_hdr = FLAG_HEADER or flagged_hdr

    # Ensure vsmex_metadata header with 'flags' before 'exists_in_dataset'
    BASE_BEFORE = ["captured_date","source","msft_classification_type","extension_identifier","publisher_name",
                   "version","artifact","sha256","size_mb","published_date","last_updated_date","verified_publisher",
                   "installation_count","average_rating","rating_count","categories","repository_url"]
    META_HEADER = BASE_BEFORE + ["flags","exists_in_dataset"]
    meta_hdr = META_HEADER

    existing_ids = {r.get("extension_identifier","") for r in flagged_rows if r.get("extension_identifier")}
    meta_keys = {(r.get("extension_identifier",""), r.get("version","")) for r in meta_rows}

    # 4) Compute *new* identifiers only
    removed_new   = {eid for eid in removed_map.keys() if eid not in existing_ids}
    malicious_new = {eid for eid in malicious_set if eid not in existing_ids}

    print(f"Existing flagged identifiers: {len(existing_ids)}")
    print(f"New removed_list ids: {len(removed_new)}")
    print(f"New malicious_list ids: {len(malicious_new)}")

    # Prefer removed_list when an ID is present in both
    worklist = []
    for eid in sorted(removed_new | malicious_new):
        if eid in removed_new:
            # If in both, we choose removed_list and ignore malicious_list
            source = "removed_list"
            classification = normalize_msft_classification(removed_map.get(eid, "Malware"))
        else:
            source = "malicious_list"
            classification = "Malicious"

        worklist.append((source, eid, classification))

    uploaded_vsix = 0
    new_meta_rows = 0
    appended_flagged = 0

    for source, eid, classification in worklist:
        rec = latest_by_id.get(eid)
        if not rec:
            # Not in metadata → exists=no (flagged CSV)
            flagged_rows.append({
                "source": source,
                "checked_date": today,
                "extension_identifier": eid,
                "msft_classification_type": classification,
                "exists_in_dataset": "no",
            })
            appended_flagged += 1
            print(f"[add] {eid}: not in metadata_master.jsonl → flagged (exists=no)")
            continue

        version = rec.get("version")
        vsix_name = rec.get("vsixFileName")
        if not version or not vsix_name:
            flagged_rows.append({
                "source": source,
                "checked_date": today,
                "extension_identifier": eid,
                "msft_classification_type": classification,
                "exists_in_dataset": "no",
            })
            appended_flagged += 1
            print(f"[add] {eid}: missing version/vsixFileName → flagged (exists=no)")
            continue

        blob_path = f"{config.VSIX_PREFIX}/{vsix_name}"
        in_azure = blob_exists(cc, blob_path)

        if not in_azure:
            # No VSIX in Azure → just flag as exists=no
            flagged_rows.append({
                "source": source,
                "checked_date": today,
                "extension_identifier": eid,
                "msft_classification_type": classification,
                "exists_in_dataset": "no",
            })
            appended_flagged += 1
            print(f"[add] {eid}@{version}: VSIX not in Azure → exists=no")
            continue

        # VSIX exists in Azure → download once for hash/size (+ optional upload)
        vsix_bytes = download_blob_bytes(cc, blob_path)
        sha256_hex = hashlib.sha256(vsix_bytes).hexdigest()

        size_val = len(vsix_bytes) / 1_000_000  # decimal MB
        if size_val < 0.01 and len(vsix_bytes) > 0:
            size_val = 0.01
        size_mb = f"{size_val:.2f}".rstrip("0").rstrip(".")

        # Large file logic (70 MB threshold)
        is_large = size_val > LARGE_FILE_THRESHOLD_MB

        # flagged CSV: mark large files as "yes; large file"
        exists_str = "yes; large file" if is_large else "yes"
        flagged_rows.append({
            "source": source,
            "checked_date": today,
            "extension_identifier": eid,
            "msft_classification_type": classification,
            "exists_in_dataset": exists_str,
        })
        appended_flagged += 1

        # VSIX exists → upload to dataset if not already there (unless large)
        dataset_path = f"{config.DATASET_ROOT}/{eid}/{version}/{vsix_name}"
        _, existing_sha = gh_get_content(dataset_path)

        # Only auto-upload to GitHub for non-large files that are missing there
        need_upload = (existing_sha is None) and (not is_large)

        if need_upload:
            try:
                gh_put_content(
                    dataset_path,
                    vsix_bytes,
                    message=f"Add VSIX {eid}@{version}",
                    sha=None,
                )
                uploaded_vsix += 1
            except requests.exceptions.HTTPError as e:
                print(f"[warn] VSIX upload failed for {eid}@{version} (continuing): {e}")

        # Append metadata row if not already present
        if (eid, version) not in meta_keys:
            pub = rec.get("publisher") or {}
            stats = rec.get("statistics") or {}

            # Keep the artifact name, just annotate if large
            artifact_value = f"{vsix_name} [Large]" if is_large else vsix_name

            meta_rows.append({
                "captured_date": today,
                "source": source,
                "msft_classification_type": classification,          # normalized
                "extension_identifier": eid,
                "publisher_name": pub.get("publisherName", "") or "",
                "version": version,
                "artifact": artifact_value,
                "sha256": sha256_hex,
                "size_mb": size_mb,
                "published_date": norm_date(rec.get("publishedDate")),
                "last_updated_date": norm_date(rec.get("lastUpdated")),
                "verified_publisher": str_bool(pub.get("isDomainVerified")),
                "installation_count": fmt_num_zero(stats.get("install")),
                "average_rating": fmt_num_zero(stats.get("averagerating")),
                "rating_count": fmt_num_zero(stats.get("ratingcount")),
                "categories": join_cats(rec.get("categories", [])),
                "repository_url": rec.get("repository", "") or "none",
                "flags": normalize_flags_field(rec.get("flags", "")),
                "exists_in_dataset": "vsmex",                        # ← write dataset name, not 'yes'
            })
            meta_keys.add((eid, version))
            new_meta_rows += 1

        exists_log = "yes (large)" if is_large else ("yes" if in_azure else "no")
        print(
            f"[add] {eid}@{version}: exists={exists_log} | "
            f"upload_vsix={'YES' if need_upload else 'no'} | "
            f"meta_row={'YES' if (eid, version) in meta_keys else 'no'}"
        )

    # 5) No-op guard
    if appended_flagged == 0 and new_meta_rows == 0 and uploaded_vsix == 0:
        print("No changes detected — nothing to commit.")
        return

    # 6) Write back CSVs
    write_csv_to_github(
        config.CSV_FLAGGED,
        flagged_rows,
        FLAG_HEADER,
        message=f"Incremental flagged update (+{appended_flagged} new rows)"
    )
    write_csv_to_github(
        config.CSV_DATASET,
        meta_rows,
        meta_hdr,
        message=f"Incremental vsmex_metadata (+{new_meta_rows} rows, {uploaded_vsix} vsix uploads)"
    )

    print(f"✅ Done | +flagged:{appended_flagged} | +meta:{new_meta_rows} | uploads:{uploaded_vsix}")

if __name__ == "__main__":
    main()
