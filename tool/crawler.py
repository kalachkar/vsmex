#!/usr/bin/env python3
# crawler.py — Incremental VSIX sync (append-only master & log; uses state/state.txt)

from __future__ import annotations
import json
import time
from datetime import datetime, timezone
import requests
from azure.storage.blob import BlobServiceClient, ContentSettings
from azure.core.exceptions import ResourceNotFoundError

try:
    import config
except ModuleNotFoundError:
    raise RuntimeError(
        "Missing config.py. Copy config_template.py → config.py and fill in your credentials."
    )

# ========= time helpers =========
def _now():
    # Fixes deprecation warning (timezone-aware)
    return datetime.now(timezone.utc) if config.USE_UTC else datetime.now()

def snapshot_date():
    return _now().strftime("%Y-%m-%d")

def now_stamp():
    return _now().strftime("%Y-%m-%d %H:%M:%S")

# ========= Marketplace =========
MARKETPLACE_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
HEADERS = {
    "Accept": "application/json;api-version=7.2-preview.1",
    "Content-Type": "application/json",
    "User-Agent": "Visual Studio Code/1.93.0",
    "X-Market-Client-Id": "VSCode",
}
# versions, files, tags, publisher, stats, latest, props
FLAGS = (0x1 | 0x2 | 0x4 | 0x8 | 0x20 | 0x80 | 0x100)

def build_payload(page_number: int) -> dict:
    return {
        "filters": [{
            "criteria": [
                {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                {"filterType": 10, "value": 'target:"Microsoft.VisualStudio.Code"'}
            ],
            "pageNumber": page_number,
            "pageSize": config.PAGE_SIZE,
            "sortBy": 10,
            "sortOrder": 0
        }],
        "flags": FLAGS
    }

def resilient_post(session, url, headers, json_payload) -> requests.Response:
    """POST with retries and exponential backoff."""
    last_err: Exception | None = None
    for attempt in range(1, config.MAX_RETRIES + 1):
        try:
            r = session.post(url, headers=headers, json=json_payload, timeout=60)
            r.raise_for_status()
            return r
        except Exception as e:
            last_err = e
            if attempt < config.MAX_RETRIES:
                sleep_for = config.RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                print(f"   ! Request failed (attempt {attempt}/{config.MAX_RETRIES}): {e}. Retrying in {sleep_for:.2f}s...")
                time.sleep(sleep_for)

    # If we got here, all retries failed
    raise RuntimeError(f"POST request failed after {config.MAX_RETRIES} attempts: {last_err}")

# ========= Azure helpers =========
def get_container_client():
    svc = BlobServiceClient.from_connection_string(config.AZURE_CONNECTION_STRING)
    cc = svc.get_container_client(config.AZURE_CONTAINER_NAME)
    try:
        cc.get_container_properties()
    except Exception:
        cc.create_container()
    return cc

def get_append_client(cc, blob_name: str):
    bc = cc.get_blob_client(blob_name)
    try:
        props = bc.get_blob_properties()
        if getattr(props, "blob_type", None) != "AppendBlob":
            raise RuntimeError(
                f"Blob '{blob_name}' exists with type '{props.blob_type}', not AppendBlob."
            )
    except ResourceNotFoundError:
        bc.create_append_blob()
    return bc

def append_line(append_client, text_line: str):
    append_client.append_block((text_line + "\n").encode("utf-8"))

def read_text_blob(cc, blob_name: str) -> str | None:
    bc = cc.get_blob_client(blob_name)
    try:
        return bc.download_blob().readall().decode("utf-8")
    except ResourceNotFoundError:
        return None

def overwrite_text_blob(cc, blob_name: str, text: str):
    cc.get_blob_client(blob_name).upload_blob(text.encode("utf-8"), overwrite=True)

def blob_exists(cc, blob_path: str) -> bool:
    try:
        cc.get_blob_client(blob_path).get_blob_properties()
        return True
    except ResourceNotFoundError:
        return False

def http_to_blob_with_retries(cc, blob_path: str, url: str):
    bc = cc.get_blob_client(blob_path)
    last_err = None
    for i in range(config.MAX_RETRIES):
        try:
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                r.raw.decode_content = True
                bc.upload_blob(
                    r.raw,
                    overwrite=True,
                    content_settings=ContentSettings(content_type="application/octet-stream"),
                    max_concurrency=4,
                )
            return
        except Exception as e:
            last_err = e
            if i < config.MAX_RETRIES - 1:
                time.sleep(config.RETRY_BACKOFF_BASE * (2 ** i))
            else:
                raise last_err or RuntimeError(f"Upload failed after {config.MAX_RETRIES} attempts")

# ========= State + Logging =========
def load_seen_versions(cc) -> set[str]:
    txt = read_text_blob(cc, config.STATE_BLOB)
    return set(line.strip() for line in txt.splitlines() if line.strip()) if txt else set()

def save_seen_versions(cc, seen_set: set[str]):
    text = "\n".join(sorted(seen_set)) + ("\n" if seen_set else "")
    overwrite_text_blob(cc, config.STATE_BLOB, text)

# ========= Record extraction =========
def extract_record(ext: dict) -> dict:
    versions = ext.get("versions", [])
    latest = versions[0] if versions else {}
    files = {f.get("assetType"): f.get("source") for f in latest.get("files", [])}
    props = {p.get("key"): p.get("value") for p in latest.get("properties", [])}
    stats = {s.get("statisticName"): s.get("value") for s in ext.get("statistics", [])}

    def safe_date(s):
        return s[:10] if isinstance(s, str) else None

    publisher_name = ext.get("publisher", {}).get("publisherName")
    extension_name = ext.get("extensionName")
    version = latest.get("version")

    ext_key = f"{publisher_name}.{extension_name}" if publisher_name and extension_name else None
    version_key = f"{ext_key}@{version}" if ext_key and version else None

    return {
        "_snapshotDate": snapshot_date(),
        "_extKey": ext_key,
        "_versionKey": version_key,
        "extensionId": ext.get("extensionId"),
        "extensionName": extension_name,
        "displayName": ext.get("displayName"),
        "publisher": {
            "publisherId": ext.get("publisher", {}).get("publisherId"),
            "publisherName": publisher_name,
            "displayName": ext.get("publisher", {}).get("displayName"),
            "domain": ext.get("publisher", {}).get("domain"),
            "isDomainVerified": ext.get("publisher", {}).get("isDomainVerified", False),
        },
        "flags": ext.get("flags"),
        "lastUpdated": safe_date(ext.get("lastUpdated")),
        "publishedDate": safe_date(ext.get("publishedDate")),
        "releaseDate": safe_date(ext.get("releaseDate")),
        "categories": ext.get("categories", []),
        "tags": ext.get("tags", []),
        "statistics": {
            "install": stats.get("install"),
            "averagerating": stats.get("averagerating"),
            "ratingcount": stats.get("ratingcount"),
            "trendingdaily": stats.get("trendingdaily"),
            "trendingmonthly": stats.get("trendingmonthly"),
            "trendingweekly": stats.get("trendingweekly"),
        },
        "version": version,
        "versionProperties": props,
        "files": files,
        "repository": props.get("Microsoft.VisualStudio.Services.Links.Source"),
        "license": props.get("Microsoft.VisualStudio.Services.Links.License"),
        "project": props.get("Microsoft.VisualStudio.Services.Links.Project"),
        "dependencies": props.get("Microsoft.VisualStudio.Code.ExtensionDependencies"),
        "vsixDownloadUrl": files.get("Microsoft.VisualStudio.Services.VSIXPackage"),
        "vsixFileName": (
            f"{publisher_name}.{extension_name}-{version}.vsix" if version else None
        ),
    }

# ========= Main =========
def main():
    cc = get_container_client()
    log_client = get_append_client(cc, config.LOG_BLOB)
    master_client = get_append_client(cc, config.MASTER_METADATA_BLOB)

    def log_line(msg: str):
        append_line(log_client, f"{now_stamp()} | {msg}")

    seen = load_seen_versions(cc)
    print(f"Seen versions loaded from blob: {len(seen)}")
    log_line(f"RUN START seen={len(seen)}")

    session = requests.Session()
    new_versions = skipped = errors = 0
    newly_seen: set[str] = set()

    for page in range(1, config.MAX_PAGES + 1):
        try:
            r = resilient_post(session, MARKETPLACE_URL, HEADERS, build_payload(page))
            if not isinstance(r, requests.Response):
                raise RuntimeError("Expected a valid Response object but got None")

            data = r.json()
            items = data.get("results", [{}])[0].get("extensions", [])
        except Exception as e:
            msg = f"FATAL page={page} error={e}"
            print(msg)
            log_line(msg)
            break

        if not items:
            print(f"→ Page {page}: 0 items (end).")
            break

        for ext in items:
            rec = extract_record(ext)
            vkey = rec.get("_versionKey")
            fname = rec.get("vsixFileName")
            url = rec.get("vsixDownloadUrl")

            if not vkey or not fname or not url:
                skipped += 1
                continue
            if vkey in seen:
                skipped += 1
                continue

            blob_path = f"{config.VSIX_PREFIX}/{fname}"

            try:
                if not blob_exists(cc, blob_path):
                    http_to_blob_with_retries(cc, blob_path, url)

                append_line(master_client, json.dumps(rec, ensure_ascii=False))
                newly_seen.add(vkey)
                new_versions += 1
                print(f"✅ {fname}")

                if len(newly_seen) % config.CHECKPOINT_EVERY == 0:
                    seen.update(newly_seen)
                    save_seen_versions(cc, seen)
                    newly_seen.clear()
                    log_line(f"CHECKPOINT saved ({len(seen)} total seen)")
            except Exception as e:
                errors += 1
                err = f"ERROR {fname}: {e}"
                print(f"❌ {err}")
                log_line(err)

        print(f"→ Page {page}: processed {len(items)} | new={new_versions} skipped={skipped} errors={errors}")
        if len(items) < config.PAGE_SIZE:
            print(f"→ Page {page} short; likely last page.")
            break
        time.sleep(config.SLEEP_BETWEEN_CALLS)

    if newly_seen:
        seen.update(newly_seen)
        save_seen_versions(cc, seen)

    summary = f"RUN END new={new_versions} skipped={skipped} errors={errors} seen_total={len(seen)}"
    print("\n" + summary)
    log_line(summary)

if __name__ == "__main__":
    main()
