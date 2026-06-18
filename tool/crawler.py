#!/usr/bin/env python3
# crawler.py — Incremental VSIX sync (local filesystem)

from __future__ import annotations
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import requests

import config

# ========= time helpers =========
def _now():
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
    raise RuntimeError(f"POST request failed after {config.MAX_RETRIES} attempts: {last_err}")

# ========= Local filesystem helpers =========
def _ensure_parent(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def append_lines(path: str, lines: list[str]):
    if not lines:
        return
    _ensure_parent(path)
    payload = "".join(line + "\n" for line in lines)
    with open(path, "a", encoding="utf-8") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())

def read_text_file(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def write_text_file(path: str, text: str):
    _ensure_parent(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)

def download_to_file(url: str, dest: str):
    _ensure_parent(dest)
    tmp = dest + ".tmp"
    try:
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    f.write(chunk)
        os.replace(tmp, dest)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

def download_with_retries(url: str, dest: str):
    last_err = None
    for i in range(config.MAX_RETRIES):
        try:
            download_to_file(url, dest)
            return
        except Exception as e:
            last_err = e
            if i < config.MAX_RETRIES - 1:
                time.sleep(config.RETRY_BACKOFF_BASE * (2 ** i))
    raise last_err or RuntimeError(f"Download failed after {config.MAX_RETRIES} attempts")

# ========= State + Logging =========
def load_seen_versions() -> set[str]:
    txt = read_text_file(config.STATE_FILE)
    if txt:
        return set(line.strip() for line in txt.splitlines() if line.strip())
    print("cache.txt not found — rebuilding from metadata_master.jsonl ...")
    return _rebuild_seen_from_metadata()

def _rebuild_seen_from_metadata() -> set[str]:
    import re
    pattern = re.compile(r'"_versionKey"\s*:\s*"([^"]+)"')
    seen = set()
    path = config.MASTER_METADATA_FILE
    if not os.path.isfile(path):
        return seen
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                seen.add(m.group(1))
    print(f"  Rebuilt {len(seen)} entries from metadata")
    save_seen_versions(seen)
    return seen

def save_seen_versions(seen_set: set[str]):
    text = "\n".join(sorted(seen_set)) + ("\n" if seen_set else "")
    write_text_file(config.STATE_FILE, text)

# ========= Record extraction =========
def extract_record(ext: dict) -> dict:
    versions = ext.get("versions", [])
    latest = versions[0] if versions else {}
    files = {f.get("assetType"): f.get("source") for f in latest.get("files", [])}
    props = {p.get("key"): p.get("value") for p in latest.get("properties", [])}
    stats = {s.get("statisticName"): s.get("value") for s in ext.get("statistics", [])}

    def safe_date(s):
        return s[:10] if isinstance(s, str) else None

    publisher_name = (ext.get("publisher", {}).get("publisherName") or "").strip()
    extension_name = (ext.get("extensionName") or "").strip()
    version = (latest.get("version") or "").strip()

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

# ========= Stats =========
def load_stats() -> dict:
    if os.path.isfile(config.STATS_FILE):
        with open(config.STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_stats(stats: dict):
    write_text_file(config.STATS_FILE, json.dumps(stats, indent=2) + "\n")

# ========= Per-extension worker (runs in thread pool) =========
def _process_ext(ext, seen: set[str]):
    rec = extract_record(ext)
    vkey = rec.get("_versionKey")
    ext_key = rec.get("_extKey")
    fname = rec.get("vsixFileName")
    url = rec.get("vsixDownloadUrl")
    version = rec.get("version")

    if not vkey or not fname or not url or not ext_key or not version:
        return "skip", None, 0
    if vkey in seen:
        return "skip", None, 0

    dest = os.path.join(config.VSIX_DIR, ext_key, version, fname)
    downloaded = not os.path.isfile(dest)
    if downloaded:
        download_with_retries(url, dest)
    size = os.path.getsize(dest)
    return "ok", rec, size if downloaded else 0

# ========= Main =========
def main():
    for d in [os.path.dirname(config.MASTER_METADATA_FILE),
              os.path.dirname(config.STATE_FILE),
              os.path.dirname(config.LOG_FILE),
              config.VSIX_DIR]:
        os.makedirs(d, exist_ok=True)

    def log_line(msg: str):
        append_lines(config.LOG_FILE, [f"{now_stamp()} | {msg}"])

    seen = load_seen_versions()
    print(f"Seen versions loaded: {len(seen)}")
    log_line(f"RUN START seen={len(seen)}")

    session = requests.Session()
    new_versions = skipped = errors = 0
    downloaded_bytes = 0
    known_ext_keys = {vkey.rsplit("@", 1)[0] for vkey in seen}
    new_ext_keys: set[str] = set()
    newly_seen: set[str] = set()

    try:
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
                print(f"-> Page {page}: 0 items (end).")
                break

            page_records: list[str] = []
            page_vkeys: list[str] = []

            with ThreadPoolExecutor(max_workers=config.DOWNLOAD_WORKERS) as executor:
                futures = {executor.submit(_process_ext, ext, seen): ext for ext in items}
                for future in as_completed(futures):
                    try:
                        status, rec, dl_size = future.result()
                    except Exception as e:
                        errors += 1
                        err = f"ERROR: {e}"
                        print(f"  {err}")
                        log_line(err)
                        continue

                    if status == "skip":
                        skipped += 1
                        continue

                    fname = rec.get("vsixFileName")
                    vkey = rec.get("_versionKey")
                    ext_key = rec.get("_extKey")

                    page_records.append(json.dumps(rec, ensure_ascii=False))
                    page_vkeys.append(vkey)
                    downloaded_bytes += dl_size
                    if ext_key and ext_key not in known_ext_keys:
                        new_ext_keys.add(ext_key)
                        known_ext_keys.add(ext_key)
                    new_versions += 1
                    print(f"  + {fname}")

            if page_records:
                append_lines(config.MASTER_METADATA_FILE, page_records)
                newly_seen.update(page_vkeys)

            if newly_seen and len(newly_seen) % config.CHECKPOINT_EVERY == 0:
                seen.update(newly_seen)
                save_seen_versions(seen)
                newly_seen.clear()
                log_line(f"CHECKPOINT saved ({len(seen)} total seen)")

            print(f"-> Page {page}: processed {len(items)} | new={new_versions} skipped={skipped} errors={errors}")
            if len(items) < config.PAGE_SIZE:
                print(f"-> Page {page} short; likely last page.")
                break
            time.sleep(config.SLEEP_BETWEEN_CALLS)

    except KeyboardInterrupt:
        print("\nInterrupted.")
        log_line("RUN INTERRUPTED by user")
    except OSError as e:
        print(f"\nDisk error: {e}")
        log_line(f"RUN ABORTED disk error: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        log_line(f"RUN ABORTED unexpected: {e}")
    finally:
        if newly_seen:
            seen.update(newly_seen)
            try:
                save_seen_versions(seen)
            except OSError as e:
                print(f"CRITICAL: failed to save state: {e}")

        summary = f"RUN END new={new_versions} skipped={skipped} errors={errors} seen_total={len(seen)}"
        print("\n" + summary)
        try:
            log_line(summary)
        except OSError:
            pass

        try:
            stats = load_stats()
            mp = stats.get("marketplace", {})
            mp["total_extensions"] = mp.get("total_extensions", 0) + len(new_ext_keys)
            mp["total_vsix_files"] = mp.get("total_vsix_files", 0) + new_versions
            mp["total_size_gb"] = round(mp.get("total_size_gb", 0) + downloaded_bytes / 1e9, 2)
            mp["last_sync"] = now_stamp()
            stats["marketplace"] = mp
            save_stats(stats)
        except Exception as e:
            print(f"WARNING: failed to update stats: {e}")

if __name__ == "__main__":
    main()
