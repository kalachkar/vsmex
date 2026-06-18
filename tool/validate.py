#!/usr/bin/env python3
"""validate.py — verify and optionally fix consistency across all VSMEx data.

Usage:
    python3 validate.py                       # report only (dataset + stats)
    python3 validate.py --full                 # include marketplace disk scan (~40 min)
    python3 validate.py --fix                  # report + auto-fix what's safe
    python3 validate.py --fix --full           # full scan + auto-fix
"""

import csv
import json
import os
import shutil
import sys
import time

import config

REPORT_DIR = os.path.join(config.BASE_DIR, "validation_report")

# ── Loaders ─────────────────────────────────────────────────────

def load_cache():
    if not os.path.isfile(config.STATE_FILE):
        return set()
    with open(config.STATE_FILE, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}

def load_metadata():
    records = {}
    if not os.path.isfile(config.MASTER_METADATA_FILE):
        return records
    with open(config.MASTER_METADATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                vkey = rec.get("_versionKey")
                if vkey:
                    records[vkey] = rec
            except Exception:
                continue
    return records

def scan_marketplace_disk():
    found = {}
    ext_dir = config.VSIX_DIR
    if not os.path.isdir(ext_dir):
        return found
    dirs = os.listdir(ext_dir)
    total = len(dirs)
    t0 = time.time()
    for i, eid in enumerate(dirs, 1):
        eid_path = os.path.join(ext_dir, eid)
        if not os.path.isdir(eid_path):
            continue
        for ver in os.listdir(eid_path):
            ver_path = os.path.join(eid_path, ver)
            if not os.path.isdir(ver_path):
                continue
            for fname in os.listdir(ver_path):
                if fname.endswith(".vsix"):
                    found[f"{eid}@{ver}"] = os.path.join(ver_path, fname)
        if i % 5000 == 0:
            elapsed = int(time.time() - t0)
            print(f"    scanned {i}/{total} dirs, {len(found)} files ... {elapsed}s")
    return found

def scan_dataset_disk():
    found = {}
    ext_dir = config.DATASET_EXTENSIONS_DIR
    if not os.path.isdir(ext_dir):
        return found
    for eid in os.listdir(ext_dir):
        eid_path = os.path.join(ext_dir, eid)
        if not os.path.isdir(eid_path):
            continue
        for ver in os.listdir(eid_path):
            ver_path = os.path.join(eid_path, ver)
            if not os.path.isdir(ver_path):
                continue
            for fname in os.listdir(ver_path):
                if fname.endswith(".vsix"):
                    found[(eid, ver)] = os.path.join(ver_path, fname)
    return found

def load_csv_file(path):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def write_list(filename, items):
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        for item in sorted(items):
            f.write(f"{item}\n")
    print(f"    → wrote {path} ({len(items)} entries)")

# ── Main ────────────────────────────────────────────────────────

def main():
    do_fix = "--fix" in sys.argv
    full_scan = "--full" in sys.argv
    errors = 0
    fixes = 0

    os.makedirs(REPORT_DIR, exist_ok=True)

    print("=" * 60)
    print("VSMEx Validation" + ("  [FIX MODE]" if do_fix else ""))
    print("=" * 60)
    print(f"BASE_DIR:    {config.BASE_DIR}")
    print(f"REPORT_DIR:  {REPORT_DIR}")
    print()

    # ── Load ────────────────────────────────────────────────────
    print("Loading cache.txt ...")
    cache = load_cache()
    print(f"  {len(cache):,} entries")

    print("Loading metadata_master.jsonl ...")
    metadata = load_metadata()
    print(f"  {len(metadata):,} records")

    mp_disk = {}
    if full_scan:
        print("Scanning marketplace/extensions/ (slow on network mounts) ...")
        mp_disk = scan_marketplace_disk()
        print(f"  {len(mp_disk):,} VSIX files on disk")
    else:
        print("Skipping marketplace disk scan (use --full to include)")

    print("Scanning vsmex-dataset/extensions/ ...")
    ds_disk = scan_dataset_disk()
    print(f"  {len(ds_disk):,} VSIX files on disk")

    flagged_csv_path = os.path.join(config.DATASET_DIR, "metadata", "msft_vscode_flagged_extensions.csv")
    meta_csv_path = os.path.join(config.DATASET_DIR, "metadata", "vsmex_metadata.csv")

    print("Loading flagged CSV ...")
    flagged_rows = load_csv_file(flagged_csv_path)
    print(f"  {len(flagged_rows):,} rows")

    print("Loading dataset CSV ...")
    meta_rows = load_csv_file(meta_csv_path)
    print(f"  {len(meta_rows):,} rows")

    # ════════════════════════════════════════════════════════════
    # MARKETPLACE
    # ════════════════════════════════════════════════════════════
    print()
    print("-" * 60)
    print("MARKETPLACE CHECKS")
    print("-" * 60)

    # 1. Cache ↔ metadata
    cache_not_in_meta = sorted(cache - set(metadata.keys()))
    meta_not_in_cache = sorted(set(metadata.keys()) - cache)

    if cache_not_in_meta:
        print(f"\n  [WARN] {len(cache_not_in_meta)} in cache but NOT in metadata:")
        for v in cache_not_in_meta:
            print(f"         {v}")
        write_list("mp_in_cache_not_in_metadata.txt", cache_not_in_meta)
        print(f"    FIX: these were downloaded but metadata record is missing.")
        print(f"         Re-run crawler.py — it will re-query these from the API.")
        print(f"         Or remove them from cache.txt to re-download next run.")
        errors += 1
    else:
        print(f"  [OK] cache ⊆ metadata ({len(cache):,} entries)")

    if meta_not_in_cache:
        print(f"\n  [WARN] {len(meta_not_in_cache)} in metadata but NOT in cache:")
        for v in meta_not_in_cache:
            print(f"         {v}")
        write_list("mp_in_metadata_not_in_cache.txt", meta_not_in_cache)
        if do_fix:
            with open(config.STATE_FILE, "a", encoding="utf-8") as f:
                for v in meta_not_in_cache:
                    f.write(v + "\n")
            print(f"    FIXED: appended {len(meta_not_in_cache)} entries to cache.txt")
            fixes += 1
        else:
            print(f"    FIX: run with --fix to append these to cache.txt")
        errors += 1
    else:
        print(f"  [OK] metadata ⊆ cache ({len(metadata):,} records)")

    # 2. Disk ↔ cache (only with --full)
    if full_scan:
        disk_not_in_cache = sorted(set(mp_disk.keys()) - cache)
        cache_not_on_disk = sorted(cache - set(mp_disk.keys()))

        if disk_not_in_cache:
            print(f"\n  [WARN] {len(disk_not_in_cache)} VSIX on disk but NOT in cache:")
            for v in disk_not_in_cache:
                print(f"         {v}  →  {mp_disk[v]}")
            write_list("mp_on_disk_not_in_cache.txt", disk_not_in_cache)
            if do_fix:
                with open(config.STATE_FILE, "a", encoding="utf-8") as f:
                    for v in disk_not_in_cache:
                        f.write(v + "\n")
                print(f"    FIXED: appended {len(disk_not_in_cache)} entries to cache.txt")
                print(f"    NOTE: these still need metadata. Re-run crawler.py to query the API.")
                fixes += 1
            else:
                print(f"    FIX: run with --fix to add to cache, then re-run crawler.py for metadata")
            errors += 1
        else:
            print(f"  [OK] disk ⊆ cache")

        if cache_not_on_disk:
            print(f"\n  [INFO] {len(cache_not_on_disk)} in cache/metadata but no VSIX on disk (delisted):")
            for v in cache_not_on_disk:
                print(f"         {v}")
            write_list("mp_delisted_no_vsix.txt", cache_not_on_disk)
            print(f"    INFO: these extensions were removed from the marketplace after")
            print(f"          the metadata was recorded. No action needed — expected gap.")
        else:
            print(f"  [OK] cache ⊆ disk (perfect 1:1)")

    # ════════════════════════════════════════════════════════════
    # DATASET
    # ════════════════════════════════════════════════════════════
    print()
    print("-" * 60)
    print("DATASET CHECKS")
    print("-" * 60)

    csv_keys = set()
    for r in meta_rows:
        eid = r.get("extension_identifier", "")
        ver = r.get("version", "")
        if eid and ver:
            csv_keys.add((eid, ver))

    ds_disk_keys = set(ds_disk.keys())

    # 3. CSV rows with no VSIX file
    csv_not_on_disk = sorted(csv_keys - ds_disk_keys)
    if csv_not_on_disk:
        print(f"\n  [WARN] {len(csv_not_on_disk)} in vsmex_metadata.csv but NO VSIX in dataset:")
        for eid, ver in csv_not_on_disk:
            mp_key = f"{eid}@{ver}"
            mp_path = mp_disk.get(mp_key, "") if full_scan else ""
            in_mp = f"  (exists in marketplace: {mp_path})" if mp_path else ""
            print(f"         {eid}@{ver}{in_mp}")
        write_list("ds_in_csv_not_on_disk.txt", [f"{e}@{v}" for e, v in csv_not_on_disk])
        if do_fix and full_scan:
            copied = 0
            for eid, ver in csv_not_on_disk:
                mp_key = f"{eid}@{ver}"
                src = mp_disk.get(mp_key)
                if src and os.path.isfile(src):
                    dst_dir = os.path.join(config.DATASET_EXTENSIONS_DIR, eid, ver)
                    os.makedirs(dst_dir, exist_ok=True)
                    shutil.copy2(src, dst_dir)
                    print(f"    FIXED: copied {src} → {dst_dir}/")
                    copied += 1
            if copied:
                print(f"    FIXED: copied {copied} VSIX from marketplace → dataset")
                fixes += 1
            not_copied = len(csv_not_on_disk) - copied
            if not_copied:
                print(f"    MANUAL: {not_copied} VSIX not found in marketplace either — cannot auto-fix")
        else:
            print(f"    FIX: copy missing VSIX from marketplace/extensions/ to vsmex-dataset/extensions/")
            print(f"         or remove the orphan rows from vsmex_metadata.csv")
        errors += 1
    else:
        print(f"  [OK] vsmex_metadata.csv ⊆ dataset disk ({len(csv_keys):,} versions)")

    # 4. VSIX files with no CSV row
    disk_not_in_csv = sorted(ds_disk_keys - csv_keys)
    if disk_not_in_csv:
        print(f"\n  [WARN] {len(disk_not_in_csv)} VSIX in dataset but NOT in vsmex_metadata.csv:")
        for eid, ver in disk_not_in_csv:
            print(f"         {eid}@{ver}  →  {ds_disk[(eid, ver)]}")
        write_list("ds_on_disk_not_in_csv.txt", [f"{e}@{v}" for e, v in disk_not_in_csv])
        print(f"    FIX: re-run vsmex.py — it will pick these up and add CSV rows.")
        print(f"         Or delete the orphan VSIX files if they shouldn't be there.")
        errors += 1
    else:
        print(f"  [OK] dataset disk ⊆ vsmex_metadata.csv ({len(ds_disk):,} files)")

    # 5. Flagged captured=yes but no dataset rows
    captured_yes = [r for r in flagged_rows if r.get("captured") == "yes"]
    captured_no  = [r for r in flagged_rows if r.get("captured") == "no"]
    csv_eids = {r.get("extension_identifier") for r in meta_rows}

    print(f"\n  [INFO] Flagged: {len(flagged_rows):,} total, {len(captured_yes):,} captured=yes, {len(captured_no):,} captured=no")
    print(f"  [INFO] Dataset: {len(meta_rows):,} rows, {len(csv_eids):,} unique extensions, {len(ds_disk):,} VSIX files")

    captured_but_no_csv = sorted({r.get("extension_identifier") for r in captured_yes} - csv_eids)
    if captured_but_no_csv:
        print(f"\n  [WARN] {len(captured_but_no_csv)} flagged captured=yes but missing from vsmex_metadata.csv:")
        for e in captured_but_no_csv:
            print(f"         {e}")
        write_list("ds_captured_yes_but_no_metadata.txt", captured_but_no_csv)
        if do_fix:
            updated = 0
            rows_by_eid = {}
            for r in flagged_rows:
                rows_by_eid[r.get("extension_identifier")] = r
            for eid in captured_but_no_csv:
                if eid in rows_by_eid:
                    rows_by_eid[eid]["captured"] = "no"
                    updated += 1
            if updated:
                fieldnames = list(flagged_rows[0].keys())
                tmp = flagged_csv_path + ".tmp"
                with open(tmp, "w", encoding="utf-8", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=fieldnames)
                    w.writeheader()
                    w.writerows(flagged_rows)
                os.replace(tmp, flagged_csv_path)
                print(f"    FIXED: set captured=no for {updated} extensions in flagged CSV")
                print(f"           (they have no actual VSIX — the flag was wrong)")
                fixes += 1
        else:
            print(f"    FIX: either the VSIX files are missing (re-run vsmex.py)")
            print(f"         or captured flag is wrong — run with --fix to set captured=no")
        errors += 1
    else:
        print(f"  [OK] all captured=yes extensions have metadata rows")

    # ════════════════════════════════════════════════════════════
    # STATS
    # ════════════════════════════════════════════════════════════
    print()
    print("-" * 60)
    print("STATS CHECK")
    print("-" * 60)
    stats_issues = []
    if os.path.isfile(config.STATS_FILE):
        with open(config.STATS_FILE, "r", encoding="utf-8") as f:
            stats = json.load(f)
        ds = stats.get("dataset", {})
        mp = stats.get("marketplace", {})

        mp_ext = mp.get("total_extensions") or mp.get("total_number_of_extensions") or 0
        print(f"  stats.json marketplace: {mp_ext:,} extensions, {mp.get('total_size_gb', '?')} GB")
        print(f"  stats.json dataset:     {ds.get('total_flagged', '?')} flagged, "
              f"{ds.get('total_captured', '?')} captured, "
              f"{ds.get('total_vsix_files', '?')} VSIX, {ds.get('total_size_gb', '?')} GB")

        if ds.get("total_flagged") != len(flagged_rows):
            print(f"  [WARN] stats.total_flagged ({ds.get('total_flagged')}) != CSV ({len(flagged_rows)})")
            stats_issues.append("total_flagged")
            errors += 1
        else:
            print(f"  [OK] stats.total_flagged matches flagged CSV")

        if ds.get("total_vsix_files") != len(ds_disk):
            print(f"  [WARN] stats.total_vsix_files ({ds.get('total_vsix_files')}) != dataset disk ({len(ds_disk)})")
            stats_issues.append("total_vsix_files")
            errors += 1
        else:
            print(f"  [OK] stats.total_vsix_files matches dataset disk")

        if ds.get("total_captured") != len(meta_rows):
            print(f"  [WARN] stats.total_captured ({ds.get('total_captured')}) != vsmex_metadata.csv ({len(meta_rows)})")
            stats_issues.append("total_captured")
            errors += 1
        else:
            print(f"  [OK] stats.total_captured matches dataset CSV")

        if stats_issues:
            print(f"\n    FIX: re-run vsmex.py — it recomputes stats.json from disk on every run")
    else:
        print(f"  [WARN] stats.json not found at {config.STATS_FILE}")
        print(f"    FIX: run vsmex.py once to generate it")
        errors += 1

    # ════════════════════════════════════════════════════════════
    # SUMMARY
    # ════════════════════════════════════════════════════════════
    print()
    print("=" * 60)
    if errors == 0:
        print("ALL CHECKS PASSED")
    else:
        print(f"{errors} WARNING(S) FOUND")
        if fixes:
            print(f"{fixes} AUTO-FIX(ES) APPLIED")
        print(f"\nReport files written to: {REPORT_DIR}")
        print(f"  ls {REPORT_DIR}/")
    print("=" * 60)
    sys.exit(0 if errors == 0 else 1)

if __name__ == "__main__":
    main()
