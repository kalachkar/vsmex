import os

# ── Environment variables ─────────────────────────────────────
# Set these in ~/.vsmex_env (and source it):
#
#   export GITHUB_PAT="ghp_your_fine_grained_pat"
#   export GITHUB_USERNAME="your-github-username"
#   export VSMEX_BASE_DIR="/path/to/vsmex"

# ── Local paths ──────────────────────────────────────────────
BASE_DIR         = os.environ.get("VSMEX_BASE_DIR", "/path/to/vsmex")
MARKETPLACE_DIR  = os.path.join(BASE_DIR, "marketplace")
DATASET_DIR      = os.path.join(BASE_DIR, "vsmex-dataset")

STATS_FILE        = os.path.join(BASE_DIR, "stats.json")

VSIX_DIR              = os.path.join(MARKETPLACE_DIR, "extensions")
MASTER_METADATA_FILE  = os.path.join(MARKETPLACE_DIR, "metadata", "metadata_master.jsonl")
STATE_FILE            = os.path.join(MARKETPLACE_DIR, "logs", "cache.txt")
LOG_FILE              = os.path.join(MARKETPLACE_DIR, "logs", "incremental.log")

DATASET_EXTENSIONS_DIR = os.path.join(DATASET_DIR, "extensions")

# ── Tunable settings ─────────────────────────────────────────
# These defaults work well; adjust if needed.

USE_UTC              = True
PAGE_SIZE            = 1000       # extensions per marketplace API page
MAX_PAGES            = 101        # max pages to fetch (101 * 1000 > full marketplace)
SLEEP_BETWEEN_CALLS  = 0.25       # seconds between API requests
MAX_RETRIES          = 5          # retries on transient failures
RETRY_BACKOFF_BASE   = 0.75       # exponential backoff base (seconds)
DOWNLOAD_WORKERS     = 4          # parallel VSIX downloads
CHECKPOINT_EVERY     = 500        # save cache every N new versions

# ── Microsoft sources ────────────────────────────────────────
# These are public URLs; no changes needed.

MSFT_MALICIOUS_URL = "https://main.vscode-cdn.net/extensions/marketplace.json"
MSFT_REMOVED_URL   = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
