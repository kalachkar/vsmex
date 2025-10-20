# config_template.py — template for local configuration
# Copy this file to config.py and fill in your credentials.

# General settings
USE_UTC = True
PAGE_SIZE = 1000
MAX_PAGES = 101
SLEEP_BETWEEN_CALLS = 0.25
MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 0.75  # seconds

# Azure Storage
AZURE_CONNECTION_STRING = "<YOUR_AZURE_STORAGE_CONNECTION_STRING>"
AZURE_CONTAINER_NAME = "<YOUR_AZURE_CONTAINER_NAME>"

# Blob paths
VSIX_PREFIX = "extensions"
MASTER_METADATA_BLOB = "metadata/metadata_master.jsonl"
STATE_BLOB = "state/state.txt"
LOG_BLOB = "logs/incremental.log"

# ===== Microsoft lists =====
MSFT_MALICIOUS_URL = "https://main.vscode-cdn.net/extensions/marketplace.json"
MSFT_REMOVED_URL = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"

# ===== GitHub configuration (PAT-based) =====
GITHUB_PAT = "<YOUR_GITHUB_PAT>"
GITHUB_USERNAME = "<YOUR_GITHUB_USERNAME>"
GITHUB_REPO = "vsmex"
GIT_BRANCH = "main"

# ===== Files in the GitHub repo =====
CSV_FLAGGED = "metadata/msft_vscode_flagged_extensions.csv"
CSV_DATASET = "metadata/vsmex_metadata.csv"
DATASET_ROOT = "dataset"
