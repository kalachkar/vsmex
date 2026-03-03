import os

# Tunable settings
USE_UTC              = True
PAGE_SIZE            = 1000
MAX_PAGES            = 101
SLEEP_BETWEEN_CALLS  = 0.25
MAX_RETRIES          = 5
RETRY_BACKOFF_BASE   = 0.75
DOWNLOAD_WORKERS     = 4
CHECKPOINT_EVERY     = 500

# Secrets — must be set as environment variables
AZURE_CONNECTION_STRING = os.environ["AZURE_CONNECTION_STRING"]
GITHUB_PAT              = os.environ["GITHUB_PAT"]

# Deployment-specific — must be set as environment variables
AZURE_CONTAINER_NAME = os.environ["AZURE_CONTAINER_NAME"]
GITHUB_USERNAME      = os.environ["GITHUB_USERNAME"]
GITHUB_REPO          = os.environ["GITHUB_REPO"]
GITHUB_DATASET_REPO  = os.environ["GITHUB_DATASET_REPO"]

# Tool constants — same for all deployments
VSIX_PREFIX          = "extensions"
MASTER_METADATA_BLOB = "metadata/metadata_master.jsonl"
STATE_BLOB           = "state/state.txt"
LOG_BLOB             = "logs/incremental.log"
GIT_BRANCH           = "main"
MSFT_MALICIOUS_URL   = "https://main.vscode-cdn.net/extensions/marketplace.json"
MSFT_REMOVED_URL     = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
CSV_FLAGGED          = "metadata/msft_vscode_flagged_extensions.csv"
CSV_DATASET          = "metadata/vsmex_metadata.csv"
DATASET_ROOT         = "dataset"
