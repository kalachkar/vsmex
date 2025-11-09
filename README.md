# VSMEx (VSCode Malicious Extensions Dataset)

Continuously collects and archives malicious VS Code extensions based on Microsoft’s official flagged lists.

## Structure

```
vsmex/
├── tool/ # Collection scripts
├── metadata/ # Incremental metadata
└── dataset/ # Malicious VSIX packages
```

---

## Quick Start

```bash
git clone https://github.com/kalachkar/vsmex.git
cd vsmex/tool
pip install -r requirements.txt
cp config_template.py config.py
python crawler.py
python vsmex.py
```

## Edit config.py to include your Azure and GitHub configuration:

```
# Azure Storage
AZURE_CONNECTION_STRING = "<your_azure_storage_connection_string>"
AZURE_CONTAINER_NAME = "<your_azure_container_name>"

# GitHub config (PAT-based)
GITHUB_PAT = "<your_github_pat>"
GITHUB_USERNAME = "<your_github_username>"
GITHUB_REPO = "<your_github_repo>"
GIT_BRANCH = "<your_github_branch>"
```


## Optional: Cron Setup

```bash
# Run crawler 6x/day (every 4 hours) and vsmex daily
0 */4 * * * cd /path/to/vsmex/tool && /usr/bin/python3 crawler.py >/dev/null 2>&1
15 2 * * * cd /path/to/vsmex/tool && /usr/bin/python3 vsmex.py >> /path/to/vsmex/logs/vsmex.log 2>&1
```
