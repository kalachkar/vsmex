# VSMEx — VSCode Malicious Extensions Dataset

> A continuously updated dataset of malicious Visual Studio Code extensions, captured from Microsoft's official flagged lists and curated security research sources.
>
> Presented at **CODASPY 2026**: *VSMEx: A Collection Tool and a Dataset of Malicious VS Code Extensions*

---

## Overview

VSMEx tracks and archives malicious VSCode extensions at the binary level. It monitors two Microsoft sources:

- **`marketplace.json`** — extensions currently flagged as malicious
- **`RemovedPackages.md`** — extensions formally removed with classification

For each flagged extension, VSMEx captures all available versions from Azure Blob Storage and records rich metadata (publisher, version, sha256, install count, engine constraints, etc.).

**Dataset stats (as of latest sync):**
- 796 flagged extension identifiers
- 1,106 captured VSIX binaries across all versions
- Sources: Microsoft malicious list, Microsoft removed list, BKC

---

## Repository Structure

```
kalachkar/vsmex  (this repo — public)
├── tool/
│   ├── config.py          # Configuration (reads secrets from env vars)
│   ├── crawler.py         # Crawls VS Code Marketplace → Azure Blob Storage
│   ├── vsmex.py           # Syncs flagged extensions → vsmex-dataset + metadata
│   └── requirements.txt
├── metadata/
│   └── msft_vscode_flagged_extensions.csv   # One row per flagged extension (public)
└── .github/workflows/
    ├── crawler.yml        # Runs crawler every 2 hours (self-hosted runner)
    └── vsmex.yml          # Runs vsmex sync at 8am and 8pm UTC (self-hosted runner)

kalachkar/vsmex-dataset  (private — request access below)
├── dataset/
│   └── <publisher.extension>/<version>/*.vsix
└── metadata/
    └── vsmex_metadata.csv   # One row per (extension, version) with sha256, size, etc.
```

---

## Metadata

### `metadata/msft_vscode_flagged_extensions.csv` (public)

One row per flagged extension identifier.

| Column | Description |
|--------|-------------|
| `source` | `malicious_list` or `removed_list` |
| `checked_date` | Date first observed in Microsoft's list |
| `extension_identifier` | `publisher.extensionName` |
| `msft_classification_type` | Microsoft's classification (e.g. `Malicious`, `Typo-squatting`) |
| `msft_removed_date` | Date of removal from marketplace (if available) |
| `captured` | `yes` / `no` — whether any VSIX binary was captured |
| `version_count` | Number of versions captured |
| `latest_version` | Most recent captured version |
| `capture_date` | Date the binary was first captured |

### `metadata/vsmex_metadata.csv` (in vsmex-dataset — gated)

One row per `(extension_identifier, version)`.

| Column | Description |
|--------|-------------|
| `extension_identifier` | `publisher.extensionName` |
| `version` | Extension version string |
| `artifact` | VSIX filename |
| `sha256` | SHA-256 of the VSIX binary |
| `size_mb` | File size in MB |
| `engines_vscode` | VS Code engine constraint from `package.json` |
| `installation_count` | Install count at time of capture |
| `exists_in_dataset` | Dataset name (e.g. `vsmex`) or source (e.g. `BKC`) |
| … | Publisher info, dates, categories, repository URL, flags |

---

## Setup

### Prerequisites

- Python 3.11+
- Azure Storage account (Blob Storage)
- GitHub fine-grained PAT with **Contents: read/write** on both repos

### Environment Variables

Set these before running either script:

```bash
export AZURE_CONNECTION_STRING="DefaultEndpointsProtocol=https;..."
export AZURE_CONTAINER_NAME="extensions"
export GITHUB_PAT="github_pat_..."
export GITHUB_USERNAME="your-username"
export GITHUB_REPO="vsmex"
export GITHUB_DATASET_REPO="vsmex-dataset"
```

### Install & Run

```bash
git clone https://github.com/kalachkar/vsmex.git
cd vsmex/tool
pip install -r requirements.txt

# Crawl the VS Code Marketplace (downloads new VSIXs to Azure)
python3 crawler.py

# Sync flagged extensions to dataset + metadata
python3 vsmex.py
```

---

## Automated Collection (GitHub Actions)

The dataset is kept up to date via two scheduled workflows on a self-hosted runner:

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| `crawler.yml` | Every 2 hours | Crawl marketplace, download new VSIXs to Azure |
| `vsmex.yml` | 8am and 8pm UTC | Sync newly flagged extensions to dataset and metadata |

---

## Dataset Access

The VSIX binaries and full metadata CSV are in the **private** `kalachkar/vsmex-dataset` repository to prevent misuse.

**To request access:** Open an issue in this repository with your name, institution, and intended use. Researchers are added as repository collaborators.

---

## Citation

If you use VSMEx in your research, please cite our paper:

```bibtex
@inproceedings{vsmex2026,
  author    = {[Author(s)]},
  title     = {VSMEx: A Collection Tool and a Dataset of Malicious VS Code Extensions},
  booktitle = {Proceedings of the ACM Conference on Data and Application Security and Privacy (CODASPY)},
  year      = {2026},
  url       = {https://github.com/kalachkar/vsmex}
}
```

---

## License

See [LICENSE](LICENSE) for details.
