# VSMEx — VSCode Malicious Extensions Dataset

> To be presented at **[CODASPY 2026](https://www.codaspy.org/2026/)** — The 16th ACM Conference on Data and Application Security and Privacy, June 23–25, 2026, Frankfurt am Main, Germany.
>
> *VSMEx: A Collection Tool and a Dataset of Malicious VS Code Extensions*

A continuously updated dataset of malicious Visual Studio Code extensions, captured from Microsoft's official flagged lists and curated security research sources. VSMEx monitors `marketplace.json` and `RemovedPackages.md`, captures all available VSIX binaries, and records rich metadata (sha256, version, install count, engine constraints, etc.).

**Citation:**
```bibtex
@inproceedings{vsmex2026,
  author    = {[Author(s)]},
  title     = {VSMEx: A Collection Tool and a Dataset of Malicious VS Code Extensions},
  booktitle = {Proceedings of the ACM Conference on Data and Application Security and Privacy (CODASPY)},
  year      = {2026},
  url       = {https://github.com/kalachkar/vsmex}
}
```

**Dataset access:** The VSIX binaries and full metadata are in the private `kalachkar/vsmex-dataset` repository. To request access, open an issue with your name, institution, and intended use.

---

## Repository Structure

```
kalachkar/vsmex  (this repo — public)
├── tool/
│   ├── config.py          # Configuration (reads secrets from env vars)
│   ├── crawler.py         # Crawls VS Code Marketplace → Azure Blob Storage
│   ├── vsmex.py           # Syncs flagged extensions → vsmex-dataset + metadata
│   └── requirements.txt
└── metadata/
    └── msft_vscode_flagged_extensions.csv   # One row per flagged extension (public)

kalachkar/vsmex-dataset  (private — request access above)
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

## License

See [LICENSE](LICENSE) for details.
