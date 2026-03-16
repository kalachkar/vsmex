# VSMEx

Dataset of malicious VS Code extensions collected from Microsoft's flagged extension lists.

To be presented at [CODASPY 2026](https://www.codaspy.org/2026/) — June 23–25, Frankfurt am Main.

```bibtex
TBD
```

## Dataset access

The VSIX packages and full metadata are kept in a separate private repository — [`kalachkar/vsmex-dataset`](https://github.com/kalachkar/vsmex-dataset) — and are not publicly available. Access is gated to prevent misuse: these are real malicious packages.

To request access, email from an institutional address with your name, institution, and intended use. We only respond to institutional email addresses.

- Dr. Yury Zhauniarovich — Y.Zhauniarovich [at] tudelft [dot] nl
- Kotaiba Alachkar — k.alachkar [at] tudelft [dot] nl

### `metadata/msft_vscode_flagged_extensions.csv` (this repo)

One row per flagged extension: `source`, `checked_date`, `extension_identifier`, `msft_classification_type`, `msft_removed_date`, `captured`, `version_count`, `latest_version`, `capture_date`.

### `metadata/vsmex_metadata.csv` (vsmex-dataset)

One row per `(extension, version)`: `captured_date`, `source`, `msft_classification_type`, `extension_identifier`, `publisher_name`, `version`, `artifact`, `sha256`, `size_mb`, `published_date`, `last_updated_date`, `verified_publisher`, `installation_count`, `average_rating`, `rating_count`, `categories`, `repository_url`, `flags`, `engines_vscode`, `exists_in_dataset`.

## Contents

- `metadata/msft_vscode_flagged_extensions.csv` — one row per flagged extension
- `tool/crawler.py` — crawls the VS Code Marketplace, stores new VSIXs in Azure Blob Storage
- `tool/vsmex.py` — reads Microsoft's flagged lists, syncs captured extensions to the dataset

## Running

Requires Python 3.11+, Azure Blob Storage, and a GitHub fine-grained PAT (Contents: read/write on both repos).

```bash
pip install -r tool/requirements.txt
```

```bash
export AZURE_CONNECTION_STRING="<your-azure-connection-string>"
export AZURE_CONTAINER_NAME="<your-container-name>"
export GITHUB_PAT="<your-github-pat>"
export GITHUB_USERNAME="<your-github-username>"
export GITHUB_REPO="<your-repo-name>"
export GITHUB_DATASET_REPO="<your-dataset-repo-name>"
```

```bash
python3 tool/crawler.py  # fetch new VSIXs from marketplace → Azure
python3 tool/vsmex.py    # sync Microsoft's flagged lists → dataset + metadata
```

## License

See [LICENSE](LICENSE).

## Acknowledgements

We thank [Marc Ohm](https://github.com/dasfreak/Backstabbers-Knife-Collection) for the Backstabbers' Knife Collection, which provided initial malicious VS Code extension samples used in this dataset, and [Karlo Zanki](https://www.reversinglabs.com) from ReversingLabs for sharing additional samples.
