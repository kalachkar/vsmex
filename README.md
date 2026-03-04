# VSMEx

Dataset of malicious VS Code extensions collected from Microsoft's flagged extension lists.

To be presented at [CODASPY 2026](https://www.codaspy.org/2026/) — June 23–25, Frankfurt am Main.

```bibtex
@inproceedings{vsmex2026,
  author    = {Kotaiba Alachkar and Yury Zhauniarovich},
  title     = {VSMEx: A Collection Tool and a Dataset of Malicious VS Code Extensions},
  booktitle = {Proceedings of the 16th ACM Conference on Data and Application Security and Privacy (CODASPY)},
  year      = {2026},
  url       = {https://github.com/kalachkar/vsmex}
}
```

## Dataset access

VSIX binaries and full metadata are in [`kalachkar/vsmex-dataset`](https://github.com/kalachkar/vsmex-dataset) (private).
To request access, email from an institutional address stating your reason:

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
export AZURE_CONNECTION_STRING="..."
export AZURE_CONTAINER_NAME="..."
export GITHUB_PAT="..."
export GITHUB_USERNAME="kalachkar"
export GITHUB_REPO="vsmex"
export GITHUB_DATASET_REPO="vsmex-dataset"
```

```bash
python3 tool/crawler.py  # fetch new VSIXs from marketplace → Azure
python3 tool/vsmex.py    # sync Microsoft's flagged lists → dataset + metadata
```

## License

See [LICENSE](LICENSE).