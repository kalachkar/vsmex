# VSMEx

**VSMEx (VSCode Malicious Extensions Dataset)** continuously collects and archives malicious VS Code extensions based on Microsoft’s official flagged lists.

---

## Structure

vsmex/
├── tool/ # Collection scripts
├── metadata/ # Incremental metadata
└── dataset/ # Malicious VSIX packages

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

---

## Optional: Cron Setup

```bash
# Run crawler 6x/day (every 4 hours) and vsmex daily
0 */4 * * * cd /path/to/vsmex/tool && /usr/bin/python3 crawler.py >/dev/null 2>&1
15 2 * * * cd /path/to/vsmex/tool && /usr/bin/python3 vsmex.py >> /path/to/vsmex/logs/vsmex.log 2>&1
```

---