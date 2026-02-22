# DFIR_Tools

A collection of Digital Forensics & Incident Response (DFIR) tools and scripts for evidence acquisition, analysis, and reporting.

Maintained by [dynamicallystatic](https://github.com/dynamicallystatic)

LinkedIn: [Bryan Ambrose](https://www.linkedin.com/in/bryan-a-2a30ab140)

---

## Table of Contents

| # | Tool | Category | Description |
|---|------|----------|-------------|
| 1 | [dfir_sqlite_dumper.py](#dfir_sqlite_dumperpy) | SQLite Forensics | Extract all SQLite tables to CSV with forensic metadata |
| 2 | [dfir_linux_collector.sh](#dfir_linux_collectorsh) | Linux Forensics | Collect forensic artifacts from a live Linux system |

---

## Tools

### [dfir_sqlite_dumper.py](https://github.com/dynamicallystatic/DFIR_Tools/blob/main/dfir_sqlite_dumper.py)

**Category:** SQLite Forensics

Extracts every table from a SQLite database into individual CSV files, with a forensic metadata report. Useful for analysing browser history, mobile device databases, application logs, and any other SQLite-backed artefact.

**Features:**
- Computes **MD5 & SHA256** hashes for chain of custody
- Exports **every table** to its own `.csv` file in an output folder
- Generates a `_dfir_extraction_report.txt` with file metadata and row counts
- Opens databases in **read-only mode** to preserve evidence integrity
- **No dependencies** — standard Python library only

**Usage:**
```bash
python3 dfir_sqlite_dumper.py <database_file> [-o output_dir] [--no-metadata]
```

**Example:**
```bash
python3 dfir_sqlite_dumper.py History
# Output: History_extracted/urls.csv, visits.csv, downloads.csv ... + report
```

---

### [dfir_linux_collector.sh](https://github.com/dynamicallystatic/DFIR_Tools/blob/main/dfir_linux_collector.sh)

**Category:** Linux Forensics

A bash script for collecting forensic evidence from a live Linux system. Offers three collection modes: triage, home, and full.

**Modes:**

| Mode | Flag | Description |
|------|------|-------------|
| Triage | `--triage` | Fast collection of key artifacts: processes, network, users, logs, persistence |
| Home | `--home` | Everything in triage + full copy of `/home/` and `/root/`, compressed to `.tar.gz` |
| Full | `--full` | Everything in home + full copy of the root filesystem, compressed to `.tar.gz` |

**Features:**
- Captures live system state: running processes, active connections, logged-in users
- Full filesystem copy of home directories or root with `rsync` (falls back to `tar` if unavailable)
- Enumerates persistence mechanisms: crontabs, systemd services, startup scripts, SSH keys
- Gathers logs: auth.log, syslog, wtmp, btmp, journalctl output
- Generates a `_dfir_collection_report.txt` with a full **SHA256 hash manifest**
- MD5 & SHA256 hash sidecar files for every `.tar.gz` archive produced
- **No dependencies beyond bash** — works on most Linux systems

**Requirements:** Bash, run as root (`sudo`)

**Usage:**
```bash
sudo bash dfir_linux_collector.sh [--triage | --home | --full] [-o output_dir]
```

**Examples:**
```bash
# Quick triage — fastest, lowest footprint
sudo bash dfir_linux_collector.sh --triage

# Home + full home directory copy to a USB drive
sudo bash dfir_linux_collector.sh --home -o /mnt/usb/case001

# Full root filesystem copy (requires ~2x filesystem size free on destination)
sudo bash dfir_linux_collector.sh --full -o /mnt/external/case001
```

---
