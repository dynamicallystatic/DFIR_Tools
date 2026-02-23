# DFIR_Tools

A collection of Digital Forensics & Incident Response (DFIR) tools and scripts for evidence acquisition, analysis, and reporting.

Maintained by [dynamicallystatic](https://github.com/dynamicallystatic)

LinkedIn: [Bryan Ambrose](https://www.linkedin.com/in/bryan-a-2a30ab140)

---

## Table of Contents

| # | Tool | Category | Description |
|---|------|----------|--------------|
| 1 | [dfir_sqlite_dumper.py](#dfir_sqlite_dumperpy) | SQLite Forensics | Extract all SQLite tables to CSV with forensic metadata |
| 2 | [dfir_linux_collector.sh](#dfir_linux_collectorsh) | Linux Forensics | Collect forensic artifacts from a live Linux system |
| 3 | [dfir_windows_registry_reporter.exe](#dfir_windows_registry_reporterexe) | Windows Forensics | Comprehensive Windows registry forensic triage tool |
| 4 | [dfir_artifact_carver/](#dfir_artifact_carver) | File Carving | Cross-platform file carver with SQLite index and CSV report |

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

### [dfir_windows_registry_reporter.exe](https://github.com/dynamicallystatic/DFIR_Tools/blob/main/dfir_windows_registry_reporter.exe)

**Category:** Windows Forensics

Standalone Windows executable for exported csv reports of registry artifacts.

**Artifact Categories:**

| Hive | Artifacts Collected |
|------|---------------------|
| **NTUSER.DAT** | UserAssist, RecentDocs, TypedPaths, OpenSaveMRU, LastVisitedMRU, RunMRU, SearchHistory, MappedDrives, PuTTY Sessions, TypedURLs |
| **SOFTWARE** | OS Info, Installed Software, Network History, Autoruns |
| **SYSTEM** | TimeZone, USB Devices, Network Interfaces, Shares, Last Shutdown, Services |
| **SAM** | Local User Accounts (requires Administrator) |

**Features:**
- Supports **offline hive files** with `--hive-dir` command
- Each artifact exported to a **CSV file**
- Master `_FULL_REPORT_*.csv` combining all artifacts into one file
- Captures network history with **first seen / last connected** timestamps
- Enumerates USB storage devices

**Requirements:** Windows only — no install needed, just run the exe

**Usage:**
```cmd
:: Live registry (no admin needed for most artifacts)
dfir_windows_registry_reporter.exe

:: Offline hive files from a suspect machine
dfir_windows_registry_reporter.exe --hive-dir C:\path\to\hives\

:: Custom output directory
dfir_windows_registry_reporter.exe -o C:\Cases\Case001\registry\
```

---

### [dfir_artifact_carver/](https://github.com/dynamicallystatic/DFIR_Tools/tree/main/dfir_artifact_carver)

**Category:** File Carving

Cross-platform Python file carving and indexing tool. Carves forensic artifacts from disk images, directories, or the live filesystem using a configurable YAML signature file with built-in file types.

**Artifact Categories:**

| Category | File Types |
|----------|------------|
| **Images** | jpg, png, gif, bmp, heic, webp, cr2, tiff |
| **Documents** | pdf, docx/xlsx/pptx, doc, rtf |
| **Databases** | sqlite, mdb |
| **Windows Artifacts** | prefetch (.pf), LNK, EVTX, registry hives |
| **Archives** | zip, 7z, rar, gz, iso |
| **Executables** | PE (exe/dll), ELF, Mach-O, Java class |
| **Media** | mp4/mov, avi, mpg, wmv, mkv, mp3, wav, flac |
| **Email** | pst, mbox, emlx |
| **Network** | pcap, pcapng |

**Features:**
- Carves **file types** using configurable byte signatures
- Three input modes: **disk image** (.dd/.raw/.e01), **directory**, **live filesystem**
- Multi-threaded scanning with progress bar
- Optional **file validation** pass (verifies carved files actually open)
- **SQLite index** (`index.db`) — file, type, offset, size, MD5, SHA256
- **CSV report** (`report.csv`) for spreadsheet review
- Carved files organized into subfolders by category
- `signatures.yaml` — enable/disable types, set max sizes, add custom signatures

**Requirements:** Python 3.10+, cross-platform — `pip install pyyaml tqdm pillow`

**Usage:**
```bash
# Carve a disk image
python dfir_artifact_carver.py --image disk.dd --output carved/

# Scan a directory recursively
python dfir_artifact_carver.py --dir /path/to/dir --output carved/

# Live filesystem scan
python dfir_artifact_carver.py --live --root C:\ --output carved/

# Custom signatures + more threads
python dfir_artifact_carver.py --image disk.dd --config my_sigs.yaml --threads 8
```

---
