# DFIR_Tools

A collection of Digital Forensics & Incident Response (DFIR) tools and scripts for evidence acquisition, analysis, and reporting.

Maintained by [@dynamicallystatic](https://github.com/dynamicallystatic)

---

## 📚 Table of Contents

| # | Tool | Category | Description |
|---|------|----------|-------------|
| 1 | [dfir_sqlite_dumper.py](#1-dfir_sqlite_dumperpy) | Database Forensics | Extract all SQLite tables to CSV with forensic metadata |
| – | *(more tools coming soon)* | | |

---

## Tools

### 1. [dfir_sqlite_dumper.py](https://github.com/dynamicallystatic/DFIR_Tools/blob/main/dfir_sqlite_dumper.py)

**Category:** Database Forensics

Extracts every table from a SQLite database into individual CSV files, with a forensic metadata report. Useful for analysing browser history, mobile device databases, application logs, and any other SQLite-backed artefact.

**Features:**
- 🔐 Computes **MD5 & SHA256** hashes for chain of custody
- 📂 Exports **every table** to its own `.csv` file in an output folder
- 📄 Generates a `_dfir_extraction_report.txt` with file metadata and row counts
- 🔒 Opens databases in **read-only mode** to preserve evidence integrity
- 🧰 **No dependencies** — standard Python library only

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

