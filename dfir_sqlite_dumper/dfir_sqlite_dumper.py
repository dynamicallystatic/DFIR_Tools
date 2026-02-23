#!/usr/bin/env python3
"""
DFIR SQLite Dumper
------------------
Digital Forensics & Incident Response tool for extracting SQLite database
contents into individual CSV files for analysis.

Usage:
    python dfir_sqlite_dumper.py <database_file> [options]

Examples:
    python dfir_sqlite_dumper.py sqlitedb.db
    python dfir_sqlite_dumper.py sqlitedb.db -o ./output
    python dfir_sqlite_dumper.py sqlitedb.db --no-metadata
"""

import sqlite3
import csv
import os
import sys
import argparse
import hashlib
import datetime


BANNER = r"""
 ____  _____ ___ ____       ____   ___  _     _ _       
|  _ \|  ___|_ _|  _ \     / ___| / _ \| |   (_) |_ ___ 
| | | | |_   | || |_) |____\___ \| | | | |   | | __/ _ \\
| |_| |  _|  | ||  _ <_____|__) | |_| | |___| | ||  __/
|____/|_|   |___|_| \_\   |____/ \__\_\_____|_|\__\___|
       SQLite Dumper for Digital Forensics & IR
"""


def compute_hash(filepath: str) -> dict:
    """Compute MD5 and SHA256 hashes of the input file for chain of custody."""
    hashes = {}
    for algo in ("md5", "sha256"):
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        hashes[algo] = h.hexdigest()
    return hashes


def get_tables(conn: sqlite3.Connection) -> list[str]:
    """Return a list of all user-defined table names in the database."""
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
    )
    return [row[0] for row in cursor.fetchall()]


def get_row_count(conn: sqlite3.Connection, table: str) -> int:
    """Return the number of rows in a table."""
    cursor = conn.execute(f"SELECT COUNT(*) FROM [{table}];")
    return cursor.fetchone()[0]


def dump_table_to_csv(conn: sqlite3.Connection, table: str, output_dir: str) -> dict:
    """
    Dump all rows from a table into a CSV file.
    Returns a summary dict with row count and output path.
    """
    safe_name = "".join(c if c.isalnum() or c in ("_", "-") else "_" for c in table)
    output_path = os.path.join(output_dir, f"{safe_name}.csv")

    cursor = conn.execute(f"SELECT * FROM [{table}];")
    columns = [description[0] for description in cursor.description]
    rows = cursor.fetchall()

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(columns)
        writer.writerows(rows)

    return {
        "table": table,
        "rows": len(rows),
        "columns": len(columns),
        "output_file": output_path,
    }


def write_metadata_report(
    db_path: str,
    hashes: dict,
    results: list[dict],
    output_dir: str,
    start_time: datetime.datetime,
):
    """Write a forensic metadata report summarising the extraction."""
    end_time = datetime.datetime.now()
    report_path = os.path.join(output_dir, "_dfir_extraction_report.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  DFIR SQLITE DUMPER - EXTRACTION REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"  Source File   : {os.path.abspath(db_path)}\n")
        f.write(f"  File Size     : {os.path.getsize(db_path):,} bytes\n")
        f.write(f"  MD5           : {hashes['md5']}\n")
        f.write(f"  SHA256        : {hashes['sha256']}\n")
        f.write(f"  Extraction    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Completed     : {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Output Dir    : {os.path.abspath(output_dir)}\n\n")
        f.write("-" * 70 + "\n")
        f.write(f"  Tables Found  : {len(results)}\n")
        f.write(f"  Total Rows    : {sum(r['rows'] for r in results):,}\n\n")
        f.write(f"  {'Table':<35} {'Rows':>10}  {'Columns':>8}  Output File\n")
        f.write(f"  {'-'*35} {'-'*10}  {'-'*8}  {'-'*30}\n")
        for r in results:
            fname = os.path.basename(r["output_file"])
            f.write(
                f"  {r['table']:<35} {r['rows']:>10,}  {r['columns']:>8}  {fname}\n"
            )
        f.write("\n" + "=" * 70 + "\n")

    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="DFIR SQLite Dumper — extract all SQLite tables to CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("database", help="Path to the SQLite database file")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory (default: <database_name>_extracted/)"
    )
    parser.add_argument(
        "--no-metadata", action="store_true",
        help="Skip writing the forensic metadata report"
    )
    args = parser.parse_args()

    print(BANNER)

    # Validate input file
    db_path = args.database
    if not os.path.isfile(db_path):
        print(f"[ERROR] File not found: {db_path}")
        sys.exit(1)

    # Determine output directory
    db_basename = os.path.splitext(os.path.basename(db_path))[0]
    output_dir = args.output or f"{db_basename}_extracted"
    os.makedirs(output_dir, exist_ok=True)

    # Start time for report
    start_time = datetime.datetime.now()
    print(f"[*] Source      : {os.path.abspath(db_path)}")
    print(f"[*] Output Dir  : {os.path.abspath(output_dir)}")
    print()

    # Hash the file (chain of custody)
    print("[*] Computing file hashes (chain of custody)...")
    hashes = compute_hash(db_path)
    print(f"    MD5    : {hashes['md5']}")
    print(f"    SHA256 : {hashes['sha256']}")
    print()

    # Connect to DB (read-only to preserve evidence integrity)
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.OperationalError as e:
        print(f"[ERROR] Could not open database: {e}")
        sys.exit(1)

    # Get tables
    tables = get_tables(conn)
    if not tables:
        print("[!] No tables found in database.")
        conn.close()
        sys.exit(0)

    print(f"[*] Found {len(tables)} table(s): {', '.join(tables)}")
    print()

    # Dump each table
    results = []
    for table in tables:
        print(f"    [+] Dumping: {table:<35}", end="", flush=True)
        try:
            result = dump_table_to_csv(conn, table, output_dir)
            results.append(result)
            print(f"  {result['rows']:>8,} rows  →  {os.path.basename(result['output_file'])}")
        except Exception as e:
            print(f"\n    [!] Error dumping table '{table}': {e}")

    conn.close()
    print()

    # Write forensic report
    if not args.no_metadata:
        report_path = write_metadata_report(db_path, hashes, results, output_dir, start_time)
        print(f"[*] Forensic report : {report_path}")

    total_rows = sum(r["rows"] for r in results)
    print(f"[*] Done — {len(results)} table(s), {total_rows:,} total rows extracted to '{output_dir}/'")
    print()


if __name__ == "__main__":
    main()
