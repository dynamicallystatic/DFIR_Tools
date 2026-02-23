#!/usr/bin/env python3
"""
DFIR Artifact Carver
---------------------
Cross-platform file carving and indexing tool.
Carves files from disk images, directories, or the live filesystem using
configurable byte signatures (signatures.yaml).

Outputs:
  - Carved files organised by type in the output directory
  - SQLite index (index.db) with offset, size, hashes, validation status
  - CSV report (report.csv)

Usage:
    python dfir_artifact_carver.py --image disk.dd --output carved/
    python dfir_artifact_carver.py --dir /path/to/dir --output carved/
    python dfir_artifact_carver.py --live --dir C:\\ --output carved/

Requirements:
    pip install pyyaml tqdm pillow
"""

import os
import sys
import csv
import re
import struct
import hashlib
import sqlite3
import datetime
import argparse
import threading
import queue
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Optional deps ──────────────────────────────────────────────────────────────
try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

try:
    from tqdm import tqdm
    HAVE_TQDM = True
except ImportError:
    HAVE_TQDM = False

try:
    from PIL import Image as PILImage
    import io as _io
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

SCRIPT_VERSION = "1.0.0"
SCRIPT_DIR     = Path(__file__).resolve().parent
DEFAULT_SIG    = SCRIPT_DIR / "signatures.yaml"

BANNER = r"""
   ____
  / ___|__ _ _ ____   _____ _ __
 | |   / _` | '__\ \ / / _ \ '__|
 | |__| (_| | |   \ V /  __/ |
  \____\__,_|_|    \_/ \___|_|
       DFIR Artifact Carver  v{}
""".format(SCRIPT_VERSION)

# ── SQLite schema ──────────────────────────────────────────────────────────────
DB_DDL = """
CREATE TABLE IF NOT EXISTS carved_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT,
    type        TEXT,
    category    TEXT,
    source      TEXT,
    offset      INTEGER,
    size_bytes  INTEGER,
    md5         TEXT,
    sha256      TEXT,
    valid       INTEGER DEFAULT 0,
    carved_at   TEXT
);
"""

CSV_FIELDS = ["id", "filename", "type", "category", "source",
              "offset", "size_bytes", "md5", "sha256", "valid", "carved_at"]

# ── Helpers ────────────────────────────────────────────────────────────────────

def hex_str_to_pattern(hex_str: str) -> bytes | None:
    """
    Convert a hex string like 'FF D8 FF ?? E0' to a bytes pattern.
    Returns a compiled regex pattern (bytes) supporting ?? wildcards.
    """
    tokens = hex_str.strip().split()
    pattern = b""
    for t in tokens:
        if t == "??":
            pattern += b"."     # regex wildcard
        else:
            pattern += re.escape(bytes.fromhex(t))
    return pattern


def compile_signature(sig: dict) -> dict | None:
    """Compile a signature entry into a ready-to-use dict with regex patterns."""
    try:
        header_pat = hex_str_to_pattern(sig["header"])
        footer_pat = hex_str_to_pattern(sig.get("footer", "")) if sig.get("footer") else None
        return {
            "name":          sig["name"],
            "category":      sig.get("category", "Unknown"),
            "extension":     sig.get("extension", "bin"),
            "header_bytes":  bytes.fromhex(sig["header"].replace("??", "00").replace(" ", "")),
            "header_pat":    re.compile(header_pat, re.DOTALL),
            "footer_pat":    re.compile(footer_pat, re.DOTALL) if footer_pat else None,
            "header_offset": sig.get("header_offset", 0),
            "max_size":      int(sig.get("max_size_mb", 10)) * 1024 * 1024,
            "min_size":      int(sig.get("min_size_kb", 1)) * 1024,
            "validate":      sig.get("validate", False),
        }
    except Exception as e:
        print(f"  [!] Could not compile signature '{sig.get('name', '?')}': {e}")
        return None


def load_signatures(config_path: Path) -> list[dict]:
    if not HAVE_YAML:
        print("[!] pyyaml not installed — pip install pyyaml")
        sys.exit(1)
    if not config_path.is_file():
        print(f"[!] Signatures file not found: {config_path}")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    sigs = []
    for s in raw.get("signatures", []):
        if not s.get("enabled", True):
            continue
        compiled = compile_signature(s)
        if compiled:
            sigs.append(compiled)
    return sigs


def hash_bytes(data: bytes) -> tuple[str, str]:
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def validate_file(data: bytes, sig: dict) -> bool:
    """Attempt to validate the carved data actually matches the claimed type."""
    ext = sig["extension"].lower()
    try:
        if ext in ("jpg", "jpeg", "png", "gif", "bmp", "webp") and HAVE_PIL:
            PILImage.open(_io.BytesIO(data)).verify()
            return True
        if ext == "sqlite":
            tmp = Path(os.environ.get("TEMP", "/tmp")) / f"_carve_tmp_{threading.get_ident()}.db"
            tmp.write_bytes(data)
            conn = sqlite3.connect(str(tmp))
            conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            conn.close()
            tmp.unlink(missing_ok=True)
            return True
        if ext in ("exe", "dll"):
            return data[:2] == b"MZ"
        if ext == "elf":
            return data[:4] == b"\x7fELF"
        if ext == "pdf":
            return data[:4] == b"%PDF"
    except Exception:
        return False
    return True  # no specific validator — assume ok


# ── Carving engine ─────────────────────────────────────────────────────────────

class CarveResult:
    __slots__ = ("sig", "source", "offset", "data")
    def __init__(self, sig, source, offset, data):
        self.sig    = sig
        self.source = source
        self.offset = offset
        self.data   = data


def scan_chunk(chunk: bytes, offset_base: int, sigs: list[dict], source: str) -> list[CarveResult]:
    """Scan a bytes chunk and return a list of CarveResult candidates."""
    results = []
    for sig in sigs:
        pos = 0
        while True:
            m = sig["header_pat"].search(chunk, pos)
            if not m:
                break
            start = m.start()
            abs_offset = offset_base + start

            # Determine end of carved data
            end = start + sig["max_size"]
            if sig["footer_pat"]:
                fm = sig["footer_pat"].search(chunk, start)
                if fm:
                    footer_end = fm.end()
                    end = footer_end
                else:
                    # Footer not found in this chunk — skip (will pick up in next chunk overlap)
                    pos = start + 1
                    continue

            data = chunk[start:end]
            if len(data) >= sig["min_size"]:
                results.append(CarveResult(sig, source, abs_offset, data))

            pos = start + 1

    return results


def read_image_chunks(image_path: Path, chunk_size: int, overlap: int):
    """Generator: yield (chunk_bytes, file_offset) from a disk image with overlap."""
    file_size = image_path.stat().st_size
    with open(image_path, "rb") as f:
        offset = 0
        prev_tail = b""
        pbar = tqdm(total=file_size, unit="B", unit_scale=True,
                    desc="  Scanning image", disable=not HAVE_TQDM)
        while offset < file_size:
            raw = f.read(chunk_size)
            if not raw:
                break
            chunk = prev_tail + raw
            yield chunk, max(0, offset - len(prev_tail))
            prev_tail = raw[-overlap:] if len(raw) > overlap else raw
            offset += len(raw)
            pbar.update(len(raw))
        pbar.close()


def read_file_chunks(file_path: Path, chunk_size: int, overlap: int):
    """Generator: yield (chunk_bytes, file_offset) from any file."""
    yield from read_image_chunks(file_path, chunk_size, overlap)


# ── Output ─────────────────────────────────────────────────────────────────────

class OutputManager:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._db_path  = output_dir / "index.db"
        self._csv_path = output_dir / "report.csv"
        self._conn     = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._lock     = threading.Lock()
        self._counter  = 0
        self._conn.execute(DB_DDL)
        self._conn.commit()
        self._csv_file = open(self._csv_path, "w", newline="", encoding="utf-8")
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=CSV_FIELDS)
        self._csv_writer.writeheader()

    def save(self, result: CarveResult, validate: bool) -> dict:
        data  = result.data
        sig   = result.sig
        valid = 0
        if validate and sig["validate"]:
            valid = 1 if validate_file(data, sig) else -1

        md5, sha256 = hash_bytes(data)
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Save file
        cat_dir = self.output_dir / sig["category"].replace(" ", "_")
        cat_dir.mkdir(exist_ok=True)
        with self._lock:
            self._counter += 1
            count = self._counter
        fname = f"{count:06d}_{sig['extension']}_off{result.offset}.{sig['extension']}"
        fpath = cat_dir / fname
        fpath.write_bytes(data)

        row = {
            "id":         count,
            "filename":   str(fpath.relative_to(self.output_dir)),
            "type":       sig["name"],
            "category":   sig["category"],
            "source":     result.source,
            "offset":     result.offset,
            "size_bytes": len(data),
            "md5":        md5,
            "sha256":     sha256,
            "valid":      valid,
            "carved_at":  now,
        }
        with self._lock:
            self._conn.execute(
                "INSERT INTO carved_files (filename,type,category,source,offset,"
                "size_bytes,md5,sha256,valid,carved_at) VALUES "
                "(:filename,:type,:category,:source,:offset,:size_bytes,"
                ":md5,:sha256,:valid,:carved_at)", row)
            self._conn.commit()
            self._csv_writer.writerow(row)
            self._csv_file.flush()
        return row

    def close(self):
        self._conn.close()
        self._csv_file.close()

    @property
    def total(self):
        return self._counter


# ── Mode handlers ──────────────────────────────────────────────────────────────

def carve_image(image_path: Path, sigs: list[dict], out: OutputManager,
                chunk_mb: int, threads: int, validate: bool):
    overlap  = max(sig["max_size"] for sig in sigs)
    overlap  = min(overlap, 10 * 1024 * 1024)  # cap overlap at 10 MB
    chunk_sz = chunk_mb * 1024 * 1024
    source   = str(image_path)
    futures  = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for chunk, base_offset in read_image_chunks(image_path, chunk_sz, overlap):
            fut = pool.submit(scan_chunk, chunk, base_offset, sigs, source)
            futures.append(fut)
        for fut in as_completed(futures):
            for result in fut.result():
                out.save(result, validate)


def carve_directory(root: Path, sigs: list[dict], out: OutputManager,
                    chunk_mb: int, threads: int, validate: bool, skip_carved: Path):
    overlap  = max(sig["max_size"] for sig in sigs)
    overlap  = min(overlap, 10 * 1024 * 1024)
    chunk_sz = chunk_mb * 1024 * 1024

    files = [p for p in root.rglob("*")
             if p.is_file() and not str(p).startswith(str(skip_carved))]

    pbar = tqdm(files, desc="  Scanning files", unit="file", disable=not HAVE_TQDM)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for fpath in pbar:
            try:
                source = str(fpath)
                futures = []
                for chunk, base_offset in read_file_chunks(fpath, chunk_sz, overlap):
                    fut = pool.submit(scan_chunk, chunk, base_offset, sigs, source)
                    futures.append(fut)
                for fut in as_completed(futures):
                    for result in fut.result():
                        out.save(result, validate)
            except (PermissionError, OSError):
                pass


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"DFIR Artifact Carver v{SCRIPT_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Input options
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--image", metavar="PATH",
                     help="Disk image to carve (.dd, .raw, .e01, etc.)")
    grp.add_argument("--dir",   metavar="PATH",
                     help="Directory to recursively scan")
    grp.add_argument("--live",  action="store_true",
                     help="Live filesystem scan — use with --root")
    parser.add_argument("--root", metavar="PATH", default="/",
                        help="Root path for --live mode (default: /)")

    # Output / config
    parser.add_argument("-o", "--output",  default="carved_output",
                        metavar="PATH",    help="Output directory (default: carved_output/)")
    parser.add_argument("-c", "--config",  default=str(DEFAULT_SIG),
                        metavar="PATH",    help=f"Signatures YAML (default: {DEFAULT_SIG.name})")

    # Tuning
    parser.add_argument("--threads",    type=int,   default=4,  help="Worker threads (default: 4)")
    parser.add_argument("--chunk-size", type=int,   default=64, metavar="MB",
                        help="Read chunk size in MB for image mode (default: 64)")
    parser.add_argument("--no-validate", action="store_true",
                        help="Skip file validation pass")
    args = parser.parse_args()

    print(BANNER)
    print(f"[*] DFIR Artifact Carver  v{SCRIPT_VERSION}")
    print(f"[*] Signatures   : {args.config}")
    print(f"[*] Output       : {os.path.abspath(args.output)}")
    print(f"[*] Threads      : {args.threads}")
    print(f"[*] Validate     : {not args.no_validate}")
    print()

    # Load signatures
    sigs = load_signatures(Path(args.config))
    print(f"[+] Loaded {len(sigs)} enabled signatures")
    print()

    out = OutputManager(Path(args.output))
    start_time = datetime.datetime.utcnow()

    try:
        if args.image:
            img = Path(args.image)
            if not img.is_file():
                print(f"[!] Image not found: {img}")
                sys.exit(1)
            print(f"[*] Mode: Disk Image → {img}  ({img.stat().st_size / 1e9:.2f} GB)")
            carve_image(img, sigs, out, args.chunk_size, args.threads,
                        not args.no_validate)

        elif args.dir:
            d = Path(args.dir)
            if not d.is_dir():
                print(f"[!] Directory not found: {d}")
                sys.exit(1)
            print(f"[*] Mode: Directory → {d}")
            carve_directory(d, sigs, out, args.chunk_size, args.threads,
                            not args.no_validate, Path(args.output).resolve())

        elif args.live:
            root = Path(args.root)
            print(f"[*] Mode: Live Filesystem → {root}")
            carve_directory(root, sigs, out, args.chunk_size, args.threads,
                            not args.no_validate, Path(args.output).resolve())

    finally:
        out.close()

    elapsed = (datetime.datetime.utcnow() - start_time).total_seconds()
    print()
    print(f"[+] Carving complete in {elapsed:.1f}s")
    print(f"[+] Total files carved : {out.total}")
    print(f"[+] Carved files       : {os.path.abspath(args.output)}/")
    print(f"[+] SQLite index       : {os.path.abspath(args.output)}/index.db")
    print(f"[+] CSV report         : {os.path.abspath(args.output)}/report.csv")
    print()


if __name__ == "__main__":
    main()
