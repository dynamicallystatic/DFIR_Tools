#!/usr/bin/env python3
"""
DFIR Windows Registry Reporter
--------------------------------
Comprehensive Windows Registry forensic triage tool.

Artifacts collected (live registry + optional offline hives):

  NTUSER.DAT (per-user):
    - UserAssist         (recently executed programs, run count, last run time)
    - RecentDocs         (recently opened files, grouped by extension)
    - TypedPaths         (paths typed into Explorer address bar)
    - OpenSaveMRU        (files opened/saved via Open/Save dialogs)
    - LastVisitedMRU     (apps + folders used in Open/Save dialogs)
    - RunMRU             (commands typed into the Run box)
    - SearchHistory      (terms searched in Explorer / WordWheelQuery)
    - Mapped Drives      (mapped network drives)
    - PuTTY Sessions     (saved SSH sessions)
    - Typed URLs         (URLs typed into IE / legacy Edge)

  SOFTWARE (HKLM):
    - OS Information     (build, version, install date, owner)
    - Installed Software (display name, version, install date, publisher)
    - Network History    (SSIDs / networks ever connected, first/last seen)
    - Time Zone          (system timezone — critical for timeline analysis)
    - Autoruns           (Run, RunOnce, Winlogon entries)

  SYSTEM (HKLM):
    - USB Devices        (every USB storage device ever connected)
    - Network Interfaces (NIC configs and IP history)
    - Shares             (local SMB shares)
    - Last Shutdown Time
    - ShimCache          (AppCompatCache — offline hive only)

  SAM (HKLM — requires admin):
    - Local User Accounts (username, RID, last logon, account flags)

Usage:
    python dfir_windows_registry_reporter.py [--live] [--hive-dir PATH] [-o OUTPUT_DIR]

Requirements:
    pip install python-registry
"""

import os
import sys
import csv
import struct
import codecs
import argparse
import datetime
import winreg
from pathlib import Path

try:
    from Registry import Registry
    REGISTRY_LIB = True
except ImportError:
    REGISTRY_LIB = False

SCRIPT_VERSION = "1.1.0"

BANNER = r"""
 __      ___         _____          _     _              
 \ \    / (_)       |  __ \        (_)   | |             
  \ \  / / _ _ __   | |__) |___  __ _ ___| |_ _ __ _   _ 
   \ \/ / | | '_ \  |  _  // _ \/ _` | / __| __| '__| | | |
    \  /  | | | | | | | \ \  __/ (_| | \__ \ |_| |  | |_| |
     \/   |_|_| |_| |_|  \_\___|\__, |_|___/\__|_|   \__, |
                                  __/ |                __/ |
         Windows Registry        |___/  DFIR Reporter |___/ 
"""

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def filetime_to_str(ft: int) -> str:
    """Convert Windows FILETIME (100-ns since 1601-01-01) to readable UTC string."""
    try:
        if ft == 0:
            return "N/A"
        us = ft // 10
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def unix_to_str(ts: int) -> str:
    try:
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def clean_str(value) -> str:
    """Strip null bytes, non-printable chars, and normalise whitespace."""
    if isinstance(value, bytes):
        for enc in ("utf-16-le", "utf-8", "latin-1"):
            try:
                value = value.decode(enc, errors="ignore")
                break
            except Exception:
                continue
    s = str(value)
    s = "".join(c for c in s if c.isprintable())
    return " ".join(s.split())[:500]


def extract_pidl_string(data: bytes) -> str:
    """
    Extract a human-readable name from a Shell Item List (PIDL) binary blob.

    RecentDocs stores values as: [UTF-16LE filename + null-terminator] + [PIDL bytes]
    OpenSavePidlMRU / LastVisitedPidlMRU store raw PIDLs.
    We try the leading null-terminated string first, then fall back to scanning
    for the longest embedded UTF-16LE printable run (>= 4 chars).
    """
    if not isinstance(data, bytes) or not data:
        return clean_str(data)

    # --- Strategy 1: leading null-terminated UTF-16LE string (RecentDocs) ---
    try:
        text = data.decode("utf-16-le", errors="ignore")
        idx  = text.find("\x00")
        if idx > 1:
            candidate = text[:idx].strip()
            if len(candidate) >= 2 and all(c.isprintable() for c in candidate):
                return candidate
    except Exception:
        pass

    # --- Strategy 2: scan for longest embedded UTF-16LE printable string ---
    # Try from BOTH byte offsets (0 and 1) so we never sync to an odd boundary.
    def _scan_offset(blob: bytes, start: int) -> str:
        best_run = ""
        i = start
        while i < len(blob) - 1:
            try:
                ch = blob[i:i+2].decode("utf-16-le")
            except Exception:
                i += 2
                continue
            if ch.isprintable() and ch != "\x00":
                run = ch
                j = i + 2
                while j < len(blob) - 1:
                    try:
                        nc = blob[j:j+2].decode("utf-16-le")
                    except Exception:
                        break
                    if nc.isprintable() and nc != "\x00":
                        run += nc
                        j   += 2
                    else:
                        break
                if len(run) >= 4 and len(run) > len(best_run):
                    best_run = run.strip()
                i = j + 2
            else:
                i += 2
        return best_run

    candidate_even = _scan_offset(data, 0)
    candidate_odd  = _scan_offset(data, 1)
    best = candidate_even if len(candidate_even) >= len(candidate_odd) else candidate_odd
    return best[:500] if best else ""


def row(artifact: str, source: str, name: str, value,
        timestamp: str = "N/A", notes: str = "") -> dict:
    return {"Artifact": artifact, "Source": source,
            "Name":     clean_str(name),
            "Value":    clean_str(value),
            "Timestamp": timestamp, "Notes": clean_str(notes)}


def enum_values(key) -> list[tuple]:
    """Yield all (name, data, type) from an open winreg key."""
    results = []
    i = 0
    while True:
        try:
            results.append(winreg.EnumValue(key, i))
            i += 1
        except OSError:
            break
    return results


def enum_subkeys(key) -> list[str]:
    names = []
    i = 0
    while True:
        try:
            names.append(winreg.EnumKey(key, i))
            i += 1
        except OSError:
            break
    return names


def open_key_safe(hive, path: str):
    try:
        return winreg.OpenKey(hive, path)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# NTUSER.DAT  (live HKCU — no admin required)
# ─────────────────────────────────────────────────────────────────────────────

def collect_userassist() -> list[dict]:
    results = []
    ua_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    ua_key = open_key_safe(winreg.HKEY_CURRENT_USER, ua_path)
    if not ua_key:
        return [row("UserAssist", ua_path, "ERROR", "Key not found")]
    for guid in enum_subkeys(ua_key):
        count_key = open_key_safe(ua_key, guid + r"\Count")
        if not count_key:
            continue
        for name, value, _ in enum_values(count_key):
            decoded = rot13(name)
            run_count = "N/A"
            last_run  = "N/A"
            if isinstance(value, bytes) and len(value) >= 72:
                run_count = struct.unpack_from("<I", value, 4)[0]
                filetime  = struct.unpack_from("<Q", value, 60)[0]
                last_run  = filetime_to_str(filetime)
            results.append(row("UserAssist", f"HKCU\\{ua_path}\\{guid}\\Count",
                               decoded, f"RunCount={run_count}", last_run))
        winreg.CloseKey(count_key)
    winreg.CloseKey(ua_key)
    return results


def collect_recent_docs() -> list[dict]:
    results = []
    rd_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    rd_key = open_key_safe(winreg.HKEY_CURRENT_USER, rd_path)
    if not rd_key:
        return [row("RecentDocs", rd_path, "ERROR", "Key not found")]
    # Root-level values
    for name, value, _ in enum_values(rd_key):
        if name.upper().startswith("MRU") or name == "":
            continue
        text = extract_pidl_string(value) if isinstance(value, bytes) else clean_str(value)
        if text:
            results.append(row("RecentDocs", f"HKCU\\{rd_path}", name, text))
    # Sub-keys grouped by extension (e.g. .docx, .pdf)
    for ext in enum_subkeys(rd_key):
        sub = open_key_safe(rd_key, ext)
        if not sub:
            continue
        for name, value, _ in enum_values(sub):
            if name.upper().startswith("MRU"):
                continue
            text = extract_pidl_string(value) if isinstance(value, bytes) else clean_str(value)
            if text:
                results.append(row("RecentDocs", f"HKCU\\{rd_path}\\{ext}", name, text))
        winreg.CloseKey(sub)
    winreg.CloseKey(rd_key)
    return results


def collect_typed_paths() -> list[dict]:
    results = []
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, path)
    if not key:
        return [row("TypedPaths", path, "INFO", "Key not found or empty")]
    for name, value, _ in enum_values(key):
        results.append(row("TypedPaths", f"HKCU\\{path}", name, str(value)))
    winreg.CloseKey(key)
    return results


def collect_opensave_mru() -> list[dict]:
    results = []
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, base)
    if not key:
        return [row("OpenSaveMRU", base, "INFO", "Key not found")]
    for ext in enum_subkeys(key):
        sub = open_key_safe(key, ext)
        if not sub:
            continue
        for name, value, _ in enum_values(sub):
            if name.upper().startswith("MRU"):
                continue
            text = extract_pidl_string(value) if isinstance(value, bytes) else clean_str(value)
            if text:
                results.append(row("OpenSaveMRU", f"HKCU\\{base}\\{ext}", name, text))
        winreg.CloseKey(sub)
    winreg.CloseKey(key)
    return results


def collect_lastvisited_mru() -> list[dict]:
    results = []
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, base)
    if not key:
        return [row("LastVisitedMRU", base, "INFO", "Key not found")]
    for name, value, _ in enum_values(key):
        if name.upper().startswith("MRU"):
            continue
        text = extract_pidl_string(value) if isinstance(value, bytes) else clean_str(value)
        if text:
            results.append(row("LastVisitedMRU", f"HKCU\\{base}", name, text))
    winreg.CloseKey(key)
    return results


def collect_run_mru() -> list[dict]:
    results = []
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, path)
    if not key:
        return [row("RunMRU", path, "INFO", "Key not found or empty")]
    for name, value, _ in enum_values(key):
        if name == "MRUList":
            continue
        results.append(row("RunMRU", f"HKCU\\{path}", name, str(value)))
    winreg.CloseKey(key)
    return results


def collect_search_history() -> list[dict]:
    results = []
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, path)
    if not key:
        return [row("SearchHistory", path, "INFO", "Key not found")]
    for name, value, _ in enum_values(key):
        if name == "MRUListEx":
            continue
        try:
            text = value.decode("utf-16-le").rstrip("\x00")
        except Exception:
            text = repr(value)
        results.append(row("SearchHistory", f"HKCU\\{path}", name, text))
    winreg.CloseKey(key)
    return results


def collect_mapped_drives() -> list[dict]:
    results = []
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Network\Persistent Connections"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, path)
    # Also try legacy path
    if not key:
        path = r"Network"
        key = open_key_safe(winreg.HKEY_CURRENT_USER, path)
    if not key:
        return [row("MappedDrives", path, "INFO", "No mapped drives found")]
    for drive in enum_subkeys(key):
        sub = open_key_safe(key, drive)
        if not sub:
            continue
        vals = {n: v for n, v, _ in enum_values(sub)}
        remote = vals.get("RemotePath", vals.get("remotepath", ""))
        user   = vals.get("UserName",   vals.get("username",   ""))
        results.append(row("MappedDrives", f"HKCU\\{path}", drive,
                           str(remote), notes=f"User={user}"))
        winreg.CloseKey(sub)
    winreg.CloseKey(key)
    return results


def collect_putty_sessions() -> list[dict]:
    results = []
    path = r"SOFTWARE\SimonTatham\PuTTY\Sessions"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, path)
    if not key:
        return [row("PuTTY Sessions", path, "INFO", "PuTTY not found or no saved sessions")]
    for session in enum_subkeys(key):
        sub = open_key_safe(key, session)
        if not sub:
            continue
        vals = {n: v for n, v, _ in enum_values(sub)}
        hostname  = vals.get("HostName",  "")
        port      = vals.get("PortNumber", "")
        username  = vals.get("UserName",  "")
        protocol  = vals.get("Protocol",  "ssh")
        results.append(row("PuTTY Sessions", f"HKCU\\{path}", session,
                           str(hostname), notes=f"Port={port} User={username} Proto={protocol}"))
        winreg.CloseKey(sub)
    winreg.CloseKey(key)
    return results


def collect_typed_urls() -> list[dict]:
    results = []
    path = r"SOFTWARE\Microsoft\Internet Explorer\TypedURLs"
    key = open_key_safe(winreg.HKEY_CURRENT_USER, path)
    if not key:
        return [row("TypedURLs", path, "INFO", "No IE typed URL history found")]
    for name, value, _ in enum_values(key):
        results.append(row("TypedURLs", f"HKCU\\{path}", name, str(value)))
    winreg.CloseKey(key)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# SOFTWARE  (live HKLM — no admin required)
# ─────────────────────────────────────────────────────────────────────────────

def collect_os_info() -> list[dict]:
    results = []
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    fields = ["ProductName", "CurrentVersion", "CurrentBuildNumber", "UBR",
              "ReleaseId", "DisplayVersion", "RegisteredOwner",
              "RegisteredOrganization", "InstallDate"]
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("OS Info", path, "ERROR", "Key not found")]
    for field in fields:
        try:
            val, _ = winreg.QueryValueEx(key, field)
            if field == "InstallDate" and isinstance(val, int):
                val = unix_to_str(val)
            results.append(row("OS Info", f"HKLM\\{path}", field, str(val)))
        except Exception:
            pass
    winreg.CloseKey(key)
    return results


def collect_installed_software() -> list[dict]:
    results = []
    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM 64-bit"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM 32-bit"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
    ]
    for hive, path, label in uninstall_paths:
        key = open_key_safe(hive, path)
        if not key:
            continue
        for subkey_name in enum_subkeys(key):
            sub = open_key_safe(key, subkey_name)
            if not sub:
                continue
            vals = {n: v for n, v, _ in enum_values(sub)}
            display_name = vals.get("DisplayName", "")
            if not display_name:
                winreg.CloseKey(sub)
                continue
            version   = vals.get("DisplayVersion", "")
            publisher = vals.get("Publisher", "")
            inst_date = vals.get("InstallDate", "")
            inst_loc  = vals.get("InstallLocation", "")
            results.append(row("Installed Software", f"{label}\\{path}",
                               str(display_name), str(version),
                               notes=f"Publisher={publisher} InstallDate={inst_date} Location={inst_loc}"))
            winreg.CloseKey(sub)
        winreg.CloseKey(key)
    return results


def collect_network_history() -> list[dict]:
    results = []
    sigs_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, sigs_path)
    if key:
        for sig in enum_subkeys(key):
            sub = open_key_safe(key, sig)
            if not sub:
                continue
            vals = {n: v for n, v, _ in enum_values(sub)}
            ssid        = vals.get("DefaultGatewayMac", "")
            profile     = vals.get("ProfileGuid", "")
            description = vals.get("Description", "")
            results.append(row("Network History", f"HKLM\\{sigs_path}",
                               str(description), str(ssid),
                               notes=f"ProfileGuid={profile}"))
            winreg.CloseKey(sub)
        winreg.CloseKey(key)

    # Profiles with first/last connected timestamps
    profiles_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, profiles_path)
    if key:
        for profile_guid in enum_subkeys(key):
            sub = open_key_safe(key, profile_guid)
            if not sub:
                continue
            vals = {n: v for n, v, _ in enum_values(sub)}
            name   = vals.get("ProfileName", "")
            cat    = {0: "Public", 1: "Private", 2: "Domain"}.get(vals.get("Category", -1), "Unknown")
            # DateCreated / DateLastConnected are 16-byte binary (year, month, dow, day, h, m, s, ms)
            def parse_net_date(b: bytes) -> str:
                try:
                    y, mo, _, d, h, mi, s, _ = struct.unpack_from("<8H", b)
                    return f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d} UTC"
                except Exception:
                    return "N/A"
            first = parse_net_date(vals["DateCreated"])        if "DateCreated"        in vals and isinstance(vals["DateCreated"],        bytes) else "N/A"
            last  = parse_net_date(vals["DateLastConnected"])  if "DateLastConnected"  in vals and isinstance(vals["DateLastConnected"],  bytes) else "N/A"
            results.append(row("Network History", f"HKLM\\{profiles_path}",
                               str(name), cat, last, f"FirstSeen={first}"))
            winreg.CloseKey(sub)
        winreg.CloseKey(key)
    if not results:
        results.append(row("Network History", profiles_path, "INFO", "No network history found"))
    return results


def collect_timezone() -> list[dict]:
    results = []
    path = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("TimeZone", path, "ERROR", "Key not found")]
    for name, value, _ in enum_values(key):
        if isinstance(value, int) or isinstance(value, str):
            results.append(row("TimeZone", f"HKLM\\{path}", name, str(value)))
    winreg.CloseKey(key)
    return results


def collect_autoruns() -> list[dict]:
    results = []
    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "HKCU Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO"),
    ]
    for hive, path, label in locations:
        key = open_key_safe(hive, path)
        if not key:
            continue
        for name, value, _ in enum_values(key):
            results.append(row("Autoruns", f"{label}\\{path}", name, str(value)))
        winreg.CloseKey(key)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM  (live HKLM — no admin required)
# ─────────────────────────────────────────────────────────────────────────────

def collect_usb_devices() -> list[dict]:
    results = []
    path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("USB Devices", path, "INFO", "No USB storage history found")]
    for device_class in enum_subkeys(key):
        class_key = open_key_safe(key, device_class)
        if not class_key:
            continue
        for serial in enum_subkeys(class_key):
            serial_key = open_key_safe(class_key, serial)
            if not serial_key:
                continue
            vals = {n: v for n, v, _ in enum_values(serial_key)}
            friendly = vals.get("FriendlyName", "")
            mfg      = vals.get("Mfg",          "")
            results.append(row("USB Devices", f"HKLM\\{path}",
                               str(friendly), str(serial),
                               notes=f"Class={device_class} Mfg={mfg}"))
            winreg.CloseKey(serial_key)
        winreg.CloseKey(class_key)
    winreg.CloseKey(key)
    return results or [row("USB Devices", path, "INFO", "No USB storage history found")]


def collect_network_interfaces() -> list[dict]:
    results = []
    path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("Network Interfaces", path, "ERROR", "Key not found")]
    for guid in enum_subkeys(key):
        sub = open_key_safe(key, guid)
        if not sub:
            continue
        vals = {n: v for n, v, _ in enum_values(sub)}
        ip       = vals.get("DhcpIPAddress",      vals.get("IPAddress",      ""))
        subnet   = vals.get("DhcpSubnetMask",     vals.get("SubnetMask",     ""))
        gateway  = vals.get("DhcpDefaultGateway", vals.get("DefaultGateway", ""))
        dns      = vals.get("DhcpNameServer",     vals.get("NameServer",     ""))
        ip_str   = ip if isinstance(ip, str) else (ip[0] if ip else "")
        results.append(row("Network Interfaces", f"HKLM\\{path}", guid, str(ip_str),
                           notes=f"Subnet={subnet} GW={gateway} DNS={dns}"))
        winreg.CloseKey(sub)
    winreg.CloseKey(key)
    return results


def collect_shares() -> list[dict]:
    results = []
    path = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("Shares", path, "INFO", "No shares found or access denied")]
    for name, value, _ in enum_values(key):
        results.append(row("Shares", f"HKLM\\{path}", name,
                           str(value) if isinstance(value, str) else repr(value)))
    winreg.CloseKey(key)
    return results or [row("Shares", path, "INFO", "No shares configured")]


def collect_last_shutdown() -> list[dict]:
    results = []
    path = r"SYSTEM\CurrentControlSet\Control\Windows"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("Last Shutdown", path, "ERROR", "Key not found")]
    try:
        val, _ = winreg.QueryValueEx(key, "ShutdownTime")
        if isinstance(val, bytes) and len(val) >= 8:
            ft = struct.unpack_from("<Q", val, 0)[0]
            ts = filetime_to_str(ft)
        else:
            ts = "N/A"
        results.append(row("Last Shutdown", f"HKLM\\{path}", "ShutdownTime", ts, ts))
    except Exception as e:
        results.append(row("Last Shutdown", path, "ERROR", str(e)))
    winreg.CloseKey(key)
    return results


def collect_services() -> list[dict]:
    results = []
    path = r"SYSTEM\CurrentControlSet\Services"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("Services", path, "ERROR", "Key not found")]
    start_map = {0: "Boot", 1: "System", 2: "Auto", 3: "Manual", 4: "Disabled"}
    for name in enum_subkeys(key):
        sub = open_key_safe(key, name)
        if not sub:
            continue
        vals = {n: v for n, v, _ in enum_values(sub)}
        img   = vals.get("ImagePath", "")
        start = start_map.get(vals.get("Start", -1), "Unknown")
        desc  = vals.get("Description", "")
        results.append(row("Services", f"HKLM\\{path}", name, str(img),
                           notes=f"Start={start} Desc={str(desc)[:100]}"))
        winreg.CloseKey(sub)
    winreg.CloseKey(key)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# SAM  (requires admin)
# ─────────────────────────────────────────────────────────────────────────────

def collect_local_users() -> list[dict]:
    results = []
    path = r"SAM\SAM\Domains\Account\Users\Names"
    key = open_key_safe(winreg.HKEY_LOCAL_MACHINE, path)
    if not key:
        return [row("Local Users", path, "INFO",
                    "Access denied — run as Administrator to collect SAM data")]
    for username in enum_subkeys(key):
        results.append(row("Local Users", f"HKLM\\{path}", username, "See SAM hive"))
    winreg.CloseKey(key)
    return results or [row("Local Users", path, "INFO", "No local accounts found")]


# ─────────────────────────────────────────────────────────────────────────────
# OFFLINE HIVE  (python-registry)
# ─────────────────────────────────────────────────────────────────────────────

def collect_shimcache_offline(system_hive: str) -> list[dict]:
    results = []
    if not REGISTRY_LIB:
        return [row("ShimCache", system_hive, "SKIP", "python-registry not installed")]
    try:
        reg  = Registry.Registry(system_hive)
        base = reg.open("ControlSet001\\Control\\Session Manager\\AppCompatCache")
        raw  = base.value("AppCompatCache").raw_data()
        sig  = struct.unpack_from("<I", raw, 0)[0]
        results.append(row("ShimCache", system_hive, "AppCompatCache",
                           f"{len(raw)} bytes raw (sig=0x{sig:08X})",
                           notes="Full parsing requires dedicated shimcache parser (regipy/appcompatprocessor)"))
    except Exception as e:
        results.append(row("ShimCache", system_hive, "ERROR", str(e)))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

FIELDNAMES = ["Artifact", "Source", "Name", "Value", "Timestamp", "Notes"]


def write_csv(rows: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

COLLECTORS = [
    # (label, function, category)
    ("UserAssist",         collect_userassist,       "NTUSER.DAT"),
    ("RecentDocs",         collect_recent_docs,      "NTUSER.DAT"),
    ("TypedPaths",         collect_typed_paths,      "NTUSER.DAT"),
    ("OpenSaveMRU",        collect_opensave_mru,     "NTUSER.DAT"),
    ("LastVisitedMRU",     collect_lastvisited_mru,  "NTUSER.DAT"),
    ("RunMRU",             collect_run_mru,          "NTUSER.DAT"),
    ("SearchHistory",      collect_search_history,   "NTUSER.DAT"),
    ("MappedDrives",       collect_mapped_drives,    "NTUSER.DAT"),
    ("PuTTY Sessions",     collect_putty_sessions,   "NTUSER.DAT"),
    ("TypedURLs",          collect_typed_urls,       "NTUSER.DAT"),
    ("OS Info",            collect_os_info,          "SOFTWARE"),
    ("Installed Software", collect_installed_software, "SOFTWARE"),
    ("Network History",    collect_network_history,  "SOFTWARE"),
    ("TimeZone",           collect_timezone,         "SYSTEM"),
    ("Autoruns",           collect_autoruns,         "SOFTWARE/NTUSER"),
    ("USB Devices",        collect_usb_devices,      "SYSTEM"),
    ("Network Interfaces", collect_network_interfaces, "SYSTEM"),
    ("Shares",             collect_shares,           "SYSTEM"),
    ("Last Shutdown",      collect_last_shutdown,    "SYSTEM"),
    ("Services",           collect_services,         "SYSTEM"),
    ("Local Users",        collect_local_users,      "SAM"),
]


def main():
    parser = argparse.ArgumentParser(
        description="DFIR Windows Registry Reporter v" + SCRIPT_VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--live",     action="store_true", default=True,
                        help="Parse live registry (default, admin not required for most keys)")
    parser.add_argument("--hive-dir", default=None,
                        help="Directory containing offline hive files (SYSTEM, NTUSER.DAT, etc.)")
    parser.add_argument("-o", "--output", default="registry_report",
                        help="Output directory (default: registry_report/)")
    args = parser.parse_args()

    print(BANNER)
    print(f"[*] DFIR Windows Registry Reporter  v{SCRIPT_VERSION}")
    print(f"[*] Output Dir  : {os.path.abspath(args.output)}")
    print(f"[*] Mode        : {'Live registry' if args.live else ''}"
          f"{'  +  Offline hives: ' + args.hive_dir if args.hive_dir else ''}")
    print()

    all_results = []
    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Live collectors ───────────────────────────────────────────────────────
    prev_cat = ""
    for label, fn, cat in COLLECTORS:
        if cat != prev_cat:
            print(f"  [{cat}]")
            prev_cat = cat
        try:
            rows = fn()
        except Exception as e:
            rows = [row(label, "ERROR", str(e), "")]
        all_results.extend(rows)
        # Per-artifact CSV
        safe_label = label.replace(" ", "_")
        out_path   = os.path.join(args.output, f"{safe_label}_{timestamp}.csv")
        write_csv(rows, out_path)
        print(f"    [+] {label:<25}  {len(rows):>5} entries  →  {os.path.basename(out_path)}")

    # ── Offline hive collectors ───────────────────────────────────────────────
    if args.hive_dir:
        print(f"\n  [Offline Hives — {args.hive_dir}]")
        system_hive = os.path.join(args.hive_dir, "SYSTEM")
        if os.path.isfile(system_hive):
            rows = collect_shimcache_offline(system_hive)
            all_results.extend(rows)
            safe_label = "ShimCache"
            out_path   = os.path.join(args.output, f"{safe_label}_{timestamp}.csv")
            write_csv(rows, out_path)
            print(f"    [+] {'ShimCache':<25}  {len(rows):>5} entries  →  {os.path.basename(out_path)}")
        else:
            print(f"    [!] SYSTEM hive not found at {system_hive} — skipping ShimCache")

    # ── Master combined CSV ───────────────────────────────────────────────────
    master_path = os.path.join(args.output, f"_FULL_REPORT_{timestamp}.csv")
    write_csv(all_results, master_path)

    print()
    print(f"[+] Master report   : {master_path}")
    print(f"[*] Total entries   : {len(all_results)} across {len(COLLECTORS)} artifact types")
    print(f"[*] Output folder   : {os.path.abspath(args.output)}")
    print()


if __name__ == "__main__":
    main()