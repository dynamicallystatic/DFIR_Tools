#!/usr/bin/env bash
# =============================================================================
# DFIR Linux Collector
# =============================================================================
# Digital Forensics & Incident Response - Linux Evidence Collection Script
#
# Usage:
#   sudo bash dfir_linux_collector.sh [MODE] [OPTIONS]
#
# Modes:
#   --triage      Quick collection of key forensic artifacts (default)
#   --home        Home directory + extended forensic artifacts
#   --full        Full forensic image of the root filesystem (use with care)
#
# Options:
#   -o, --output  Output directory (default: ./DFIR_<hostname>_<timestamp>)
#   -h, --help    Show this help message
#
# Examples:
#   sudo bash dfir_linux_collector.sh --triage
#   sudo bash dfir_linux_collector.sh --home -o /mnt/usb/evidence
#   sudo bash dfir_linux_collector.sh --full -o /mnt/external/case001
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
BANNER='
 _     _                   ____      _ _           _
| |   (_)_ __  _   ___  __/ ___|___ | | | ___  ___| |_ ___  _ __
| |   | | `_ \| | | \ \/ / |   / _ \| | |/ _ \/ __| __/ _ \| `__|
| |___| | | | | |_| |>  <| |__| (_) | | |  __/ (__| || (_) | |
|_____|_|_| |_|\__,_/_/\_\\____\___/|_|_|\___|\___|\__\___/|_|

           Linux Forensic Evidence Collection
'

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_VERSION="1.0.0"
HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
MODE=""
OUTPUT_DIR=""
REPORT_FILE=""
LOG_FILE=""
ERRORS=0

# Colour codes
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
log()   { echo -e "${CYAN}[*]${RESET} $*"; echo "[*] $*" >> "$LOG_FILE"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; echo "[+] $*" >> "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; echo "[!] $*" >> "$LOG_FILE"; }
err()   { echo -e "${RED}[ERROR]${RESET} $*"; echo "[ERROR] $*" >> "$LOG_FILE"; ERRORS=$((ERRORS+1)); }
banner(){ echo -e "${BOLD}${CYAN}$*${RESET}"; }

# Safe copy — logs errors but does not abort
safe_copy() {
    local src="$1" dst="$2"
    if [ -e "$src" ]; then
        mkdir -p "$dst"
        cp -a "$src" "$dst/" 2>>"$LOG_FILE" && ok "Collected: $src" \
            || { err "Failed to copy: $src"; }
    else
        warn "Not found (skipped): $src"
    fi
}

# Safe command capture (supports piped commands via bash -c)
safe_cmd() {
    local label="$1" outfile="$2"
    shift 2
    if bash -c "$*" > "$outfile" 2>>"$LOG_FILE"; then
        ok "Captured: $label"
    else
        warn "Partial/failed: $label"
    fi
}

# Recursive directory copy
safe_dir() {
    local src="$1" dst="$2"
    if [ -d "$src" ]; then
        mkdir -p "$dst"
        cp -a "$src/." "$dst/" 2>>"$LOG_FILE" && ok "Collected dir: $src" \
            || warn "Partial copy of dir: $src"
    else
        warn "Directory not found (skipped): $src"
    fi
}

# Hash a file
hash_file() {
    local f="$1"
    if [ -f "$f" ]; then
        md5sum "$f" && sha256sum "$f"
    fi
}

# Full directory copy — uses rsync if available, falls back to tar pipe
# Usage: copy_dir_full <src> <dst> [exclude_path ...]
copy_dir_full() {
    local src="$1" dst="$2"
    shift 2
    mkdir -p "$dst"
    if command -v rsync &>/dev/null; then
        local excludes=()
        for ex in "$@"; do excludes+=("--exclude=$ex"); done
        rsync -aH "${excludes[@]}" "$src" "$dst" 2>>"$LOG_FILE" \
            && ok "Copied (rsync): $src" \
            || warn "rsync of $src completed with some errors (check collection.log)."
    else
        warn "rsync not found — falling back to tar pipe for $src"
        local tar_excludes=()
        for ex in "$@"; do tar_excludes+=("--exclude=$ex"); done
        tar -cf - "${tar_excludes[@]}" -C "$src" . 2>>"$LOG_FILE" \
            | tar -xf - -C "$dst/" 2>>"$LOG_FILE" \
            && ok "Copied (tar): $src" \
            || warn "tar copy of $src completed with some errors (check collection.log)."
    fi
}


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    echo ""
    echo "Usage: sudo bash $0 [MODE] [OPTIONS]"
    echo ""
    echo "  Modes (pick one):"
    echo "    --triage    Quick triage of key forensic artifacts     [fastest]"
    echo "    --home      Home directory + extended artifact collect  [moderate]"
    echo "    --full      Full forensic copy of root filesystem       [slowest]"
    echo ""
    echo "  Options:"
    echo "    -o, --output DIR   Output directory"
    echo "    -h, --help         Show this help"
    echo ""
}

if [ "$#" -eq 0 ]; then usage; exit 1; fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --triage) MODE="triage" ;;
        --home)   MODE="home"   ;;
        --full)   MODE="full"   ;;
        -o|--output) OUTPUT_DIR="$2"; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

if [ -z "$MODE" ]; then echo "ERROR: No mode specified."; usage; exit 1; fi

# ─────────────────────────────────────────────────────────────────────────────
# ROOT CHECK
# ─────────────────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${RESET} This script must be run as root (use sudo)."
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# SETUP OUTPUT DIRECTORY
# ─────────────────────────────────────────────────────────────────────────────
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="./DFIR_${HOSTNAME_VAL}_${MODE}_${TIMESTAMP}"
fi

# Strip any trailing slash to prevent double-slash paths and broken tar archive names
OUTPUT_DIR="${OUTPUT_DIR%/}"

mkdir -p "$OUTPUT_DIR"
LOG_FILE="${OUTPUT_DIR}/collection.log"
REPORT_FILE="${OUTPUT_DIR}/_dfir_collection_report.txt"
touch "$LOG_FILE"

echo -e "$BANNER"
log "DFIR Linux Collector v${SCRIPT_VERSION}"
log "Mode       : ${MODE^^}"
log "Host       : $HOSTNAME_VAL"
log "Output Dir : $(realpath "$OUTPUT_DIR")"
log "Started    : $(date)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# MODULE: SYSTEM TRIAGE
# Collected in all modes
# ─────────────────────────────────────────────────────────────────────────────
collect_triage() {
    banner "==> [1/5] System Information"
    local sysdir="${OUTPUT_DIR}/system_info"
    mkdir -p "$sysdir"

    safe_cmd "uname"           "$sysdir/uname.txt"           uname -a
    safe_cmd "hostname"        "$sysdir/hostname.txt"         hostname -f 2>/dev/null || hostname
    safe_cmd "uptime"          "$sysdir/uptime.txt"           uptime
    safe_cmd "date"            "$sysdir/date.txt"             date
    safe_cmd "os-release"      "$sysdir/os_release.txt"       cat /etc/os-release
    safe_cmd "cpu-info"        "$sysdir/cpuinfo.txt"          cat /proc/cpuinfo
    safe_cmd "memory-info"     "$sysdir/meminfo.txt"          cat /proc/meminfo
    safe_cmd "disk-usage"      "$sysdir/df.txt"               df -h
    safe_cmd "mount-points"    "$sysdir/mounts.txt"           cat /proc/mounts
    safe_cmd "lsblk"           "$sysdir/lsblk.txt"           lsblk -o NAME,SIZE,TYPE,MOUNTPOINT

    banner "==> [2/5] Users & Authentication"
    local authdir="${OUTPUT_DIR}/users_auth"
    mkdir -p "$authdir"

    safe_copy /etc/passwd       "$authdir"
    safe_copy /etc/shadow       "$authdir"
    safe_copy /etc/group        "$authdir"
    safe_copy /etc/sudoers      "$authdir"
    [ -d /etc/sudoers.d ] && safe_dir /etc/sudoers.d "$authdir/sudoers.d"

    safe_cmd "logged-in-users"  "$authdir/who.txt"            who
    safe_cmd "w-output"         "$authdir/w.txt"              w
    safe_cmd "last-logins"      "$authdir/last.txt"           last -F -w
    safe_cmd "failed-logins"    "$authdir/lastb.txt"          lastb -F -w 2>/dev/null || warn "lastb unavailable"
    safe_cmd "id-root"          "$authdir/id_root.txt"        id root

    banner "==> [3/5] Processes & Network"
    local netdir="${OUTPUT_DIR}/processes_network"
    mkdir -p "$netdir"

    safe_cmd "ps-all"           "$netdir/ps_aux.txt"          ps aux
    safe_cmd "ps-tree"          "$netdir/ps_tree.txt"         ps auxf
    safe_cmd "open-files"       "$netdir/lsof.txt"            lsof 2>/dev/null
    safe_cmd "network-sockets"  "$netdir/ss.txt"              ss -antp
    safe_cmd "netstat"          "$netdir/netstat.txt"         netstat -antp 2>/dev/null || warn "netstat unavailable"
    safe_cmd "arp-table"        "$netdir/arp.txt"             arp -n 2>/dev/null
    safe_cmd "routing-table"    "$netdir/route.txt"           ip route
    safe_cmd "ip-addresses"     "$netdir/ip_addr.txt"         ip addr
    safe_cmd "interfaces"       "$netdir/ifconfig.txt"        ifconfig -a 2>/dev/null || ip link
    safe_cmd "firewall-rules"   "$netdir/iptables.txt"        iptables -L -n -v 2>/dev/null || warn "iptables unavailable"
    safe_cmd "dns-resolv"       "$netdir/resolv.conf.txt"     cat /etc/resolv.conf
    safe_copy /etc/hosts        "$netdir"

    banner "==> [4/5] Persistence & Scheduled Tasks"
    local persdir="${OUTPUT_DIR}/persistence"
    mkdir -p "$persdir"

    # Crontabs
    [ -d /etc/cron.d ]       && safe_dir /etc/cron.d       "$persdir/cron.d"
    [ -d /etc/cron.daily ]   && safe_dir /etc/cron.daily   "$persdir/cron.daily"
    [ -d /etc/cron.hourly ]  && safe_dir /etc/cron.hourly  "$persdir/cron.hourly"
    [ -d /etc/cron.weekly ]  && safe_dir /etc/cron.weekly  "$persdir/cron.weekly"
    [ -d /etc/cron.monthly ] && safe_dir /etc/cron.monthly "$persdir/cron.monthly"
    safe_copy /etc/crontab "$persdir"
    # User crontabs
    if [ -d /var/spool/cron ]; then
        safe_dir /var/spool/cron "$persdir/user_crontabs"
    fi
    if [ -d /var/spool/cron/crontabs ]; then
        safe_dir /var/spool/cron/crontabs "$persdir/user_crontabs"
    fi

    # Startup / init
    safe_cmd "systemctl-services" "$persdir/systemctl_list.txt" \
        systemctl list-units --type=service --all 2>/dev/null || warn "systemctl unavailable"
    safe_cmd "rc.local"        "$persdir/rc_local.txt"       cat /etc/rc.local 2>/dev/null || true
    safe_cmd "loaded-modules"  "$persdir/lsmod.txt"          lsmod
    safe_cmd "kernel-modules"  "$persdir/modinfo.txt"        ls /sys/module/

    # SSH
    local sshdir="$persdir/ssh"
    mkdir -p "$sshdir"
    safe_copy /etc/ssh/sshd_config "$sshdir"
    for homedir in /home/* /root; do
        [ -d "$homedir/.ssh" ] && safe_dir "$homedir/.ssh" "$sshdir/$(basename $homedir)_dot_ssh"
    done

    banner "==> [5/5] Logs"
    local logdir="${OUTPUT_DIR}/logs"
    mkdir -p "$logdir"

    for logfile in auth.log syslog messages secure kern.log dmesg \
                   faillog wtmp btmp lastlog dpkg.log apt/history.log \
                   audit/audit.log; do
        safe_copy "/var/log/$logfile" "$logdir"
    done
    safe_cmd "dmesg-live"   "$logdir/dmesg_live.txt"  dmesg
    safe_cmd "journalctl"   "$logdir/journal.txt"     journalctl --no-pager -n 5000 2>/dev/null || warn "journalctl unavailable"

    # /tmp contents listing
    safe_cmd "tmp-listing"  "${OUTPUT_DIR}/system_info/tmp_contents.txt" ls -laR /tmp
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE: HOME & EXTENDED ARTIFACTS
# ─────────────────────────────────────────────────────────────────────────────
collect_home() {
    collect_triage   # includes everything from triage

    banner "==> [+] Full Copy of Home Directories"
    local homecol="${OUTPUT_DIR}/home_folders"
    mkdir -p "$homecol"

    # Full copy of /home/ — all users, all files
    if [ -d /home ] && [ "$(ls -A /home 2>/dev/null)" ]; then
        log "Copying /home/ (all files and folders)..."
        copy_dir_full /home/ "$homecol/home/"
    else
        warn "/home/ is empty or not found — skipping."
    fi

    # Full copy of /root/ home directory
    if [ -d /root ]; then
        log "Copying /root/ (all files and folders)..."
        copy_dir_full /root/ "$homecol/root/"
    else
        warn "/root/ not found — skipping."
    fi

    banner "==> [+] Package & Software Inventory"
    local pkgdir="${OUTPUT_DIR}/software"
    mkdir -p "$pkgdir"
    safe_cmd "dpkg-list"  "$pkgdir/dpkg_installed.txt"  dpkg -l 2>/dev/null   || true
    safe_cmd "rpm-list"   "$pkgdir/rpm_installed.txt"   rpm -qa 2>/dev/null   || true
    safe_cmd "pip-list"   "$pkgdir/pip_installed.txt"   pip3 list 2>/dev/null  || true
    safe_cmd "snap-list"  "$pkgdir/snap_installed.txt"  snap list 2>/dev/null  || true

    # Compress home_collection into hostname_timestamp_home.tar.gz
    local home_archive="${OUTPUT_DIR}/${HOSTNAME_VAL}_${TIMESTAMP}_home.tar.gz"
    banner "==> [+] Compressing Home Folders"
    log "Creating archive: $(basename "$home_archive")"
    tar -czf "$home_archive" -C "$OUTPUT_DIR" home_folders/ 2>>"$LOG_FILE" \
        && ok "Home archive created: $home_archive" \
        || warn "Home compression had errors (check collection.log)"
    rm -rf "${OUTPUT_DIR}/home_folders"
    ok "Uncompressed home_folders removed."
    # Hash the archive
    local h_md5 h_sha256
    h_md5=$(md5sum "$home_archive" | awk '{print $1}')
    h_sha256=$(sha256sum "$home_archive" | awk '{print $1}')
    echo "  MD5    : $h_md5" && echo "  MD5    : $h_md5" >> "$LOG_FILE"
    echo "  SHA256 : $h_sha256" && echo "  SHA256 : $h_sha256" >> "$LOG_FILE"
    printf 'MD5    %s  %s\nSHA256 %s  %s\n' \
        "$h_md5" "$(basename "$home_archive")" \
        "$h_sha256" "$(basename "$home_archive")" \
        > "${home_archive}.hashes.txt"
    ok "Hash sidecar: ${home_archive}.hashes.txt"
}


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: FULL ROOT COPY
# ─────────────────────────────────────────────────────────────────────────────
collect_full() {
    collect_home   # everything from home mode first

    banner "==> [FULL] Forensic Copy of Root Filesystem"
    warn "Full mode: this may take a very long time and requires significant disk space."
    warn "Excluded: /proc /sys /dev /run /tmp ${OUTPUT_DIR}"

    local fulldir="${OUTPUT_DIR}/root_filesystem"
    mkdir -p "$fulldir"

    log "Copying full root filesystem..."
    copy_dir_full / "$fulldir/" \
        "/proc" "/sys" "/dev" "/run" "/tmp" "$(realpath "$OUTPUT_DIR")"

    # Compress root_filesystem into hostname_timestamp_full.tar.gz
    local full_archive="${OUTPUT_DIR}/${HOSTNAME_VAL}_${TIMESTAMP}_full.tar.gz"
    banner "==> [FULL] Compressing Root Filesystem Copy"
    log "Creating archive: $(basename "$full_archive") (this may take a while)"
    tar -czf "$full_archive" -C "$OUTPUT_DIR" root_filesystem/ 2>>"$LOG_FILE" \
        && ok "Full archive created: $full_archive" \
        || warn "Full compression had errors (check collection.log)"
    rm -rf "${OUTPUT_DIR}/root_filesystem"
    ok "Uncompressed root_filesystem removed."
    # Hash the archive
    local f_md5 f_sha256
    f_md5=$(md5sum "$full_archive" | awk '{print $1}')
    f_sha256=$(sha256sum "$full_archive" | awk '{print $1}')
    echo "  MD5    : $f_md5" && echo "  MD5    : $f_md5" >> "$LOG_FILE"
    echo "  SHA256 : $f_sha256" && echo "  SHA256 : $f_sha256" >> "$LOG_FILE"
    printf 'MD5    %s  %s\nSHA256 %s  %s\n' \
        "$f_md5" "$(basename "$full_archive")" \
        "$f_sha256" "$(basename "$full_archive")" \
        > "${full_archive}.hashes.txt"
    ok "Hash sidecar: ${full_archive}.hashes.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
write_report() {
    local end_time file_count dir_size
    end_time=$(date)
    file_count=$(find "$OUTPUT_DIR" -type f | wc -l)
    dir_size=$(du -sh "$OUTPUT_DIR" | cut -f1)

    {
        echo "======================================================================"
        echo "  DFIR LINUX COLLECTOR - COLLECTION REPORT"
        echo "  Version : $SCRIPT_VERSION"
        echo "======================================================================"
        echo ""
        echo "  Host           : $HOSTNAME_VAL"
        echo "  Kernel         : $(uname -r)"
        echo "  Mode           : ${MODE^^}"
        echo "  Started        : $(date -r "$LOG_FILE" 2>/dev/null || echo "N/A")"
        echo "  Completed      : $end_time"
        echo "  Output Dir     : $(realpath "$OUTPUT_DIR")"
        echo "  Files Collected: $file_count"
        echo "  Total Size     : $dir_size"
        echo "  Errors/Warnings: $ERRORS"
        echo ""
        echo "----------------------------------------------------------------------"
        echo "  Collected Sections:"
        echo ""
        find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d | sort | while read -r d; do
            local count
            count=$(find "$d" -type f | wc -l)
            printf "  %-45s  %5s files\n" "$(basename "$d")" "$count"
        done
        echo ""
        echo "----------------------------------------------------------------------"
        echo "  File Hash Manifest (SHA256):"
        echo ""
        find "$OUTPUT_DIR" -type f ! -name "_dfir_collection_report.txt" \
            -exec sha256sum {} \; 2>/dev/null | sed "s|$(realpath "$OUTPUT_DIR")/||"
        echo ""
        echo "======================================================================"
    } > "$REPORT_FILE"

    ok "Forensic report written: $REPORT_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
case "$MODE" in
    triage) collect_triage ;;
    home)   collect_home   ;;
    full)   collect_full   ;;
esac

echo ""
log "Finalising — generating report and hash manifest..."
write_report

echo ""
echo -e "${BOLD}${GREEN}Collection complete!${RESET}"
echo -e "  Output : $(realpath "$OUTPUT_DIR" 2>/dev/null || echo "$OUTPUT_DIR")"
echo -e "  Report : $REPORT_FILE"
echo -e "  Errors : $ERRORS"
echo ""
