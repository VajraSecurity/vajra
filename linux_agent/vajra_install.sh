#!/bin/bash

# Vajra installer - single-file combined edition
# Author: Arjun Sable, IEOR, IIT Bombay
#
# Combines what used to be four files (vajra_install.sh dispatcher +
# vajra_common.sh shared library + vajra_install_full.sh + vajra_install_
# reduced.sh) into one script. Behaviour is unchanged from that split
# version - same root-detection, same full vs reduced logic, same host
# identifier caching. Uninstall (-uninstall) needs no token:
#
#   sudo ./vajra_install.sh [-install|-uninstall]   -> full mode
#        ./vajra_install.sh [-install|-uninstall]   -> reduced mode
#
# Everything below is organised in three sections:
#   1. Shared library functions (was vajra_common.sh)
#   2. Full-mode-only functions, each suffixed _full
#   3. Reduced-mode-only functions, each suffixed _reduced
# followed by a small dispatcher (was vajra_install.sh) and the main block.

start_time=$(date +%s.%N)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Populated by check_permissions_full / check_permissions_reduced, whichever
# runs (decided by the dispatcher at the bottom based on $EUID).
RUNNING_AS_ROOT=""
ALLOW_ADMIN_ACCESS=""
TARGET_USER=""
TARGET_HOME=""

# ===========================================================================
# SECTION 1 - SHARED LIBRARY (was vajra_common.sh)
# ===========================================================================

scriptVersion="3.2.0.0"

# Create log file (shared across whichever mode script runs)
LogFile="vajra_install_log.txt"
if [ -f "$LogFile" ]; then
    rm -f "$LogFile"
fi

logError() {
    local level="$1"
    local message="$2"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LogFile"
}

# ---------------------------------------------------------------------------
# Linux version/architecture check - identical for both modes
# ---------------------------------------------------------------------------
# The server address, certificate and enrollment secret are not in the repository folder: the
# package downloaded from the Vajra console (linux_agent.zip) has them. Check before anything on
# this machine is touched.
check_package_files() {
    local f missing=0
    for f in common/cert.pem common/enrollment_secret common/osqueryd common/extension.ext; do
        [ -f "$f" ] || { echo -e "\e[31m [-] Missing $f\e[0m"; missing=1; }
    done
    [ "$missing" = 0 ] && return 0
    echo -e "\e[31m [-] This folder is not a complete agent package. Download linux_agent.zip from the Vajra\e[0m"
    echo -e "\e[31m     web console (it contains your server's certificate and enrollment secret), unzip it and\e[0m"
    echo -e "\e[31m     run the installer from that folder. common/extension.ext is the Vajra extension build.\e[0m"
    logError "ERROR" "Agent package incomplete (see messages above). Nothing was changed."
    exit 1
}

check_linux_version() {
    supported_kernel_version="4.18"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        linux_flavor=$NAME
    else
        linux_flavor=$(uname -s)
    fi

    kernel_version=$(uname -r)

    if [ "$(uname -m)" == "x86_64" ]; then
        architecture="64"
    else
        architecture="32"
    fi

    logError "INFO" "Linux flavour $linux_flavor, $kernel_version and architecture $architecture bits"

    if [ "$(printf '%s\n' "$supported_kernel_version" "$kernel_version" | sort -V | head -n1)" == "$supported_kernel_version" ]; then
        echo -e "\e[33m [+] Vajra client supports the current Linux flavour $linux_flavor, kernel version $kernel_version and $architecture bits.\e[0m"
        echo -e "\e[33m [+] Continuing the installation process.\e[0m"
        logError "INFO" "Linux flavour $linux_flavor, $kernel_version and architecture $architecture bits - supported."
    else
        echo -e "\e[33m [-] Vajra client does not support current Linux kernel version.\e[0m"
        echo -e "\e[33m [-] Vajra client currently supports Linux kernel version above $supported_kernel_version.\e[0m"
        echo -e "\e[31m [-] Aborting the installation process.\e[0m"
        logError "ERROR" "Unsupported kernel: Linux flavour $linux_flavor, $kernel_version, architecture $architecture bits"
        read -n 1 -s -r -p "Press any key to exit ..."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Cleanup any stray/orphaned Vajra processes not tracked by systemd
# ---------------------------------------------------------------------------
cleanup_stale_processes() {
    echo -e "\e[33m [+] Cleaning up any stale Vajra/osquery processes...\e[0m"
    # vajra_linux_extension.ext is no longer installed (nothing loaded it);
    # still listed so a reinstall over an old host stops any stray copy.
    for proc in osqueryd vajra.sh extension.ext vajra_linux_extension.ext; do
        pids=$(pgrep -f "$proc" 2>/dev/null)
        if [ -n "$pids" ]; then
            echo -e "\e[33m [+] Found stale process(es) for $proc, terminating...\e[0m"
            kill -9 $pids 2>/dev/null
            logError "INFO" "Killed stale process(es) for $proc: $pids"
        fi
    done
}

# Resolve which user reduced-mode installs/uninstalls act on. Full mode never
# calls this; reduced mode always does, whether run directly by that user or
# by root on their behalf via SUDO_USER.
resolve_target_user() {
    if [ -n "$TARGET_USER" ]; then
        return
    fi
    if [ "$RUNNING_AS_ROOT" = true ]; then
        if [ -z "$SUDO_USER" ] || [ "$SUDO_USER" = "root" ]; then
            echo -e "\e[31m [-] ERROR: Reduced mode requires a non-root SUDO_USER context. Exiting...\e[0m"
            logError "ERROR" "No valid SUDO_USER for reduced mode under root."
            exit 1
        fi
        TARGET_USER="$SUDO_USER"
        TARGET_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        TARGET_USER="$(whoami)"
        TARGET_HOME="$HOME"
    fi
}

# ---------------------------------------------------------------------------
# Checks whether Vajra is actually installed in the CURRENT mode
# (INSTALL_MODE, set by whichever install_osquery_*/uninstall_osquery_*
# entry point is running). Used so uninstall can stop early when there's
# nothing to remove.
# ---------------------------------------------------------------------------
is_vajra_installed() {
    if [ "$INSTALL_MODE" = "full" ]; then
        # Check installed *presence*, not current run state. `is-active`
        # alone reports "not installed" for a stopped/failed/crash-looped
        # service even though the files are still on disk, which would block
        # a legitimate uninstall on exactly the machines that need it most.
        # Match against the actual artifacts do_uninstall_steps_full removes.
        # (osqueryd and /etc/osquery are not checked: another osquery install owns them.)
        systemctl list-unit-files vajra.service >/dev/null 2>&1 \
            || [ -f /etc/systemd/system/vajra.service ]
    else
        resolve_target_user
        local uid_of_u
        uid_of_u=$(id -u "$TARGET_USER" 2>/dev/null)
        [ -n "$uid_of_u" ] || return 1
        # Same presence-over-active-state reasoning as full mode above -
        # match the artifacts do_uninstall_steps_reduced removes.
        [ -f "$TARGET_HOME/.config/systemd/user/vajra.service" ] \
            || [ -d "$TARGET_HOME/.local/share/vajra" ]
    fi
}


# ---------------------------------------------------------------------------
# File copy helper - shared loop; sources/destinations arrays + INSTALL_MODE
# (fixed per script) + RUNNING_AS_ROOT/TARGET_USER (set by each mode script)
# decide how each copy actually happens. On a missing source it calls
# cleanup_partial_install_full or _reduced, chosen by INSTALL_MODE.
# ---------------------------------------------------------------------------
_copy_file_list() {
    for ((i = 0; i < ${#sources[@]}; i++)); do
        source="${sources[$i]}"
        destination="${destinations[$i]}"

        if [ ! -f "$source" ]; then
            echo -e "\e[31m [-] ERROR: Source file $source not found.\e[0m"
            echo -e "\e[31m [-] Aborting the installation process\e[0m"
            echo -e "\e[33m [-] Cleaning up the installation files\e[0m"
            logError "ERROR" "Source file $source not found. Aborting."
            if [ "$INSTALL_MODE" = "full" ]; then
                cleanup_partial_install_full
            else
                cleanup_partial_install_reduced
            fi
            exit 1
        fi

        # If a previous run of this script hardened this file (chattr +i via
        # harden_vajra_config), it can't be overwritten until unlocked - clear
        # it here so re-installs/updates aren't silently blocked. Harmless if
        # the file was never hardened (chattr just no-ops with an error we
        # discard) or chattr isn't available on this filesystem.
        #
        # destination is sometimes a directory (trailing slash, e.g.
        # "/etc/osquery/") rather than the full target file path - resolve the
        # actual file path first, otherwise `[ -f "$destination" ]` is always
        # false for a directory and the stale immutable flag on the real file
        # underneath it never gets cleared, so the cp below fails silently.
        local dest_file="$destination"
        if [ -d "$destination" ]; then
            dest_file="${destination%/}/$(basename "$source")"
        fi
        if [ -f "$dest_file" ] && command -v chattr >/dev/null 2>&1; then
            sudo chattr -i "$dest_file" 2>/dev/null || true
        fi

        if [ "$INSTALL_MODE" = "full" ]; then
            sudo cp "$source" "$destination"
        elif [ "$RUNNING_AS_ROOT" = true ]; then
            sudo -u "$TARGET_USER" cp "$source" "$destination"
        else
            cp "$source" "$destination"
        fi

        if [ $? -eq 0 ]; then
            echo -e "\e[33m [+] Copied $source to $destination successfully.\e[0m"
            logError "INFO" "Copied $source to $destination successfully."
        else
            echo -e "\e[31m [-] ERROR: Failed to copy $source to $destination.\e[0m"
            logError "ERROR" "Failed to copy $source to $destination."
        fi
    done
}

# ---------------------------------------------------------------------------
# Host identifier - single source of truth for every mode/install
# ---------------------------------------------------------------------------
# Host identifier - single source of truth for every mode/install
# ---------------------------------------------------------------------------
# Reading /sys/class/dmi/id/product_uuid directly requires root - fine for
# full mode, but reduced mode (no-root) can't do this on its own. To keep
# BOTH modes reporting the exact same identifier for a given machine (so a
# reinstall in either mode maps to the same dashboard node), full mode
# caches the UUID it reads into a world-readable file the first time it
# installs (see cache_host_identifier(), called from vajra_install_full.sh).
# Reduced mode then just reads that cache - no root, no sudo, no dmidecode
# needed on its side at all.
HOST_ID_CACHE_FILE="/etc/vajra/host_id"

get_host_identifier() {
    # 1. Prefer the cached value, if one exists - this is what makes reduced
    #    mode able to resolve the SAME id a full-mode install on this box
    #    already established, without needing root itself.
    if [ -r "$HOST_ID_CACHE_FILE" ]; then
        local cached
        cached=$(tr -d '[:space:]' < "$HOST_ID_CACHE_FILE" 2>/dev/null)
        if [ -n "$cached" ]; then
            echo "$cached" | tr 'A-F' 'a-f'
            return
        fi
    fi

    # 2. No cache yet - e.g. this is the very first install on this machine
    #    and it happens to be a reduced-mode (no-root) one. Fall back to a
    #    direct read attempt (works if already root), then sudo, then
    #    dmidecode. In the common no-root case none of these will succeed
    #    either (by design - no privilege escalation happens here), and this
    #    returns empty; callers already handle an empty result.
    local uuid
    uuid=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null)

    if [ -z "$uuid" ] && command -v sudo &>/dev/null; then
        uuid=$(sudo cat /sys/class/dmi/id/product_uuid 2>/dev/null)
    fi

    if [ -z "$uuid" ] && command -v dmidecode &>/dev/null; then
        uuid=$(sudo dmidecode -s system-uuid 2>/dev/null)
    fi

    echo "$uuid" | tr 'A-F' 'a-f'
}

# Called ONLY from full mode (the one path that reliably has root and can
# therefore both read the real DMI UUID and write to /etc/vajra/). Writes
# the UUID to a world-readable cache so any later reduced-mode install/read
# on this same machine sees the identical value, with no cache of its own.
cache_host_identifier() {
    local host_id="$1"
    if [ -z "$host_id" ]; then
        logError "ERROR" "cache_host_identifier called with empty host_id - not writing cache."
        return 1
    fi

    sudo mkdir -p /etc/vajra
    echo "$host_id" | sudo tee "$HOST_ID_CACHE_FILE" >/dev/null
    sudo chmod 644 "$HOST_ID_CACHE_FILE"

    if [ "$(cat "$HOST_ID_CACHE_FILE" 2>/dev/null)" = "$host_id" ]; then
        echo -e "\e[32m [+] Cached host identifier to $HOST_ID_CACHE_FILE (world-readable) for reduced mode to reuse.\e[0m"
        logError "INFO" "Cached host identifier ($host_id) to $HOST_ID_CACHE_FILE."
    else
        echo -e "\e[31m [-] WARNING: Failed to write host identifier cache to $HOST_ID_CACHE_FILE.\e[0m"
        logError "ERROR" "Failed to write $HOST_ID_CACHE_FILE."
    fi
}

# Pin the host identifier directly into osquery.flags - the one file BOTH
# modes reliably read via --flagfile=..., regardless of whether vajra.sh
# wraps osqueryd or something else invokes it directly. Strips any
# pre-existing --host_identifier= / --specified_identifier= lines so there's
# no ambiguity about which line gflags honors, then appends our own.
pin_host_identifier() {
    local flags_file="$1"
    local host_id
    host_id=$(get_host_identifier)

    if [ -z "$host_id" ]; then
        echo -e "\e[31m [-] WARNING: Could not determine host identifier from /sys/class/dmi/id/product_uuid - $flags_file left unmodified.\e[0m"
        logError "ERROR" "Could not read DMI product_uuid - not patching $flags_file."
        return 1
    fi

    if [ ! -f "$flags_file" ]; then
        echo -e "\e[31m [-] ERROR: $flags_file not found - cannot pin host identifier.\e[0m"
        logError "ERROR" "$flags_file missing when attempting to pin host identifier."
        return 1
    fi

    local sed_status tee_status
    if [ "$INSTALL_MODE" = "full" ]; then
        # A stale immutable flag (chattr +i, from a previous harden_vajra_config
        # run) silently breaks both commands below with "Operation not
        # permitted" - clear it first so a re-install actually re-pins instead
        # of leaving the old identifier in place under a false success message.
        command -v chattr >/dev/null 2>&1 && sudo chattr -i "$flags_file" 2>/dev/null
        sudo sed -i '/^--host_identifier=/d; /^--specified_identifier=/d' "$flags_file"
        sed_status=$?
        printf '%s\n%s\n' "--host_identifier=specified" "--specified_identifier=$host_id" | sudo tee -a "$flags_file" > /dev/null
        tee_status=$?
    elif [ "$RUNNING_AS_ROOT" = true ]; then
        sudo -u "$TARGET_USER" sed -i '/^--host_identifier=/d; /^--specified_identifier=/d' "$flags_file"
        sed_status=$?
        printf '%s\n%s\n' "--host_identifier=specified" "--specified_identifier=$host_id" | sudo -u "$TARGET_USER" tee -a "$flags_file" > /dev/null
        tee_status=$?
    else
        sed -i '/^--host_identifier=/d; /^--specified_identifier=/d' "$flags_file"
        sed_status=$?
        printf '%s\n%s\n' "--host_identifier=specified" "--specified_identifier=$host_id" >> "$flags_file"
        tee_status=$?
    fi

    if [ "$sed_status" -eq 0 ] && [ "$tee_status" -eq 0 ]; then
        echo -e "\e[32m [+] Pinned host identifier to DMI product_uuid ($host_id) in $flags_file.\e[0m"
        logError "INFO" "Pinned $flags_file to host_identifier=specified, specified_identifier=$host_id."
    else
        echo -e "\e[31m [-] ERROR: Failed to pin host identifier in $flags_file (sed_status=$sed_status tee_status=$tee_status).\e[0m"
        logError "ERROR" "Failed to pin host identifier in $flags_file (sed_status=$sed_status tee_status=$tee_status)."
        return 1
    fi
}

# ===========================================================================
# SECTION 2 - FULL MODE ONLY (was vajra_install_full.sh)
# ===========================================================================


# ---------------------------------------------------------------------------
# Root check - full mode has no non-root path, unlike the old combined script
# ---------------------------------------------------------------------------
check_permissions_full() {
    if [ "$EUID" -eq 0 ]; then
        RUNNING_AS_ROOT=true
        echo -e "\e[32m [+] SUCCESS: Script running with root privileges.\e[0m"
        logError "INFO" "Script running with root privileges (full mode)."
    else
        echo -e "\e[31m [-] ERROR: Full mode requires root/sudo privileges.\e[0m"
        echo -e "\e[31m [-] Re-run with sudo, or use vajra_install_reduced.sh for a no-root install.\e[0m"
        logError "ERROR" "Full-mode script invoked without root."
        read -n 1 -s -r -p "Press any key to exit ..."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Service-already-running detection. Checks full mode's own service, AND
# scans every user's home for a still-running reduced-mode instance - since
# /sys/class/dmi/id/product_uuid is shared across modes on the same box, letting both run
# simultaneously causes the two to visibly collide on the dashboard.
# ---------------------------------------------------------------------------
check_vajra_service_not_running_full() {
    echo -e "\e[33m [+] Checking for existing Vajra installations...\e[0m"

    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet vajra.service 2>/dev/null; then
            echo -e "\e[31m [-] ERROR: Vajra (full mode) service is already running. Exiting...\e[0m"
            logError "ERROR" "Full-mode vajra.service already active."
            read -n 1 -s -r -p "Press any key to exit ..."
            exit 1
        fi
    fi

    for home_dir in /home/*; do
        [ -d "$home_dir" ] || continue
        u=$(basename "$home_dir")
        unit_path="$home_dir/.config/systemd/user/vajra.service"
        if [ -f "$unit_path" ]; then
            uid_of_u=$(id -u "$u" 2>/dev/null)
            if [ -n "$uid_of_u" ] && sudo -u "$u" XDG_RUNTIME_DIR="/run/user/$uid_of_u" systemctl --user is-active --quiet vajra.service 2>/dev/null; then
                echo -e "\e[31m [-] ERROR: A reduced-mode Vajra service is already running for user $u. Exiting...\e[0m"
                echo -e "\e[31m [-] Running both modes on the same machine causes conflicting node identities. Uninstall that instance first.\e[0m"
                logError "ERROR" "Reduced-mode vajra.service active for user $u - refusing full-mode install."
                read -n 1 -s -r -p "Press any key to exit ..."
                exit 1
            fi
        fi
    done

    echo -e "\e[32m [+] No existing Vajra service detected. Proceeding with installation...\e[0m"
    logError "INFO" "No existing Vajra service detected."
}

# ---------------------------------------------------------------------------
# Access level - full mode runs with administrator access. There is no remote
# terminal/shell feature in this agent.
# ---------------------------------------------------------------------------
prompt_access_level() {
    ALLOW_ADMIN_ACCESS=true
    logError "INFO" "Full mode: ALLOW_ADMIN_ACCESS=$ALLOW_ADMIN_ACCESS"
}

# ---------------------------------------------------------------------------
# Directory creation
# ---------------------------------------------------------------------------
create_directories_full() {
    echo -e "\e[33m [+] Creating installation directories \e[0m"
    sudo mkdir -p /etc/osquery/
    logError "INFO" "Created install directories (full mode)."
}

# ---------------------------------------------------------------------------
# File copy
# ---------------------------------------------------------------------------
# Remember whether osquery was on this machine before Vajra. If it was, keep a copy of its
# binary and /etc/osquery so uninstall can put them back instead of deleting them.
# /etc/vajra/osqueryd_origin holds "preexisting" or "vajra" and survives uninstall steps below.
record_osquery_origin_full() {
    sudo mkdir -p /etc/vajra
    [ -f /etc/vajra/osqueryd_origin ] && return 0      # re-install: keep the first answer
    if [ -f /usr/bin/osqueryd ]; then
        sudo cp -p /usr/bin/osqueryd /usr/bin/osqueryd.vajra-orig
        if [ -d /etc/osquery ] && [ -n "$(ls -A /etc/osquery 2>/dev/null)" ]; then
            sudo rm -rf /etc/osquery.vajra-orig
            sudo cp -a /etc/osquery /etc/osquery.vajra-orig
        fi
        echo preexisting | sudo tee /etc/vajra/osqueryd_origin >/dev/null
        echo -e "\e[33m [i] osquery is already installed; it will be restored if Vajra is uninstalled.\e[0m"
    else
        echo vajra | sudo tee /etc/vajra/osqueryd_origin >/dev/null
    fi
    logError "INFO" "osquery origin: $(cat /etc/vajra/osqueryd_origin)"
}

copy_files_full() {
    local extension_source="common/extension.ext"
    record_osquery_origin_full

    sources=(
        "common/cert.pem"
        "common/enrollment_secret"
        "common/vajra.flags"
        "common/osquery.flags"
        "common/osqueryd"
        "common/vajra.service"
        "common/vajra.sh"
        "$extension_source"
        "common/extensions.load"
        "common/extension.conf"
    )
    destinations=(
        "/etc/osquery/"
        "/etc/osquery/"
        "/etc/osquery/"
        "/etc/osquery/"
        "/usr/bin/"
        "/etc/systemd/system/"
        "/usr/bin/"
        "/etc/osquery/extension.ext"
        "/etc/osquery/"
        "/etc/osquery/"
    )
    _copy_file_list

    # Older installs also copied vajra_linux_extension.ext, which nothing
    # loads (extensions.load lists only extension.ext). Remove it on reinstall.
    sudo rm -f /etc/osquery/vajra_linux_extension.ext

    # Older installs recorded a terminal/noterminal build here; it is no longer used.
    sudo rm -f /etc/osquery/extension_variant

    # A stale copy of the unit at /lib/systemd/system/ can shadow or conflict
    # with the canonical /etc/systemd/system/ one on some distros - remove any
    # leftover from an older install that wrote it there.
    if [ -f /lib/systemd/system/vajra.service ]; then
        sudo rm -f /lib/systemd/system/vajra.service
        logError "INFO" "Removed legacy duplicate unit /lib/systemd/system/vajra.service."
    fi
}

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
set_permissions_to_binary_full() {
    sudo chmod +x /usr/bin/osqueryd
    sudo chmod +x /usr/bin/vajra.sh
    sudo chmod +x /etc/osquery/extension.ext
    sudo chmod 644 /etc/systemd/system/vajra.service
    logError "INFO" "Set binary permissions (full mode)."
}

# ---------------------------------------------------------------------------
# Service creation (system service)
# ---------------------------------------------------------------------------
create_full_mode_service() {
    local host_id
    host_id=$(get_host_identifier)
    if [ -n "$host_id" ]; then
        cache_host_identifier "$host_id"
    else
        echo -e "\e[31m [-] WARNING: Could not read DMI product_uuid - reduced-mode installs on this machine will not have a cached identifier to fall back on.\e[0m"
        logError "ERROR" "get_host_identifier() returned empty during full-mode install - cache not written."
    fi

    pin_host_identifier "/etc/osquery/osquery.flags"

    if ! fetch_agent_cert_from_step_ca_full; then
        if ! fetch_agent_cert_from_share_full; then
            if ! issue_local_agent_mtls_cert_full; then
                copy_agent_mtls_cert_full
            fi
        fi
    fi

    sudo systemctl daemon-reload

    sudo systemctl start vajra.service
    if [ $? -eq 0 ]; then
        echo -e "\e[32m [+] Vajra service started successfully.\e[0m"
        logError "INFO" "Successfully started Vajra service (full mode)."
    else
        echo -e "\e[31m [-] ERROR: Failed to start Vajra service.\e[0m"
        logError "ERROR" "Failed to start Vajra service (full mode)."
    fi

    sudo systemctl enable vajra.service
    if [ $? -eq 0 ]; then
        echo -e "\e[32m [+] Vajra service enabled to start on boot successfully.\e[0m"
        logError "INFO" "Vajra service enabled on boot (full mode)."
    else
        echo -e "\e[31m [-] ERROR: Vajra service failed to enable on boot.\e[0m"
        logError "ERROR" "Vajra service failed to enable on boot (full mode)."
    fi
}

# ---------------------------------------------------------------------------
# Agent mTLS client certificate (optional)
#
# Per AGENT_MTLS.md: each full-mode agent may present a client cert whose CN
# equals its host_identifier, signed by the deployment's Agent CA. If none
# of the sources below produce a cert, the agent simply connects without a
# client cert (safe rollout - matches AGENT_MTLS_MODE=off/optional).
#
# Four ways this can be satisfied, tried in this order:
#   1. fetch_agent_cert_from_step_ca_full - FULLY AUTOMATIC, FLEET-SCALE.
#      Talks directly to a running step-ca server over HTTPS and gets a
#      cert issued on the spot, authenticated by a shared provisioner
#      secret shipped in common/ (same trust model as enrollment_secret).
#      No manual per-host step at all - this is the one to use once
#      step-ca is set up (see setup_step_ca.sh). Requires
#      common/root_ca.crt, common/step_ca_provisioner.pass, and
#      STEP_CA_URL to be present/set.
#   2. fetch_agent_cert_from_share_full   - FLEET-SAFE, manual. Pulls this
#      host's own pre-issued cert from a shared mount point, keyed by UUID.
#      Falls back to this only if step-ca isn't configured/reachable.
#   3. issue_local_agent_mtls_cert_full   - CA-MACHINE-ONLY. Only fires if
#      mtls/agent-ca/agent-ca.key is sitting right next to this script. Safe
#      ONLY when this script is run directly on the one machine that holds
#      the CA (e.g. vajralab itself, for local dev/testing) - see the
#      SECURITY NOTE on that function below. NEVER copy agent-ca.key out to
#      other machines to make this path fire there too.
#   4. copy_agent_mtls_cert_full          - legacy fallback. Expects a
#      pre-baked common/agent.crt + agent.key already sitting in the
#      install package (one cert per package, built for one specific host).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# FULLY AUTOMATIC: fetch this host's cert directly from a running step-ca
# server. Configure via environment variable (or hardcode STEP_CA_URL below
# once your CA's address is settled):
#   sudo STEP_CA_URL=https://vajra-ca.example.com:9000 ./vajra_install.sh -install
# Expects, shipped in common/ (both public/safe to distribute - no private
# key material):
#   common/root_ca.crt               - step-ca's root cert, so this agent
#                                       can verify it's really talking to
#                                       the right CA
#   common/step_ca_provisioner.pass  - the shared bootstrap secret set up
#                                       in setup_step_ca.sh. Same trust
#                                       model/risk profile as
#                                       enrollment_secret: if the install
#                                       package leaks, someone could use it
#                                       to request a cert. Consistent with
#                                       the risk already accepted for
#                                       enrollment_secret fleet-wide.
# Installs the step CLI locally on first run if it isn't already present
# (best-effort - falls through to the next cert source if that fails, e.g.
# no internet access to download it).
# ---------------------------------------------------------------------------
fetch_agent_cert_from_step_ca_full() {
    if [ -z "${STEP_CA_URL:-}" ]; then
        return 1   # not configured - let share/issue-local/copy handle it
    fi

    local root_ca="common/root_ca.crt"
    local prov_pass="common/step_ca_provisioner.pass"

    if [ ! -f "$root_ca" ] || [ ! -f "$prov_pass" ]; then
        echo -e "\e[33m [i] STEP_CA_URL set but common/root_ca.crt or step_ca_provisioner.pass missing from this package - checking other cert sources.\e[0m"
        logError "INFO" "STEP_CA_URL set but required files missing in common/ - skipping step-ca fetch."
        return 1
    fi

    local host_id
    host_id=$(get_host_identifier)
    if [ -z "$host_id" ]; then
        echo -e "\e[31m [-] WARNING: Could not determine host identifier - cannot request a cert from step-ca.\e[0m"
        logError "WARN" "STEP_CA_URL set but get_host_identifier empty - skipping step-ca fetch."
        return 1
    fi

    if ! command -v step >/dev/null 2>&1; then
        echo -e "\e[33m [+] step CLI not found - attempting to install it...\e[0m"
        local arch step_arch
        arch=$(uname -m)
        case "$arch" in
            x86_64) step_arch="amd64" ;;
            aarch64|arm64) step_arch="arm64" ;;
            *) echo -e "\e[31m [-] WARNING: Unsupported architecture ($arch) for automatic step CLI install.\e[0m"
               logError "WARN" "step-ca fetch: unsupported arch $arch for step CLI auto-install."
               return 1 ;;
        esac
        local tmp_tgz="/tmp/step-cli-install.tar.gz"
        local step_ver
        step_ver=$(curl -fsSL "https://api.github.com/repos/smallstep/cli/releases/latest" \
            | grep -o '"tag_name": *"[^"]*"' | head -1 | sed -E 's/.*"tag_name": *"v?([^"]*)".*/\1/')
        if [ -z "$step_ver" ]; then
            echo -e "\e[31m [-] WARNING: Could not determine latest step CLI version - checking other cert sources.\e[0m"
            logError "WARN" "step-ca fetch: could not resolve latest step CLI version from GitHub API."
            return 1
        fi
        if curl -fsSL -o "$tmp_tgz" \
            "https://github.com/smallstep/cli/releases/download/v${step_ver}/step_linux_${step_ver}_${step_arch}.tar.gz" \
            && tar -xzf "$tmp_tgz" -C /tmp \
            && sudo mv /tmp/step_*/bin/step /usr/local/bin/step; then
            rm -f "$tmp_tgz"
            echo -e "\e[32m [+] step CLI installed.\e[0m"
        else
            echo -e "\e[31m [-] WARNING: Could not install step CLI (no internet access?) - checking other cert sources.\e[0m"
            logError "WARN" "step-ca fetch: failed to auto-install step CLI."
            rm -f "$tmp_tgz"
            return 1
        fi
    fi

    echo -e "\e[33m [+] Requesting mTLS cert for this host (${host_id}) from step-ca at ${STEP_CA_URL}...\e[0m"
    local tmp_crt="/tmp/vajra_agent_${host_id}.crt"
    local tmp_key="/tmp/vajra_agent_${host_id}.key"
    rm -f "$tmp_crt" "$tmp_key"

    if step ca certificate "$host_id" "$tmp_crt" "$tmp_key" \
        --provisioner "${STEP_CA_PROVISIONER:-vajra-fleet-v2}" \
        --provisioner-password-file "$prov_pass" \
        --ca-url "$STEP_CA_URL" \
        --root "$root_ca" \
        --force >> "$LogFile" 2>&1; then

        sudo install -o root -g root -m 644 "$tmp_crt" /etc/osquery/agent.crt
        local crt_status=$?
        sudo install -o root -g root -m 600 "$tmp_key" /etc/osquery/agent.key
        local key_status=$?
        rm -f "$tmp_crt" "$tmp_key"

        if [ "$crt_status" -eq 0 ] && [ "$key_status" -eq 0 ]; then
            echo -e "\e[32m [+] Agent mTLS certificate issued by step-ca and installed for host_identifier=${host_id}: /etc/osquery/agent.crt (644), /etc/osquery/agent.key (600).\e[0m"
            logError "INFO" "mTLS cert issued by step-ca and installed for $host_id."

            # step-ca issues short-lived certs by design - without a renewal
            # daemon this agent's mTLS cert expires and breaks the connection.
            # Copy the root CA into place and set up automatic renewal so
            # this is a one-time, per-host setup rather than a manual task.
            sudo install -o root -g root -m 644 "$root_ca" /etc/osquery/root_ca.crt

            sudo tee /etc/systemd/system/vajra-cert-renew.service >/dev/null <<EOF
[Unit]
Description=step-ca cert auto-renewal for Vajra agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/step ca renew --daemon --ca-url ${STEP_CA_URL} --root /etc/osquery/root_ca.crt /etc/osquery/agent.crt /etc/osquery/agent.key
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
            sudo systemctl daemon-reload
            if sudo systemctl enable --now vajra-cert-renew.service >> "$LogFile" 2>&1; then
                echo -e "\e[32m [+] Automatic mTLS cert renewal daemon (vajra-cert-renew.service) installed and running.\e[0m"
                logError "INFO" "vajra-cert-renew.service installed and started for $host_id."
            else
                echo -e "\e[31m [-] WARNING: Cert issued, but the renewal daemon failed to start - this cert will expire without renewal. Check $LogFile.\e[0m"
                logError "WARN" "vajra-cert-renew.service failed to enable/start for $host_id."
            fi

            return 0
        else
            echo -e "\e[31m [-] ERROR: step-ca issued a cert but installing it to /etc/osquery/ failed.\e[0m"
            logError "ERROR" "step-ca cert issued for $host_id but install failed (crt_status=$crt_status key_status=$key_status)."
            return 1
        fi
    else
        echo -e "\e[31m [-] WARNING: step-ca certificate request failed - checking other cert sources. See $LogFile for details.\e[0m"
        logError "WARN" "step-ca certificate request failed for $host_id - see log above for step CLI output."
        rm -f "$tmp_crt" "$tmp_key"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# FLEET-SAFE: fetch this host's own pre-issued cert from a shared mount,
# keyed by its own UUID - e.g. an NFS/CIFS mount an admin has already set up
# at install time, or any locally-reachable path. Set via the
# AGENTCERT_SHARE_ROOT environment variable:
#   sudo AGENTCERT_SHARE_ROOT=/mnt/vajra-certs ./vajra_install.sh -install
# Expects, per host:
#   $AGENTCERT_SHARE_ROOT/<host-uuid>/agent.crt
#   $AGENTCERT_SHARE_ROOT/<host-uuid>/agent.key
# already placed there ahead of time by looping issue-agent-cert.sh on
# vajralab (which holds the CA) across every known fleet UUID - the CA
# private key itself never goes anywhere near the share or any endpoint.
# ---------------------------------------------------------------------------
fetch_agent_cert_from_share_full() {
    if [ -z "${AGENTCERT_SHARE_ROOT:-}" ]; then
        return 1   # not configured - let issue_local/copy handle it
    fi

    local host_id
    host_id=$(get_host_identifier)
    if [ -z "$host_id" ]; then
        echo -e "\e[31m [-] WARNING: Could not determine host identifier - cannot fetch mTLS cert from share.\e[0m"
        logError "WARN" "AGENTCERT_SHARE_ROOT set but get_host_identifier empty - skipping share fetch."
        return 1
    fi

    local src_crt="${AGENTCERT_SHARE_ROOT%/}/${host_id}/agent.crt"
    local src_key="${AGENTCERT_SHARE_ROOT%/}/${host_id}/agent.key"

    if [ ! -f "$src_crt" ] || [ ! -f "$src_key" ]; then
        echo -e "\e[33m [i] No mTLS cert found on the share for this host (${host_id}) - checking other sources.\e[0m"
        logError "INFO" "AGENTCERT_SHARE_ROOT set but no cert at ${src_crt} for host_identifier=${host_id}."
        return 1
    fi

    echo -e "\e[33m [+] Fetching mTLS cert for this host (${host_id}) from ${AGENTCERT_SHARE_ROOT}...\e[0m"
    sudo install -o root -g root -m 644 "$src_crt" /etc/osquery/agent.crt
    local crt_status=$?
    sudo install -o root -g root -m 600 "$src_key" /etc/osquery/agent.key
    local key_status=$?

    if [ "$crt_status" -eq 0 ] && [ "$key_status" -eq 0 ]; then
        echo -e "\e[32m [+] Agent mTLS certificate fetched from fleet share and installed for host_identifier=${host_id}: /etc/osquery/agent.crt (644), /etc/osquery/agent.key (600).\e[0m"
        logError "INFO" "mTLS cert fetched from share and installed for $host_id."
        return 0
    else
        echo -e "\e[31m [-] ERROR: Failed to install cert/key fetched from share.\e[0m"
        logError "ERROR" "Failed to install share-fetched cert/key (crt_status=$crt_status key_status=$key_status) for $host_id."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Per-host cert issuance from a LOCAL Agent CA (SECURITY NOTE below).
#
# Only fires if an Agent CA private key is sitting next to this script, at
# mtls/agent-ca/{agent-ca.crt,agent-ca.key}. This is intended for the case
# where you run this installer FROM the machine that already holds the CA
# (e.g. vajralab) - each target host gets its own cert, CN'd to its own
# DMI UUID, minted fresh at install time.
#
# DO NOT put mtls/agent-ca/agent-ca.key into a package you hand out or push
# to other machines. Whoever holds that key can mint a valid client identity
# for ANY host_identifier - it must stay exactly where the CA already lives,
# never travel with the installer itself. If you need to install on a
# different box than the one holding the CA, either (a) run this installer
# there too, in-place, or (b) issue the cert separately with
# mtls/issue-agent-cert.sh <host_id> and drop the resulting agent.crt/
# agent.key into common/ for copy_agent_mtls_cert_full() below to pick up -
# that path ships only the public cert+key pair, never the CA key.
# ---------------------------------------------------------------------------
issue_local_agent_mtls_cert_full() {
    local ca_dir="$SCRIPT_DIR/mtls/agent-ca"
    local ca_crt="$ca_dir/agent-ca.crt"
    local ca_key="$ca_dir/agent-ca.key"
    local issue_script="$SCRIPT_DIR/mtls/issue-agent-cert.sh"

    if [ ! -f "$ca_crt" ] || [ ! -f "$ca_key" ]; then
        return 1   # no local CA here - let copy_agent_mtls_cert_full() handle it
    fi

    if [ ! -f "$issue_script" ]; then
        echo -e "\e[31m [-] WARNING: Local Agent CA found but mtls/issue-agent-cert.sh is missing - skipping local issuance.\e[0m"
        logError "WARN" "Agent CA present but issue-agent-cert.sh missing at $issue_script."
        return 1
    fi

    local host_id
    host_id=$(get_host_identifier)
    if [ -z "$host_id" ]; then
        echo -e "\e[31m [-] WARNING: Could not determine host identifier - cannot issue a local mTLS cert.\e[0m"
        logError "WARN" "get_host_identifier empty - skipping local mTLS cert issuance."
        return 1
    fi

    echo -e "\e[33m [+] Local Agent CA found - issuing a fresh mTLS cert for this host ($host_id)...\e[0m"
    logError "INFO" "Issuing local mTLS cert via $issue_script for host_identifier=$host_id."

    ( cd "$ca_dir/.." && ./issue-agent-cert.sh "$host_id" )
    local issued_crt="$SCRIPT_DIR/mtls/agent-certs/$host_id/agent.crt"
    local issued_key="$SCRIPT_DIR/mtls/agent-certs/$host_id/agent.key"

    if [ ! -f "$issued_crt" ] || [ ! -f "$issued_key" ]; then
        echo -e "\e[31m [-] ERROR: issue-agent-cert.sh did not produce agent.crt/agent.key for $host_id.\e[0m"
        logError "ERROR" "Local mTLS issuance failed for $host_id - no output cert/key found."
        return 1
    fi

    sudo install -o root -g root -m 644 "$issued_crt" /etc/osquery/agent.crt
    local crt_status=$?
    sudo install -o root -g root -m 600 "$issued_key" /etc/osquery/agent.key
    local key_status=$?

    if [ "$crt_status" -eq 0 ] && [ "$key_status" -eq 0 ]; then
        echo -e "\e[32m [+] Agent mTLS certificate issued and installed for host_identifier=$host_id: /etc/osquery/agent.crt (644), /etc/osquery/agent.key (600).\e[0m"
        logError "INFO" "Local mTLS cert installed for $host_id."
        return 0
    else
        echo -e "\e[31m [-] ERROR: Failed to install locally-issued mTLS certificate/key.\e[0m"
        logError "ERROR" "Failed to install locally-issued cert/key (crt_status=$crt_status key_status=$key_status) for $host_id."
        return 1
    fi
}

copy_agent_mtls_cert_full() {
    local crt_src="common/agent.crt"
    local key_src="common/agent.key"

    if [ ! -f "$crt_src" ] && [ ! -f "$key_src" ]; then
        echo -e "\e[33m [i] No agent mTLS certificate in this package (common/agent.crt / agent.key not found) - skipping.\e[0m"
        echo -e "\e[33m [i] Agent will connect without a client certificate (fine if AGENT_MTLS_MODE is off/optional on the server).\e[0m"
        logError "INFO" "No agent mTLS cert/key present - mTLS not configured for this install."
        return
    fi

    if [ ! -f "$crt_src" ] || [ ! -f "$key_src" ]; then
        echo -e "\e[31m [-] WARNING: Only one of agent.crt/agent.key found in common/ - mTLS needs both. Skipping mTLS setup.\e[0m"
        logError "WARN" "Incomplete mTLS cert pair in common/ - skipping mTLS install."
        return
    fi

    echo -e "\e[33m [+] Installing agent mTLS client certificate...\e[0m"

    sudo install -o root -g root -m 644 "$crt_src" /etc/osquery/agent.crt
    local crt_status=$?
    sudo install -o root -g root -m 600 "$key_src" /etc/osquery/agent.key
    local key_status=$?

    if [ "$crt_status" -eq 0 ] && [ "$key_status" -eq 0 ]; then
        echo -e "\e[32m [+] Agent mTLS certificate installed: /etc/osquery/agent.crt (644), /etc/osquery/agent.key (600, root-only).\e[0m"
        logError "INFO" "Agent mTLS cert/key installed."
    else
        echo -e "\e[31m [-] ERROR: Failed to install agent mTLS certificate/key.\e[0m"
        logError "ERROR" "Failed to install agent mTLS cert/key (crt_status=$crt_status key_status=$key_status)."
        return
    fi

    if command -v openssl &>/dev/null; then
        local cert_cn host_id
        cert_cn=$(sudo openssl x509 -in /etc/osquery/agent.crt -noout -subject 2>/dev/null \
            | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p' | tr -d '[:space:]')
        host_id=$(get_host_identifier)

        if [ -z "$cert_cn" ]; then
            echo -e "\e[33m [!] WARNING: Could not read CN from agent.crt to verify it.\e[0m"
            logError "WARN" "Could not parse CN from installed agent.crt."
        elif [ -n "$host_id" ] && [ "$cert_cn" != "$host_id" ]; then
            echo -e "\e[33m [!] WARNING: agent.crt CN ($cert_cn) does not match this host's identifier ($host_id).\e[0m"
            echo -e "\e[33m [!] The server will reject this certificate once AGENT_MTLS_MODE is optional/required.\e[0m"
            logError "WARN" "Agent cert CN mismatch: cert_cn=$cert_cn host_id=$host_id"
        else
            echo -e "\e[32m [+] agent.crt CN matches this host's identifier ($host_id).\e[0m"
            logError "INFO" "Agent cert CN verified against host identifier ($host_id)."
        fi
    fi
}

# ---------------------------------------------------------------------------
# osqueryd upgrade on an already-installed full-mode agent, run by hand. It
# installs the common/osqueryd shipped in this package,
# checks the agent comes back up, and puts the previous binary back on its
# own if it doesn't, so a bad osqueryd never needs a reinstall.
#
# osqueryd upgrades its database in place the first time it starts, and an
# older osqueryd can't open the result (5.0.1.1 refuses a 5.12.1 database:
# "Column families not opened"). So the database is backed up with the
# binary and put back with it, and going back to an older osqueryd starts it
# on a new database.
#
# Invoked via: sudo ./vajra_install.sh -update-osquery
# ---------------------------------------------------------------------------
OSQUERYD_PATH="/usr/bin/osqueryd"
OSQUERYD_BACKUP="/usr/bin/osqueryd.vajra-prev"
# Full mode runs osqueryd with the default --database_path (vajra.sh passes
# only --flagfile).
OSQUERY_DB_PATH="/var/osquery/osquery.db"
OSQUERY_DB_BACKUP="/var/osquery/osquery.db.vajra-prev"
VAJRA_UNIT_PATH="/etc/systemd/system/vajra.service"
OSQUERY_HEALTH_TIMEOUT=120     # seconds for osqueryd + the extension to come up
OSQUERY_HEALTH_STABLE=20       # ...and then stay up

has_systemd() { [ -d /run/systemd/system ]; }

# osqueryd_version prints the version a binary reports ("5.12.1"), or nothing.
osqueryd_version() {
    "$1" --version 2>/dev/null | awk '{print $NF}'
}

# version_older is true when version $1 sorts before version $2.
version_older() {
    [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ] \
        && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

# osquery_db_step does $1 to the database while the agent is stopped:
#   backup   copy it to OSQUERY_DB_BACKUP (an empty marker if there is none)
#   fresh    move it to OSQUERY_DB_BACKUP so osqueryd starts a new one
#   restore  put the backup back exactly as it was
osquery_db_step() {
    case "$1" in
        backup|fresh)
            rm -rf "${OSQUERY_DB_BACKUP:?}"
            if [ ! -e "$OSQUERY_DB_PATH" ]; then
                mkdir -p "$OSQUERY_DB_BACKUP" && : > "$OSQUERY_DB_BACKUP/.vajra-no-db"
            elif [ "$1" = fresh ]; then
                mv "$OSQUERY_DB_PATH" "$OSQUERY_DB_BACKUP"
            else
                cp -a "$OSQUERY_DB_PATH" "$OSQUERY_DB_BACKUP" || { rm -rf "${OSQUERY_DB_BACKUP:?}"; return 1; }
            fi
            ;;
        restore)
            [ -d "$OSQUERY_DB_BACKUP" ] || return 1
            rm -rf "${OSQUERY_DB_PATH:?}" || return 1
            [ -e "$OSQUERY_DB_BACKUP/.vajra-no-db" ] && return 0
            cp -a "$OSQUERY_DB_BACKUP" "$OSQUERY_DB_PATH"
            ;;
    esac
}

# set_refuse_manual_stop toggles vajra.service's tamper protection, which
# otherwise blocks the stop this upgrade needs (see do_uninstall_steps_full).
set_refuse_manual_stop() {
    sed -i "s/^RefuseManualStop=.*/RefuseManualStop=$1/" "$VAJRA_UNIT_PATH" 2>/dev/null
    systemctl daemon-reload 2>/dev/null
}

# swap_osqueryd stops the agent, does osquery_db_step $2 to the database,
# installs $1 as osqueryd and starts it again. Returns 2, with nothing
# changed, when the database step fails.
swap_osqueryd() {
    set_refuse_manual_stop no
    systemctl stop vajra.service 2>/dev/null
    local rc=0
    if ! osquery_db_step "$2"; then
        rc=2
    else
        chattr -i "$OSQUERYD_PATH" 2>/dev/null
        if install -m 0755 -o root -g root "$1" "$OSQUERYD_PATH.new" \
            && mv -f "$OSQUERYD_PATH.new" "$OSQUERYD_PATH"; then
            rc=0
        else
            rm -f "$OSQUERYD_PATH.new"
            rc=1
        fi
    fi
    set_refuse_manual_stop yes
    systemctl start vajra.service 2>/dev/null
    return $rc
}

# agent_healthy waits for osqueryd, the extension and vajra.service to be up
# and stay up for OSQUERY_HEALTH_STABLE seconds, within OSQUERY_HEALTH_TIMEOUT.
agent_healthy() {
    local deadline=$(( $(date +%s) + OSQUERY_HEALTH_TIMEOUT ))
    local up_since=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if pgrep -x osqueryd >/dev/null 2>&1 && pgrep -x extension.ext >/dev/null 2>&1 \
            && systemctl is-active --quiet vajra.service; then
            [ -n "$up_since" ] || up_since=$(date +%s)
            if [ $(( $(date +%s) - up_since )) -ge "$OSQUERY_HEALTH_STABLE" ]; then
                return 0
            fi
        else
            up_since=""
        fi
        sleep 2
    done
    return 1
}

update_osquery_standalone_full() {
    echo -e "\e[32m [+] Upgrading osqueryd on this node.\e[0m"
    logError "INFO" "osqueryd upgrade requested."

    check_permissions_full

    INSTALL_MODE="full"
    if ! is_vajra_installed || [ ! -f "$OSQUERYD_PATH" ] || [ ! -f "$VAJRA_UNIT_PATH" ]; then
        echo -e "\e[31m [-] ERROR: Vajra (full mode) is not installed on this system - install it first: sudo $0 -install\e[0m"
        logError "ERROR" "osqueryd upgrade requested but Vajra is not installed."
        exit 1
    fi
    if ! has_systemd; then
        echo -e "\e[31m [-] ERROR: -update-osquery needs systemd.\e[0m"
        logError "ERROR" "osqueryd upgrade requested on a host without systemd."
        exit 1
    fi

    local new_bin="common/osqueryd"
    if [ ! -f "$new_bin" ]; then
        echo -e "\e[31m [-] ERROR: $new_bin not found in this package - nothing to install.\e[0m"
        logError "ERROR" "osqueryd upgrade requested but $new_bin is missing from this package."
        exit 1
    fi
    chmod +x "$new_bin" 2>/dev/null
    local old_version new_version
    old_version=$(osqueryd_version "$OSQUERYD_PATH")
    new_version=$(osqueryd_version "$new_bin")
    if [ -z "$new_version" ]; then
        echo -e "\e[31m [-] ERROR: $new_bin does not run on this host (no version reported) - not installing it.\e[0m"
        logError "ERROR" "osqueryd upgrade: $new_bin reported no version."
        exit 1
    fi
    if [ "$(sha256sum < "$new_bin")" = "$(sha256sum < "$OSQUERYD_PATH")" ]; then
        echo -e "\e[32m [+] osqueryd is already at $new_version - nothing to do.\e[0m"
        logError "INFO" "osqueryd upgrade: already at $new_version."
        exit 0
    fi
    echo -e "\e[33m [+] osqueryd ${old_version:-unknown} -> $new_version\e[0m"
    logError "INFO" "osqueryd upgrade: ${old_version:-unknown} -> $new_version"

    if ! cp -p "$OSQUERYD_PATH" "$OSQUERYD_BACKUP"; then
        echo -e "\e[31m [-] ERROR: could not back up $OSQUERYD_PATH - not upgrading.\e[0m"
        logError "ERROR" "osqueryd upgrade: backup to $OSQUERYD_BACKUP failed."
        exit 1
    fi

    # An older osqueryd can't open the database a newer one upgraded.
    local db_step=backup
    if version_older "$new_version" "$old_version"; then
        db_step=fresh
        echo -e "\e[33m [i] $new_version is older than $old_version and can't read its database: it starts on a new one (results not yet sent are dropped, and the agent enrolls again). The current database is kept until the agent is up.\e[0m"
        logError "WARN" "osqueryd downgrade $old_version -> $new_version: starting on a new database."
    fi

    echo -e "\e[33m [+] Installing osqueryd $new_version and restarting the agent...\e[0m"
    local swap_rc=0
    swap_osqueryd "$new_bin" "$db_step" || swap_rc=$?
    if [ "$swap_rc" -eq 2 ]; then
        rm -f "$OSQUERYD_BACKUP"
        echo -e "\e[31m [-] ERROR: could not back up the osquery database ($OSQUERY_DB_PATH) - not upgrading. Nothing changed.\e[0m"
        logError "ERROR" "osqueryd upgrade: backing up $OSQUERY_DB_PATH failed; nothing changed."
        exit 1
    fi
    if [ "$swap_rc" -eq 0 ] && agent_healthy; then
        rm -f "$OSQUERYD_BACKUP"
        rm -rf "${OSQUERY_DB_BACKUP:?}"
        echo -e "\e[32m [+] osqueryd is now $new_version; the agent is running.\e[0m"
        logError "INFO" "osqueryd upgrade successful: now $new_version."
        return 0
    fi

    echo -e "\e[31m [-] The agent did not come up on osqueryd $new_version - putting ${old_version:-the previous version} back...\e[0m"
    logError "ERROR" "osqueryd upgrade: agent unhealthy on $new_version - restoring ${old_version:-previous}."
    if swap_osqueryd "$OSQUERYD_BACKUP" restore && agent_healthy; then
        rm -f "$OSQUERYD_BACKUP"
        rm -rf "${OSQUERY_DB_BACKUP:?}"
        echo -e "\e[33m [-] Restored osqueryd ${old_version:-previous}; the agent is running. Nothing else changed.\e[0m"
        logError "WARN" "osqueryd upgrade rolled back to ${old_version:-previous}."
    else
        echo -e "\e[31m [-] CRITICAL: the agent is still not healthy after restoring osqueryd. The previous binary is kept at $OSQUERYD_BACKUP and its database at $OSQUERY_DB_BACKUP - check 'systemctl status vajra.service'.\e[0m"
        logError "ERROR" "osqueryd upgrade: agent unhealthy even after restoring the previous osqueryd (kept at $OSQUERYD_BACKUP, database at $OSQUERY_DB_BACKUP)."
    fi
    exit 1
}

# ---------------------------------------------------------------------------
# Install orchestration
# ---------------------------------------------------------------------------
install_osquery_full() {
    echo -e "\e[32m [+] Installing Vajra client (full mode) version $scriptVersion.\e[0m"
    logError "INFO" "Vajra client full-mode installation, script version $scriptVersion"

    check_permissions_full
    check_package_files
    check_linux_version
    check_vajra_service_not_running_full
    cleanup_stale_processes
    prompt_access_level
    create_directories_full
    copy_files_full
    set_permissions_to_binary_full
    create_full_mode_service
    harden_vajra_config
    setup_clamav

    echo -e "\e[32m [+] Vajra Client installation successful (full mode)!\e[0m"
    echo -e "\e[33m [i] Version $scriptVersion.\e[0m"
    logError "INFO" "Vajra Client installation successful (full mode), version $scriptVersion."
}

# ---------------------------------------------------------------------------
# Uninstall orchestration
# ---------------------------------------------------------------------------
do_uninstall_steps_full() {
    # vajra.service ships with RefuseManualStop=yes (tamper protection against
    # an ad hoc "systemctl stop") - a plain stop below would be refused, so
    # clear it here first. Uninstall needs no token; running as root is the
    # only gate, so this just disarms the unit for the uninstall in progress.
    if [ -f /etc/systemd/system/vajra.service ]; then
        sudo sed -i 's/^RefuseManualStop=yes/RefuseManualStop=no/' /etc/systemd/system/vajra.service 2>/dev/null
        sudo systemctl daemon-reload 2>/dev/null
    fi

    echo -e "\e[33m [+] Stopping Vajra service\e[0m"
    sudo systemctl stop vajra.service 2>/dev/null
    echo -e "\e[33m [+] Disabling Vajra service\e[0m"
    sudo systemctl disable vajra.service 2>/dev/null

    # Remove the step-ca cert auto-renewal daemon (see
    # fetch_agent_cert_from_step_ca_full) if this host has one - otherwise
    # it survives uninstall indefinitely, still polling step-ca for a host
    # that's supposed to be deprovisioned.
    if systemctl list-unit-files vajra-cert-renew.service >/dev/null 2>&1; then
        echo -e "\e[33m [+] Stopping and removing mTLS cert renewal daemon\e[0m"
        sudo systemctl stop vajra-cert-renew.service 2>/dev/null
        sudo systemctl disable vajra-cert-renew.service 2>/dev/null
        sudo rm -f /etc/systemd/system/vajra-cert-renew.service
        sudo systemctl daemon-reload 2>/dev/null
        logError "INFO" "vajra-cert-renew.service stopped and removed during uninstall."
    fi

    # harden_vajra_config marks extension.conf, enrollment_secret, osquery.flags,
    # vajra.flags, agent.crt and agent.key immutable (chattr +i) at the end of
    # every full install - any of those left immutable makes
    # the rm -rf below fail per-file with "Operation not permitted" while
    # still reporting overall uninstall success, leaving stale hardened files
    # behind. Clear the whole tree recursively so a re-install afterwards
    # starts from a genuinely clean /etc/osquery/, not just extension.ext.
    # Safe no-op on a machine that was never updated/hardened.
    sudo chattr -R -i /etc/osquery/ 2>/dev/null

    echo -e "\e[33m [+] Removing Vajra binaries, configuration and service files\e[0m"
    if [ "$(cat /etc/vajra/osqueryd_origin 2>/dev/null)" = preexisting ]; then
        # osquery was here first: remove only what Vajra added and put the original back.
        sudo rm -rf /usr/bin/vajra.sh /etc/osquery/ \
            /lib/systemd/system/vajra.service /etc/systemd/system/vajra.service
        [ -f /usr/bin/osqueryd.vajra-orig ] && sudo mv -f /usr/bin/osqueryd.vajra-orig /usr/bin/osqueryd
        [ -d /etc/osquery.vajra-orig ] && sudo mv -f /etc/osquery.vajra-orig /etc/osquery
        sudo rm -f /etc/vajra/osqueryd_origin
        echo -e "\e[33m [i] The original osquery was restored (its database in /var/osquery was left alone). Restart its own service if it had one.\e[0m"
    else
        sudo rm -rf /usr/bin/osqueryd /usr/bin/vajra.sh /etc/osquery/ \
            /lib/systemd/system/vajra.service /etc/systemd/system/vajra.service /var/osquery/
        sudo rm -f /etc/vajra/osqueryd_origin
    fi
    sudo systemctl daemon-reload 2>/dev/null

    # NOTE: /etc/vajra/host_id (the cached DMI UUID - see cache_host_identifier
    # in vajra_common.sh) is deliberately NOT removed here. A reduced-mode
    # install on this same machine, now or later, still needs to read it to
    # resolve the same host identifier this full-mode install used. Delete it
    # manually only if you specifically want the next install (any mode) on
    # this machine to re-derive/report as a different identifier.

    echo -e "\e[32m [+] Full-mode Vajra installation removed.\e[0m"
    logError "INFO" "Full-mode Vajra installation removed."
    echo -e "\e[32mVajra Client uninstallation successful\e[0m"
}

# Used internally when an install fails partway through.
cleanup_partial_install_full() {
    echo -e "\e[33m [+] Cleaning up partial installation...\e[0m"
    logError "INFO" "Cleaning up partial installation."
    do_uninstall_steps_full
}

# User-facing uninstall - no token needed, like vajra_uninstall.bat on Windows.
# Root (sudo) is the only requirement, enforced by check_permissions_full.
uninstall_osquery_full() {
    echo -e "\e[33m [+] Uninstalling Vajra Client (full mode). Please wait ...\e[0m"
    logError "INFO" "Uninstalling Vajra Client (full mode)."

    check_permissions_full

    if ! is_vajra_installed; then
        echo -e "\e[31m [-] ERROR: Vajra (full mode) is not installed on this system - nothing to uninstall.\e[0m"
        logError "ERROR" "Uninstall requested but Vajra (full mode) is not installed."
        exit 1
    fi

    verify_agent_mtls_cert_uninstall

    do_uninstall_steps_full
}

# ---------------------------------------------------------------------------
# mTLS identity sanity check before uninstall proceeds. Non-blocking by
# design (matches AGENT_MTLS_MODE's own staged-rollout philosophy elsewhere
# in this codebase): a mismatch here is a signal worth having in the log for
# whoever's auditing the fleet, not a reason to refuse an uninstall. It
# records whether this host's mTLS identity looked right at the moment of
# removal, which is useful forensic context if a machine's cert was ever
# tampered with or copied elsewhere.
# ---------------------------------------------------------------------------
verify_agent_mtls_cert_uninstall() {
    local cert="/etc/osquery/agent.crt"
    local host_id
    host_id=$(cat /etc/vajra/host_id 2>/dev/null)

    if [ ! -f "$cert" ]; then
        logError "INFO" "mTLS uninstall check: no agent.crt present at $cert - nothing to verify."
        return 0
    fi

    echo -e "\e[33m [+] Verifying mTLS agent identity before uninstall...\e[0m"

    local cert_cn
    cert_cn=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p')

    if [ -z "$cert_cn" ]; then
        echo -e "\e[31m [-] WARNING: Could not read a CN from $cert (unreadable or malformed).\e[0m"
        logError "WARN" "mTLS uninstall check: could not read CN from $cert."
    elif [ -z "$host_id" ]; then
        echo -e "\e[31m [-] WARNING: No cached host_identifier at /etc/vajra/host_id to compare against.\e[0m"
        logError "WARN" "mTLS uninstall check: cert CN=$cert_cn but no host_identifier available to compare."
    elif [ "$cert_cn" = "$host_id" ]; then
        echo -e "\e[32m [+] mTLS identity check: OK - cert CN matches this host's identifier.\e[0m"
        logError "INFO" "mTLS uninstall check: PASS - cert CN ($cert_cn) matches host_identifier ($host_id)."
    else
        echo -e "\e[31m [-] WARNING: mTLS identity MISMATCH - cert CN ($cert_cn) does not match host_identifier ($host_id).\e[0m"
        echo -e "\e[31m [-] This host's agent cert may have been copied from elsewhere or tampered with. Proceeding with uninstall (non-blocking check).\e[0m"
        logError "WARN" "mTLS uninstall check: MISMATCH - cert CN ($cert_cn) != host_identifier ($host_id). Proceeding with uninstall anyway (non-blocking check)."
    fi
}

# ---------------------------------------------------------------------------

# ===========================================================================
# SECTION 3 - REDUCED MODE ONLY (was vajra_install_reduced.sh)
# ===========================================================================


# ---------------------------------------------------------------------------
# Root check - reduced mode works either way: run directly by a non-root
# user (the common case), or by root on behalf of $SUDO_USER.
# ---------------------------------------------------------------------------
check_permissions_reduced() {
    if [ "$EUID" -eq 0 ]; then
        RUNNING_AS_ROOT=true
        resolve_target_user
        echo -e "\e[33m [i] Running as root - installing reduced mode for user '$TARGET_USER' (via SUDO_USER).\e[0m"
        logError "INFO" "Reduced mode invoked as root, targeting SUDO_USER=$TARGET_USER."
    else
        RUNNING_AS_ROOT=false
        resolve_target_user
        echo -e "\e[33m [i] No root/sudo privileges - installing reduced mode under your own home directory: $TARGET_HOME\e[0m"
        echo -e "\e[33m [i] Full (admin) mode is not available without root - if you need it: sudo ./vajra_install.sh -install\e[0m"
        logError "INFO" "Reduced mode, no root - installing for $TARGET_USER under $TARGET_HOME."
    fi
}

# ---------------------------------------------------------------------------
# Service-already-running detection. Checks this user's own reduced-mode
# instance, AND (if root) full mode's system service - since /etc/vajra/host_id
# is shared across modes on the same box, letting both run simultaneously
# causes the two to visibly collide on the dashboard.
# ---------------------------------------------------------------------------
check_vajra_service_not_running_reduced() {
    echo -e "\e[33m [+] Checking for existing Vajra installations...\e[0m"

    if [ "$RUNNING_AS_ROOT" = true ]; then
        if command -v systemctl &>/dev/null && systemctl is-active --quiet vajra.service 2>/dev/null; then
            echo -e "\e[31m [-] ERROR: Vajra (full mode) service is already running on this machine. Exiting...\e[0m"
            echo -e "\e[31m [-] Running both modes on the same machine causes conflicting node identities. Uninstall that instance first.\e[0m"
            logError "ERROR" "Full-mode vajra.service already active - refusing reduced-mode install."
            read -n 1 -s -r -p "Press any key to exit ..."
            exit 1
        fi
        local uid_of_u
        uid_of_u=$(id -u "$TARGET_USER" 2>/dev/null)
        if [ -n "$uid_of_u" ] && sudo -u "$TARGET_USER" XDG_RUNTIME_DIR="/run/user/$uid_of_u" systemctl --user is-active --quiet vajra.service 2>/dev/null; then
            echo -e "\e[31m [-] ERROR: A reduced-mode Vajra service is already running for user '$TARGET_USER'. Exiting...\e[0m"
            logError "ERROR" "Reduced-mode vajra.service already active for $TARGET_USER."
            read -n 1 -s -r -p "Press any key to exit ..."
            exit 1
        fi
    else
        if systemctl --user is-active --quiet vajra.service 2>/dev/null; then
            echo -e "\e[31m [-] ERROR: A reduced-mode Vajra service is already running for your account. Exiting...\e[0m"
            logError "ERROR" "Reduced-mode vajra.service already active for $(whoami)."
            read -n 1 -s -r -p "Press any key to exit ..."
            exit 1
        fi
    fi

    echo -e "\e[32m [+] No existing Vajra service detected. Proceeding with installation...\e[0m"
    logError "INFO" "No existing Vajra service detected (reduced mode)."
}

# ---------------------------------------------------------------------------
# Directory creation - entirely under the target user's own home directory,
# no /etc, no /usr/bin, nothing outside $HOME.
# ---------------------------------------------------------------------------
create_directories_reduced() {
    echo -e "\e[33m [+] Creating installation directories \e[0m"
    VAJRA_HOME="$TARGET_HOME/.local/share/vajra"
    OSQUERY_DIR="$VAJRA_HOME/etc/osquery"
    BIN_DIR="$VAJRA_HOME/bin"
    VAR_OSQUERY_DIR="$VAJRA_HOME/var/osquery"

    if [ "$RUNNING_AS_ROOT" = true ]; then
        sudo -u "$TARGET_USER" mkdir -p "$OSQUERY_DIR" "$BIN_DIR" "$VAR_OSQUERY_DIR"
    else
        mkdir -p "$OSQUERY_DIR" "$BIN_DIR" "$VAR_OSQUERY_DIR"
    fi

    logError "INFO" "Created $OSQUERY_DIR, $BIN_DIR, $VAR_OSQUERY_DIR (reduced mode, user=$TARGET_USER)."
}

# ---------------------------------------------------------------------------
# File copy - baseline telemetry only, no extensions, no vajra.sh wrapper
# (reduced mode's systemd unit invokes osqueryd directly - see
# create_reduced_mode_service - so vajra.sh is never needed here).
# ---------------------------------------------------------------------------
copy_files_reduced() {
    sources=(
        "common/cert.pem"
        "common/enrollment_secret"
        "common/vajra.flags"
        "common/osquery.flags"
        "common/osqueryd"
    )
    destinations=(
        "$OSQUERY_DIR/"
        "$OSQUERY_DIR/"
        "$OSQUERY_DIR/"
        "$OSQUERY_DIR/"
        "$BIN_DIR/"
    )
    _copy_file_list

    # osquery.flags loads the shared flags from /etc/osquery/vajra.flags,
    # which only a full install writes: point it at this mode's own copy.
    local sed_cmd=(sed -i "s#^--flagfile=/etc/osquery/vajra.flags\$#--flagfile=$OSQUERY_DIR/vajra.flags#" "$OSQUERY_DIR/osquery.flags")
    if [ "$RUNNING_AS_ROOT" = true ]; then
        sed_cmd=(sudo -u "$TARGET_USER" "${sed_cmd[@]}")
    fi
    if ! "${sed_cmd[@]}" || ! grep -qxF -- "--flagfile=$OSQUERY_DIR/vajra.flags" "$OSQUERY_DIR/osquery.flags"; then
        echo -e "\e[31m [-] ERROR: Could not point $OSQUERY_DIR/osquery.flags at $OSQUERY_DIR/vajra.flags.\e[0m"
        logError "ERROR" "copy_files_reduced: could not rewrite the vajra.flags path in osquery.flags."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Permissions - readable/writable only by the target user, nothing world-
# or group-readable (unlike /etc/vajra/host_id, which is deliberately
# world-readable so this exact script can read it without root).
# ---------------------------------------------------------------------------
set_permissions_to_binary_reduced() {
    local chown_prefix=()
    if [ "$RUNNING_AS_ROOT" = true ]; then
        chown_prefix=(sudo -u "$TARGET_USER")
    fi

    "${chown_prefix[@]}" chmod +x "$BIN_DIR/osqueryd"
    "${chown_prefix[@]}" chmod 700 "$OSQUERY_DIR"
    "${chown_prefix[@]}" chmod 600 "$OSQUERY_DIR/cert.pem" "$OSQUERY_DIR/enrollment_secret" 2>/dev/null

    logError "INFO" "Set binary/config permissions (reduced mode, user=$TARGET_USER)."
}

# ---------------------------------------------------------------------------
# Service creation (systemd --user)
# ---------------------------------------------------------------------------
create_reduced_mode_service() {
    local user_uid user_systemd_dir
    user_uid=$(id -u "$TARGET_USER" 2>/dev/null)
    if [ -z "$user_uid" ]; then
        echo -e "\e[31m [-] ERROR: Could not resolve uid for user '$TARGET_USER'.\e[0m"
        logError "ERROR" "create_reduced_mode_service: could not resolve uid for $TARGET_USER."
        return 1
    fi
    user_systemd_dir="$TARGET_HOME/.config/systemd/user"

    local as_user=()
    if [ "$RUNNING_AS_ROOT" = true ]; then
        as_user=(sudo -u "$TARGET_USER")
    fi

    "${as_user[@]}" mkdir -p "$user_systemd_dir"

    # get_host_identifier() (vajra_common.sh) reads the world-readable
    # /etc/vajra/host_id cache written by a full-mode install on this same
    # machine (see cache_host_identifier), so reduced mode gets the exact
    # same identifier without needing root itself. If no full-mode install
    # has ever run here, there's no cache yet and this can come back empty -
    # that's a real limitation of reduced mode on a machine that has never
    # once run in full mode, not a bug.
    local stable_host_id
    stable_host_id=$(get_host_identifier)
    if [ -z "$stable_host_id" ]; then
        echo -e "\e[31m [-] ERROR: No cached host identifier found ($HOST_ID_CACHE_FILE) and this machine has no root access to derive one directly.\e[0m"
        echo -e "\e[33m [i] Run a full-mode install (sudo ./vajra_install.sh -install) at least once on this machine first - it caches the identifier reduced mode then reuses.\e[0m"
        logError "ERROR" "get_host_identifier() empty - no cache and no root fallback available (reduced mode)."
        return 1
    fi
    logError "INFO" "Reduced mode: forcing --specified_identifier=$stable_host_id (from $HOST_ID_CACHE_FILE)."

    cat >"/tmp/.vajra_reduced_unit_$$" <<EOF
[Unit]
Description=Vajra MDR Agent (reduced mode - no admin/extension access)
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/osqueryd --verbose --flagfile=$OSQUERY_DIR/osquery.flags --pidfile=$VAR_OSQUERY_DIR/osqueryd.pidfile --database_path=$VAR_OSQUERY_DIR --enroll_secret_path=$OSQUERY_DIR/enrollment_secret --tls_server_certs=$OSQUERY_DIR/cert.pem --host_identifier=specified --specified_identifier=$stable_host_id
Restart=on-failure

[Install]
WantedBy=default.target
EOF

    if [ "$RUNNING_AS_ROOT" = true ]; then
        sudo -u "$TARGET_USER" cp "/tmp/.vajra_reduced_unit_$$" "$user_systemd_dir/vajra.service"
    else
        cp "/tmp/.vajra_reduced_unit_$$" "$user_systemd_dir/vajra.service"
    fi
    rm -f "/tmp/.vajra_reduced_unit_$$"

    loginctl enable-linger "$TARGET_USER" 2>/dev/null

    "${as_user[@]}" env XDG_RUNTIME_DIR="/run/user/$user_uid" systemctl --user daemon-reload
    if "${as_user[@]}" env XDG_RUNTIME_DIR="/run/user/$user_uid" systemctl --user enable --now vajra.service; then
        echo -e "\e[32m [+] Reduced-mode Vajra service started and enabled for user '$TARGET_USER'.\e[0m"
        logError "INFO" "Reduced-mode systemd --user service enabled for $TARGET_USER."
    else
        echo -e "\e[31m [-] ERROR: Failed to start/enable the reduced-mode service for '$TARGET_USER'.\e[0m"
        echo -e "\e[33m [i] This can happen if the user has no active/lingering session. Try: sudo loginctl enable-linger $TARGET_USER\e[0m"
        logError "ERROR" "Failed to enable reduced-mode systemd --user service for $TARGET_USER."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Install orchestration
# ---------------------------------------------------------------------------
install_osquery_reduced() {
    echo -e "\e[32m [+] Installing Vajra client (reduced mode) version $scriptVersion.\e[0m"
    logError "INFO" "Vajra client reduced-mode installation, script version $scriptVersion"

    check_permissions_reduced
    check_package_files
    check_linux_version
    check_vajra_service_not_running_reduced
    cleanup_stale_processes
    create_directories_reduced
    if ! copy_files_reduced; then
        echo -e "\e[31m [-] Aborting installation - rolling back.\e[0m"
        cleanup_partial_install_reduced
        exit 1
    fi
    set_permissions_to_binary_reduced

    if ! create_reduced_mode_service; then
        echo -e "\e[31m [-] Aborting installation - rolling back.\e[0m"
        cleanup_partial_install_reduced
        exit 1
    fi

    echo -e "\e[32m [+] Vajra service installation completed successfully.\e[0m"
    echo -e "\e[33m [i] Mode: REDUCED (no admin access) - running as user '$TARGET_USER', no detection extensions loaded.\e[0m"
    logError "INFO" "Reduced-mode installation completed successfully for $TARGET_USER."
}

# ---------------------------------------------------------------------------
# Uninstall orchestration
# ---------------------------------------------------------------------------
do_uninstall_steps_reduced() {
    local user_uid
    user_uid=$(id -u "$TARGET_USER" 2>/dev/null)

    echo -e "\e[33m [+] Stopping reduced-mode Vajra service\e[0m"
    if [ "$RUNNING_AS_ROOT" = true ] && [ -n "$user_uid" ]; then
        sudo -u "$TARGET_USER" env XDG_RUNTIME_DIR="/run/user/$user_uid" systemctl --user stop vajra.service 2>/dev/null
        sudo -u "$TARGET_USER" env XDG_RUNTIME_DIR="/run/user/$user_uid" systemctl --user disable vajra.service 2>/dev/null
    else
        systemctl --user stop vajra.service 2>/dev/null
        systemctl --user disable vajra.service 2>/dev/null
    fi

    echo -e "\e[33m [+] Removing Vajra files under $TARGET_HOME/.local/share/vajra\e[0m"
    if [ "$RUNNING_AS_ROOT" = true ]; then
        sudo -u "$TARGET_USER" rm -rf "$TARGET_HOME/.local/share/vajra" "$TARGET_HOME/.config/systemd/user/vajra.service"
    else
        rm -rf "$TARGET_HOME/.local/share/vajra" "$TARGET_HOME/.config/systemd/user/vajra.service"
    fi

    echo -e "\e[32m [+] Reduced-mode Vajra installation removed.\e[0m"
    logError "INFO" "Reduced-mode Vajra installation removed for $TARGET_USER."
    echo -e "\e[32mVajra Client uninstallation successful\e[0m"
}

# Used internally when an install fails partway through.
cleanup_partial_install_reduced() {
    echo -e "\e[33m [+] Cleaning up partial installation...\e[0m"
    logError "INFO" "Cleaning up partial installation (reduced mode)."
    do_uninstall_steps_reduced
}

# User-facing uninstall - no token needed, same as full mode.
uninstall_osquery_reduced() {
    echo -e "\e[33m [+] Uninstalling Vajra Client (reduced mode). Please wait ...\e[0m"
    logError "INFO" "Uninstalling Vajra Client (reduced mode)."

    check_permissions_reduced

    if ! is_vajra_installed; then
        echo -e "\e[31m [-] ERROR: Vajra (reduced mode) is not installed for user '$TARGET_USER' - nothing to uninstall.\e[0m"
        logError "ERROR" "Uninstall requested but Vajra (reduced mode) is not installed for $TARGET_USER."
        exit 1
    fi

    do_uninstall_steps_reduced
}

# ---------------------------------------------------------------------------

# ===========================================================================
# DISPATCHER (was vajra_install.sh) + MAIN
# ===========================================================================
# Every entry point below picks the _full or _reduced variant based on
# $EUID, exactly like the old separate dispatcher script did by choosing
# which file to exec into.

install_osquery() {
    if [ "$EUID" -eq 0 ]; then
        INSTALL_MODE="full"
        install_osquery_full
    else
        INSTALL_MODE="reduced"
        install_osquery_reduced
    fi
}

uninstall_osquery() {
    if [ "$EUID" -eq 0 ]; then
        INSTALL_MODE="full"
        uninstall_osquery_full
    else
        INSTALL_MODE="reduced"
        uninstall_osquery_reduced
    fi
}

# ---------------------------------------------------------------------------
# Lightweight status query for GUI/TUI wrappers - prints machine-readable
# output and exits immediately, without running any install/uninstall steps.
# ---------------------------------------------------------------------------
print_installed_status() {
    if [ "$EUID" -eq 0 ]; then
        INSTALL_MODE="full"
        RUNNING_AS_ROOT=true
    else
        INSTALL_MODE="reduced"
        RUNNING_AS_ROOT=false
    fi
    if is_vajra_installed; then
        echo "INSTALLED"
    else
        echo "NOT_INSTALLED"
    fi
}

# ---------------------------------------------------------------------------
# ClamAV integration (-installav) — installs clamd/clamonacc for both distro
# families and applies the RHEL-specific fixes documented for it (LocalSocket,
# /var/lib/clamav ownership race, SELinux fd-passing on Fedora 44+), scopes
# on-access watching to each user's Downloads dir, then restarts vajra.service
# so the agent re-probes for the clamd socket (it only probes at startup).
# ---------------------------------------------------------------------------
setup_clamav() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "\e[31m [-] ERROR: -installav requires root (run with sudo).\e[0m"
        exit 1
    fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        distro_id="${ID:-}"
        distro_like="${ID_LIKE:-}"
    else
        distro_id=""
        distro_like=""
    fi

    is_rhel_family=false
    case " $distro_id $distro_like " in
        *" rhel "*|*" fedora "*|*" centos "*) is_rhel_family=true ;;
    esac

    echo -e "\e[33m [+] Installing ClamAV (distro: ${distro_id:-unknown})...\e[0m"
    logError "INFO" "setup_clamav: starting on distro_id=$distro_id distro_like=$distro_like"

    if [ "$is_rhel_family" = true ]; then
        # -------------------- RHEL / Rocky / Fedora / CentOS Stream --------------------
        dnf install -y clamav clamd clamav-update >> "$LogFile" 2>&1

        # Fix 1: LocalSocket ships commented out - clamd starts but no socket exists.
        sed -i 's|^\s*#\s*\(LocalSocket\s\)|\1|' /etc/clamd.d/scan.conf
        mkdir -p /var/run/clamd.scan

        # Fix 2: /var/lib/clamav is created root:root by clamav-filesystem before the
        # clamupdate sysusers scriptlet creates that user - freshclam can't write to it.
        chown -R clamupdate:clamupdate /var/lib/clamav

        # Fix 3: SELinux blocks clamonacc's --fdpass (SCM_RIGHTS) into clamd's domain
        # on Fedora 44+. Only relevant on Fedora, and only if SELinux is Enforcing.
        if [ "$distro_id" = "fedora" ] && command -v getenforce >/dev/null 2>&1 \
           && [ "$(getenforce)" = "Enforcing" ]; then
            echo -e "\e[33m [+] Fedora + SELinux Enforcing detected - making antivirus_t permissive for fd-passing.\e[0m"
            semanage permissive -a antivirus_t 2>>"$LogFile" || true
            setsebool -P antivirus_can_scan_system 1 2>>"$LogFile" || true
        fi

        systemctl enable --now clamd@scan >> "$LogFile" 2>&1
        systemctl enable --now clamonacc >> "$LogFile" 2>&1

        log_owner="clamscan"
        clamonacc_service="clamonacc"
        clamd_service="clamd@scan"
    else
        # -------------------- Debian / Ubuntu --------------------
        apt-get install -y clamav clamav-daemon >> "$LogFile" 2>&1
        systemctl enable --now clamav-daemon >> "$LogFile" 2>&1
        systemctl enable --now clamav-clamonacc >> "$LogFile" 2>&1

        log_owner="clamav"
        clamonacc_service="clamav-clamonacc"
        clamd_service="clamav-daemon"
    fi

    # Fetch the virus signature database now instead of waiting for freshclam's
    # own schedule - without this clamd can come up with no database at all on
    # a fresh install. Stop the freshclam daemon first so this one-shot run can
    # acquire its lock on the database files, then leave it enabled to keep
    # signatures current going forward. Service name is clamav-freshclam on
    # both Debian and RHEL (the clamav-update package on RHEL ships the same
    # unit name).
    echo -e "\e[33m [+] Fetching initial virus signatures (freshclam) - this can take a few minutes...\e[0m"
    systemctl stop clamav-freshclam >> "$LogFile" 2>&1
    if freshclam --stdout >> "$LogFile" 2>&1; then
        echo -e "\e[32m [+] Signature database downloaded.\e[0m"
    else
        echo -e "\e[33m [-] freshclam initial run failed - the freshclam service will retry automatically.\e[0m"
        logError "WARN" "setup_clamav: initial freshclam run failed."
    fi
    systemctl enable --now clamav-freshclam >> "$LogFile" 2>&1

    # clamonacc refuses to start if its log file doesn't already exist.
    mkdir -p /var/log/clamav
    touch /var/log/clamav/clamonacc.log
    chown "$log_owner:$log_owner" /var/log/clamav/clamonacc.log

    # Scope on-access scanning to each user's Downloads dir (not all of /home -
    # watching everything creates an inotify event storm on interactive systems).
    # Written as a managed block so it can be safely re-run/updated later.
    clamd_conf="/etc/clamd.d/scan.conf"
    [ "$is_rhel_family" = true ] || clamd_conf="/etc/clamav/clamd.conf"

    if [ -f "$clamd_conf" ]; then
        sed -i '/# >>> vajra-edr on-access/,/# <<< vajra-edr on-access/d' "$clamd_conf"
        {
            echo "# >>> vajra-edr on-access"
            # clamonacc refuses to start without at least one Exclude directive -
            # otherwise it can end up watching/scanning its own scan activity in
            # a loop. Excluding root (clamd's own UID) is the standard fix.
            echo "OnAccessExcludeRootUID true"
            for d in /home/*/Downloads /root/Downloads; do
                [ -d "$d" ] && echo "OnAccessIncludePath $d"
            done
            echo "# <<< vajra-edr on-access"
        } >> "$clamd_conf"
    else
        echo -e "\e[31m [-] WARNING: $clamd_conf not found - on-access scope not configured.\e[0m"
        logError "WARN" "setup_clamav: $clamd_conf missing, on-access scope skipped."
    fi

    # If clamonacc is configured (via a systemd drop-in or clamd.conf) to move
    # detections into quarantine, the target dir must exist before it starts -
    # it fails setup entirely otherwise ("Failed to get realpath of ...").
    mkdir -p /root/quarantine
    chmod 700 /root/quarantine

    systemctl restart "$clamd_service" >> "$LogFile" 2>&1
    systemctl restart "$clamonacc_service" >> "$LogFile" 2>&1

    echo -e "\e[32m [+] ClamAV installed and configured (clamd: $clamd_service, on-access: $clamonacc_service).\e[0m"
    logError "INFO" "setup_clamav: complete. clamd_service=$clamd_service clamonacc_service=$clamonacc_service"

    # The agent only probes for the clamd socket at startup (Init()) - if it
    # started before ClamAV existed, it fell back to TCP and never re-probes.
    # Restart it now so it finds the freshly created socket.
    if systemctl list-unit-files vajra.service >/dev/null 2>&1; then
        echo -e "\e[33m [+] Restarting vajra.service so the agent re-probes for the clamd socket...\e[0m"
        # Tamper protection refuses a manual restart; lift it just for this one.
        set_refuse_manual_stop no
        systemctl restart vajra.service
        set_refuse_manual_stop yes
        logError "INFO" "setup_clamav: vajra.service restarted for clamd socket re-probe."
    else
        echo -e "\e[33m [-] vajra.service not found - install Vajra first, then re-run -installav, or restart the agent manually once it is installed.\e[0m"
    fi
}

# ---------------------------------------------------------------------------
# Config hardening (-hardenconfig) - locks down Vajra's on-disk config
# against tampering by any non-root process:
#   - root:root ownership, 600 permissions on every sensitive file
#   - immutable flag (chattr +i) so even root can't modify without
#     explicitly clearing it first
#   - systemd-creds machine-bound encryption for enrollment_secret, where
#     systemd/TPM2 support is available (real encryption, not obfuscation -
#     the encrypted blob is useless if copied to a different machine)
# ---------------------------------------------------------------------------
harden_vajra_config() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "\e[31m [-] ERROR: -hardenconfig requires root (run with sudo).\e[0m"
        exit 1
    fi

    local conf_dir="/etc/osquery"
    local sensitive_files=(
        "$conf_dir/extension.conf"
        "$conf_dir/enrollment_secret"
        "$conf_dir/agent.key"
        "$conf_dir/agent.crt"
        "$conf_dir/osquery.flags"
        "$conf_dir/vajra.flags"
    )

    echo -e "\e[33m [+] Hardening Vajra config files...\e[0m"
    logError "INFO" "harden_vajra_config: starting"

    local f failed=0
    for f in "${sensitive_files[@]}"; do
        if [ -f "$f" ]; then
            # chown/chmod fail on a file an earlier run made immutable: clear
            # the flag first (the step below sets it again).
            chattr -i "$f" 2>/dev/null
            if chown root:root "$f" && chmod 600 "$f"; then
                echo -e "\e[32m [+] Permissions locked: $f (root:root, 600)\e[0m"
            else
                failed=$((failed + 1))
                echo -e "\e[31m [-] Could not set root:root, 600 on $f\e[0m"
                logError "ERROR" "harden_vajra_config: chown/chmod failed on $f"
            fi
        else
            echo -e "\e[33m [-] Skipping (not present): $f\e[0m"
        fi
    done

    if command -v chattr >/dev/null 2>&1; then
        for f in "${sensitive_files[@]}"; do
            if [ -f "$f" ]; then
                if chattr +i "$f" 2>/dev/null; then
                    echo -e "\e[32m [+] Immutable flag set: $f\e[0m"
                else
                    echo -e "\e[33m [-] Could not set immutable flag on $f (filesystem may not support it).\e[0m"
                fi
            fi
        done
        echo -e "\e[33m [+] To edit a locked file later: chattr -i <file>, edit, then chattr +i <file> again.\e[0m"
    else
        echo -e "\e[33m [-] chattr not available - skipping immutable flag step.\e[0m"
    fi

    if command -v systemd-creds >/dev/null 2>&1 && systemd-creds has-tpm2 >/dev/null 2>&1; then
        local secret_src="$conf_dir/enrollment_secret"
        local cred_out="/etc/vajra/enrollment_secret.cred"

        if [ -f "$secret_src" ]; then
            mkdir -p /etc/vajra
            chattr -i "$secret_src" 2>/dev/null || true
            if systemd-creds encrypt "$secret_src" "$cred_out" >> "$LogFile" 2>&1; then
                chmod 600 "$cred_out"
                echo -e "\e[32m [+] enrollment_secret encrypted (machine-bound) -> $cred_out\e[0m"
                echo -e "\e[33m [+] To use this in vajra.service, add under [Service]:\e[0m"
                echo -e "\e[33m       LoadCredentialEncrypted=enrollment_secret:$cred_out\e[0m"
                echo -e "\e[33m     and have the agent read it from \$CREDENTIALS_DIRECTORY/enrollment_secret at\e[0m"
                echo -e "\e[33m     runtime instead of $secret_src directly - that part is an agent code\e[0m"
                echo -e "\e[33m     change, not something this script wires in automatically.\e[0m"
            else
                echo -e "\e[31m [-] systemd-creds encrypt failed - see $LogFile.\e[0m"
            fi
            chattr +i "$secret_src" 2>/dev/null || true
        else
            echo -e "\e[33m [-] $secret_src not found - skipping systemd-creds step.\e[0m"
        fi
    else
        echo -e "\e[33m [-] systemd-creds with TPM2 support not available on this system - skipping.\e[0m"
        echo -e "\e[33m     (Needs systemd 250+ and a TPM2 device/emulator. Permissions + immutable flag\e[0m"
        echo -e "\e[33m     above still apply and are the meaningful protection without this.)\e[0m"
    fi

    if [ "$failed" -gt 0 ]; then
        echo -e "\e[31m [-] Config hardening finished, but $failed file(s) could not be locked down - see above.\e[0m"
        logError "ERROR" "harden_vajra_config: complete with $failed permission failure(s)"
        return 1
    fi
    echo -e "\e[32m [+] Config hardening complete.\e[0m"
    logError "INFO" "harden_vajra_config: complete"
}

if [ $# -eq 0 ] || [ $# -eq 1 ]; then
    if [ "$1" = "-installav" ]; then
        setup_clamav
        exit 0
    elif [ "$1" = "-update-osquery" ]; then
        update_osquery_standalone_full
        exit 0
    elif [ "$1" = "-install" ] || [ "$1" = "" ]; then
        install_osquery
    elif [ "$1" = "-uninstall" ]; then
        uninstall_osquery
    elif [ "$1" = "-installed-status" ]; then
        print_installed_status
    else
        echo -e "\e[31mInvalid argument: $1\e[0m"
        echo -e "\e[31mUsage: $0 [-install | -uninstall | -installav | -update-osquery]\e[0m"
        echo -e "\e[32mIf no option is selected, by default the script will install (full mode if run with sudo, reduced mode otherwise)\e[0m"
        echo -e "\e[32m-update-osquery upgrades osqueryd to the one in this package on an already-installed full-mode host, and puts the old one back if the agent doesn't come up.\e[0m"
        exit 1
    fi
else
    echo -e "\e[32mMultiple arguments provided.\e[0m"
fi

end_time=$(date +%s.%N)
elapsed_time=$(echo "$end_time - $start_time" | bc)
echo "Operation took: $elapsed_time seconds"
