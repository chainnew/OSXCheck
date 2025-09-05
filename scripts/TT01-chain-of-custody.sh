#!/bin/bash

################################################################################
# TT01 Chain of Custody - Forensic Data Collection Script for macOS
# Version: 1.0.0-PRODUCTION
# Purpose: Forensically sound system state documentation and evidence collection
# Compliance: Designed to maintain chain of custody for legal proceedings
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Script metadata
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="TT01-chain-of-custody.sh"
readonly SCRIPT_HASH=$(shasum -a 256 "$0" | awk '{print $1}')

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root for complete data collection." >&2
    echo "Use: sudo $0 [case_number] [examiner_name]" >&2
    exit 1
fi

# Validate command line arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <case_number> <examiner_name> [description]" >&2
    echo "Example: $0 CASE-2025-001 'John Doe' 'Routine security audit'" >&2
    exit 1
fi

# Case information
readonly CASE_NUMBER="$1"
readonly EXAMINER_NAME="$2"
readonly CASE_DESCRIPTION="${3:-No description provided}"
readonly ACQUISITION_START=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
readonly ACQUISITION_ID=$(uuidgen)

# Output configuration
readonly OUTPUT_BASE="/Volumes/Evidence"
readonly OUTPUT_DIR="${OUTPUT_BASE}/${CASE_NUMBER}_${ACQUISITION_ID}"
readonly VOLATILE_DIR="${OUTPUT_DIR}/volatile"
readonly PERSISTENT_DIR="${OUTPUT_DIR}/persistent"
readonly METADATA_DIR="${OUTPUT_DIR}/metadata"
readonly LOG_FILE="${OUTPUT_DIR}/acquisition.log"
readonly MANIFEST_FILE="${OUTPUT_DIR}/manifest.sha256"
readonly CHAIN_FILE="${OUTPUT_DIR}/chain_of_custody.txt"

# Create secure output structure
create_output_structure() {
    if [ ! -d "$OUTPUT_BASE" ]; then
        echo "ERROR: Evidence volume not mounted at $OUTPUT_BASE" >&2
        echo "Please mount an external drive at $OUTPUT_BASE before running this script" >&2
        exit 1
    fi
    
    mkdir -p "$VOLATILE_DIR" "$PERSISTENT_DIR" "$METADATA_DIR"
    chmod 700 "$OUTPUT_DIR"
    
    # Initialize chain of custody documentation
    cat > "$CHAIN_FILE" <<EOF
CHAIN OF CUSTODY RECORD
=======================
Acquisition ID: $ACQUISITION_ID
Case Number: $CASE_NUMBER
Examiner: $EXAMINER_NAME
Description: $CASE_DESCRIPTION
Start Time: $ACQUISITION_START
Script Version: $SCRIPT_VERSION
Script Hash: $SCRIPT_HASH
System: $(uname -a)
Hostname: $(hostname)
EOF
}

# Logging function with timestamps and hash recording
log_action() {
    local message="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Function to collect data with error handling and hash verification
collect_with_verification() {
    local description="$1"
    local output_file="$2"
    local command="$3"
    
    log_action "Collecting: $description"
    
    local temp_file="${output_file}.tmp"
    local start_time=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
    
    # Execute collection command with error handling
    if eval "$command" > "$temp_file" 2>&1; then
        mv "$temp_file" "$output_file"
        local file_hash=$(shasum -a 256 "$output_file" | awk '{print $1}')
        local end_time=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
        
        # Record in manifest
        echo "${file_hash}  ${output_file#$OUTPUT_DIR/}" >> "$MANIFEST_FILE"
        
        # Log success with metadata
        cat >> "$METADATA_DIR/collection_metadata.json" <<EOF
{
  "description": "$description",
  "file": "${output_file#$OUTPUT_DIR/}",
  "hash_sha256": "$file_hash",
  "start_time": "$start_time",
  "end_time": "$end_time",
  "status": "success"
},
EOF
        log_action "Successfully collected: $description (SHA256: ${file_hash:0:16}...)"
    else
        local error_code=$?
        rm -f "$temp_file"
        log_action "WARNING: Failed to collect $description (error code: $error_code)"
        
        # Record failure in metadata
        cat >> "$METADATA_DIR/collection_metadata.json" <<EOF
{
  "description": "$description",
  "file": "${output_file#$OUTPUT_DIR/}",
  "start_time": "$start_time",
  "status": "failed",
  "error_code": $error_code
},
EOF
    fi
}

# Phase 1: Volatile Data Collection (Order matters for forensic validity)
collect_volatile_data() {
    log_action "=== PHASE 1: VOLATILE DATA COLLECTION ==="
    
    # Network connections (most volatile)
    collect_with_verification \
        "Active network connections" \
        "$VOLATILE_DIR/netstat_an.txt" \
        "netstat -an"
    
    collect_with_verification \
        "Network interface configuration" \
        "$VOLATILE_DIR/ifconfig.txt" \
        "ifconfig -a"
    
    collect_with_verification \
        "Network routing table" \
        "$VOLATILE_DIR/netstat_rn.txt" \
        "netstat -rn"
    
    collect_with_verification \
        "ARP cache" \
        "$VOLATILE_DIR/arp.txt" \
        "arp -an"
    
    # Process information
    collect_with_verification \
        "Running processes" \
        "$VOLATILE_DIR/ps_auxww.txt" \
        "ps auxww"
    
    collect_with_verification \
        "Process tree" \
        "$VOLATILE_DIR/pstree.txt" \
        "ps axjf 2>/dev/null || ps axj"
    
    collect_with_verification \
        "Open files and network connections by process" \
        "$VOLATILE_DIR/lsof_full.txt" \
        "lsof -n -P"
    
    # Memory and system state
    collect_with_verification \
        "Memory statistics" \
        "$VOLATILE_DIR/vm_stat.txt" \
        "vm_stat"
    
    collect_with_verification \
        "System resource snapshot" \
        "$VOLATILE_DIR/top_snapshot.txt" \
        "top -l 1 -n 0"
    
    collect_with_verification \
        "Kernel extensions" \
        "$VOLATILE_DIR/kextstat.txt" \
        "kextstat"
    
    # Current system time (for correlation)
    collect_with_verification \
        "System time and timezone" \
        "$VOLATILE_DIR/time_info.txt" \
        "echo 'Date: '$(date); echo 'UTC: '$(date -u); echo 'Timezone: '$(systemsetup -gettimezone 2>/dev/null || echo 'Unknown')"
}

# Phase 2: System Configuration
collect_system_configuration() {
    log_action "=== PHASE 2: SYSTEM CONFIGURATION ==="
    
    collect_with_verification \
        "System profiler - Hardware" \
        "$PERSISTENT_DIR/system_hardware.txt" \
        "system_profiler SPHardwareDataType"
    
    collect_with_verification \
        "System profiler - Software" \
        "$PERSISTENT_DIR/system_software.txt" \
        "system_profiler SPSoftwareDataType"
    
    collect_with_verification \
        "Disk configuration" \
        "$PERSISTENT_DIR/diskutil_list.txt" \
        "diskutil list"
    
    collect_with_verification \
        "Mounted filesystems" \
        "$PERSISTENT_DIR/mount.txt" \
        "mount"
    
    collect_with_verification \
        "Disk usage" \
        "$PERSISTENT_DIR/df.txt" \
        "df -h"
    
    # Security configuration
    collect_with_verification \
        "System Integrity Protection status" \
        "$PERSISTENT_DIR/csrutil_status.txt" \
        "csrutil status"
    
    collect_with_verification \
        "Firmware variables" \
        "$PERSISTENT_DIR/nvram.txt" \
        "nvram -p"
    
    collect_with_verification \
        "Firewall configuration" \
        "$PERSISTENT_DIR/firewall_status.txt" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getallowsigned --getallowsignedapp --getstealthmode"
    
    collect_with_verification \
        "Gatekeeper status" \
        "$PERSISTENT_DIR/gatekeeper_status.txt" \
        "spctl --status"
}

# Phase 3: User and Account Information
collect_user_information() {
    log_action "=== PHASE 3: USER AND ACCOUNT INFORMATION ==="
    
    collect_with_verification \
        "User accounts" \
        "$PERSISTENT_DIR/users.txt" \
        "dscl . list /Users | while read user; do echo \"=== User: \$user ===\"; dscl . read /Users/\$user; done"
    
    collect_with_verification \
        "Group membership" \
        "$PERSISTENT_DIR/groups.txt" \
        "dscl . list /Groups | while read group; do echo \"=== Group: \$group ===\"; dscl . read /Groups/\$group; done"
    
    collect_with_verification \
        "Currently logged in users" \
        "$VOLATILE_DIR/who.txt" \
        "who -a"
    
    collect_with_verification \
        "Last login information" \
        "$PERSISTENT_DIR/last.txt" \
        "last -100"
}

# Phase 4: Persistence Mechanisms
collect_persistence_mechanisms() {
    log_action "=== PHASE 4: PERSISTENCE MECHANISMS ==="
    
    # System-wide launch items
    collect_with_verification \
        "System LaunchDaemons" \
        "$PERSISTENT_DIR/launchdaemons_system.txt" \
        "ls -la@eO /Library/LaunchDaemons/ 2>/dev/null; echo '---'; ls -la@eO /System/Library/LaunchDaemons/ 2>/dev/null"
    
    collect_with_verification \
        "System LaunchAgents" \
        "$PERSISTENT_DIR/launchagents_system.txt" \
        "ls -la@eO /Library/LaunchAgents/ 2>/dev/null; echo '---'; ls -la@eO /System/Library/LaunchAgents/ 2>/dev/null"
    
    # User launch items (for each user)
    collect_with_verification \
        "User LaunchAgents" \
        "$PERSISTENT_DIR/launchagents_users.txt" \
        "for user_home in /Users/*; do echo \"=== \$user_home ===\"; ls -la@eO \"\$user_home/Library/LaunchAgents/\" 2>/dev/null || echo 'Not found'; done"
    
    # Login items
    collect_with_verification \
        "Login items" \
        "$PERSISTENT_DIR/login_items.txt" \
        "osascript -e 'tell application \"System Events\" to get the properties of every login item' 2>/dev/null || echo 'Unable to retrieve'"
}

# Phase 5: Installed Software
collect_installed_software() {
    log_action "=== PHASE 5: INSTALLED SOFTWARE ==="
    
    collect_with_verification \
        "Applications directory listing" \
        "$PERSISTENT_DIR/applications.txt" \
        "ls -la@eO /Applications/"
    
    collect_with_verification \
        "Installed packages" \
        "$PERSISTENT_DIR/pkgutil_packages.txt" \
        "pkgutil --pkgs"
    
    # Collect code signatures for running processes
    collect_with_verification \
        "Code signatures of running processes" \
        "$VOLATILE_DIR/codesign_processes.txt" \
        "ps aux | awk '{print \$11}' | grep -v COMMAND | sort -u | while read proc; do echo \"=== \$proc ===\"; codesign -dvvv \"\$proc\" 2>&1 || echo 'Not signed or not found'; done"
}

# Phase 6: Log Collection
collect_system_logs() {
    log_action "=== PHASE 6: SYSTEM LOG COLLECTION ==="
    
    collect_with_verification \
        "Unified log (last 24 hours)" \
        "$PERSISTENT_DIR/unified_log_24h.txt" \
        "log show --last 24h --style compact"
    
    collect_with_verification \
        "System log" \
        "$PERSISTENT_DIR/system_log.txt" \
        "tail -n 10000 /var/log/system.log 2>/dev/null || echo 'System log not available'"
    
    collect_with_verification \
        "Installation log" \
        "$PERSISTENT_DIR/install_log.txt" \
        "tail -n 10000 /var/log/install.log 2>/dev/null || echo 'Install log not available'"
}

# Phase 7: Hash Critical System Files
hash_critical_files() {
    log_action "=== PHASE 7: CRITICAL FILE HASHING ==="
    
    # Define critical directories to hash
    local critical_paths=(
        "/usr/bin"
        "/usr/sbin"
        "/bin"
        "/sbin"
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
        "/System/Library/LaunchDaemons"
        "/System/Library/LaunchAgents"
    )
    
    for path in "${critical_paths[@]}"; do
        if [ -d "$path" ]; then
            local safe_name=$(echo "$path" | tr '/' '_')
            collect_with_verification \
                "File hashes for $path" \
                "$PERSISTENT_DIR/hashes${safe_name}.txt" \
                "find '$path' -type f -exec shasum -a 256 {} + 2>/dev/null | head -1000"
        fi
    done
}

# Finalize collection and create verification
finalize_collection() {
    log_action "=== FINALIZING COLLECTION ==="
    
    # Close metadata JSON array
    echo "]" >> "$METADATA_DIR/collection_metadata.json"
    
    # Record acquisition end time
    local acquisition_end=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
    
    # Update chain of custody
    cat >> "$CHAIN_FILE" <<EOF

End Time: $acquisition_end
Total Files Collected: $(find "$OUTPUT_DIR" -type f | wc -l)
Manifest Hash: $(shasum -a 256 "$MANIFEST_FILE" | awk '{print $1}')

VERIFICATION INSTRUCTIONS:
To verify integrity of collected data:
1. Check manifest hash matches above
2. Run: shasum -c "$MANIFEST_FILE"
3. All files should report "OK"

Examiner Signature: ____________________
Date: ____________________
EOF
    
    # Create final archive with compression
    log_action "Creating evidence archive..."
    local archive_name="${CASE_NUMBER}_${ACQUISITION_ID}.tar.gz"
    tar -czf "${OUTPUT_BASE}/${archive_name}" -C "$OUTPUT_DIR" .
    
    # Generate final archive hash
    local archive_hash=$(shasum -a 256 "${OUTPUT_BASE}/${archive_name}" | awk '{print $1}')
    
    # Create verification file
    cat > "${OUTPUT_BASE}/${CASE_NUMBER}_verification.txt" <<EOF
Evidence Archive Verification
==============================
Archive: ${archive_name}
SHA256: ${archive_hash}
Created: $(date -u +"%Y-%m-%dT%H:%M:%S%z")
Examiner: $EXAMINER_NAME
Case: $CASE_NUMBER

To verify: shasum -a 256 ${archive_name}
Expected: ${archive_hash}
EOF
    
    log_action "Collection complete. Archive: ${OUTPUT_BASE}/${archive_name}"
    log_action "Archive SHA256: ${archive_hash}"
}

# Main execution flow
main() {
    echo "TT01 Chain of Custody - Forensic Data Collection"
    echo "================================================"
    echo "Case Number: $CASE_NUMBER"
    echo "Examiner: $EXAMINER_NAME"
    echo "Starting at: $ACQUISITION_START"
    echo ""
    
    # Initialize output structure
    create_output_structure
    
    # Initialize metadata JSON
    echo "[" > "$METADATA_DIR/collection_metadata.json"
    
    # Execute collection phases in forensically sound order
    collect_volatile_data
    collect_system_configuration
    collect_user_information
    collect_persistence_mechanisms
    collect_installed_software
    collect_system_logs
    hash_critical_files
    
    # Finalize and package
    finalize_collection
    
    echo ""
    echo "COLLECTION SUMMARY"
    echo "=================="
    echo "Evidence Location: ${OUTPUT_BASE}/${CASE_NUMBER}_${ACQUISITION_ID}.tar.gz"
    echo "Verification File: ${OUTPUT_BASE}/${CASE_NUMBER}_verification.txt"
    echo "Please sign and secure the chain of custody document."
}

# Execute main function
main "$@"

exit 0