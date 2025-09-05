#!/bin/bash

################################################################################
# TT06-persistence-mechanisms.sh - Production Persistence Mechanism Forensics
# Version: 6.0.0-PRODUCTION
# Purpose: Comprehensive persistence mechanism detection and analysis for macOS
# Platform: macOS 10.12+ with bash 3.2 compatibility
# Classification: FORENSIC EVIDENCE COLLECTION - PERSISTENCE MECHANISMS
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Script Constants
readonly SCRIPT_VERSION="6.0.0-PRODUCTION"
readonly SCRIPT_NAME="TT06-persistence-mechanisms.sh"
readonly SCRIPT_PURPOSE="Persistence Mechanism Forensic Collection"
readonly SCRIPT_HASH="$(shasum -a 256 "$0" | awk '{print $1}')"

# Validate execution parameters
if [ $# -lt 2 ]; then
    echo "ERROR: Insufficient parameters for forensic collection" >&2
    echo "Usage: $0 <case_id> <examiner> [evidence_path]" >&2
    echo "Example: $0 CASE-2025-001 'J.Smith' /Volumes/Evidence" >&2
    exit 1
fi

# Forensic Case Parameters
readonly CASE_ID="${1}"
readonly EXAMINER="${2}"
readonly EVIDENCE_PATH="${3:-/Volumes/Evidence}"
readonly ACQUISITION_ID="$(uuidgen)"
readonly ACQUISITION_START="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
readonly HOSTNAME="$(hostname)"
readonly OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo 'Unknown')"

# Validate evidence path
if [ ! -d "$EVIDENCE_PATH" ]; then
    echo "ERROR: Evidence path not accessible: $EVIDENCE_PATH" >&2
    echo "Mount an evidence drive or specify a valid path" >&2
    exit 1
fi

# Evidence Structure
readonly OUTPUT_ROOT="${EVIDENCE_PATH}/persistence_${CASE_ID}_${ACQUISITION_ID}"
readonly LAUNCH_DIR="${OUTPUT_ROOT}/01_launch_services"
readonly KEXT_DIR="${OUTPUT_ROOT}/02_kernel_extensions"
readonly LOGIN_DIR="${OUTPUT_ROOT}/03_login_items"
readonly CRON_DIR="${OUTPUT_ROOT}/04_scheduled_tasks"
readonly ACCOUNT_DIR="${OUTPUT_ROOT}/05_accounts"
readonly SSH_DIR="${OUTPUT_ROOT}/06_ssh_persistence"
readonly METADATA_DIR="${OUTPUT_ROOT}/00_metadata"
readonly LOG_FILE="${METADATA_DIR}/acquisition.log"
readonly ERROR_LOG="${METADATA_DIR}/errors.log"
readonly MANIFEST_FILE="${METADATA_DIR}/evidence_manifest.sha256"
readonly CHAIN_FILE="${METADATA_DIR}/chain_of_custody.txt"
readonly FINDINGS_FILE="${METADATA_DIR}/findings_summary.txt"

# Initialize forensic environment
initialize_forensic_environment() {
    mkdir -p "$LAUNCH_DIR" "$KEXT_DIR" "$LOGIN_DIR" "$CRON_DIR" "$ACCOUNT_DIR" "$SSH_DIR" "$METADATA_DIR"
    chmod 700 "$OUTPUT_ROOT"
    
    cat > "$CHAIN_FILE" <<-EOF
	PERSISTENCE MECHANISM FORENSIC COLLECTION - CHAIN OF CUSTODY
	============================================================
	Case ID: $CASE_ID
	Acquisition ID: $ACQUISITION_ID
	Examiner: $EXAMINER
	Start Time: $ACQUISITION_START
	
	System Information:
	  Hostname: $HOSTNAME
	  OS Version: $OS_VERSION
	  Architecture: $(uname -m)
	  Kernel: $(uname -r)
	
	Script Information:
	  Version: $SCRIPT_VERSION
	  Hash: $SCRIPT_HASH
	
	Evidence Location: $OUTPUT_ROOT
	
	COLLECTION LOG:
	--------------
	EOF
    
    cat > "$FINDINGS_FILE" <<-EOF
	PERSISTENCE MECHANISM FINDINGS
	==============================
	Generated: $ACQUISITION_START
	Case ID: $CASE_ID
	
	PERSISTENCE ANALYSIS:
	--------------------
	EOF
    
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG" >&2)
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Persistence forensics initialized"
}

# Secure evidence collection
collect_evidence() {
    local description="$1"
    local output_dir="$2"
    local output_file="$3"
    local command="$4"
    local timeout_seconds="${5:-60}"
    
    local full_path="${output_dir}/${output_file}.txt"
    local temp_path="${full_path}.tmp"
    local start_time="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Collecting: $description"
    
    {
        echo "Evidence Collection: $description"
        echo "Timestamp: $start_time"
        echo "Command: $command"
        echo "=========================================="
        echo ""
    } > "$temp_path"
    
    if timeout "$timeout_seconds" bash -c "$command" >> "$temp_path" 2>&1; then
        local exit_code=0
    else
        local exit_code=$?
        echo "Collection failed with exit code: $exit_code" >> "$temp_path"
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] WARNING: Failed to collect $description (exit: $exit_code)" >> "$ERROR_LOG"
    fi
    
    mv "$temp_path" "$full_path"
    local file_hash="$(shasum -a 256 "$full_path" | awk '{print $1}')"
    echo "${file_hash}  ${full_path#$OUTPUT_ROOT/}" >> "$MANIFEST_FILE"
    echo "[$start_time] Collected: $description (${file_hash:0:16}...)" >> "$CHAIN_FILE"
    
    return $exit_code
}

# Get list of non-system users
get_user_list() {
    ls /Users 2>/dev/null | grep -v -E "Shared|.localized|Guest" || echo ""
}

# Phase 1: Launch Services Analysis
analyze_launch_services() {
    echo ""
    echo "=== PHASE 1: LAUNCH SERVICES ANALYSIS ==="
    
    local daemon_count=0
    local agent_count=0
    local suspicious_count=0
    
    # System launch daemons
    collect_evidence \
        "System launch daemons" \
        "$LAUNCH_DIR" \
        "system_daemons" \
        "ls -la /Library/LaunchDaemons 2>/dev/null; echo '---'; ls -la /System/Library/LaunchDaemons 2>/dev/null | head -50"
    
    # Analyze each daemon
    for plist in /Library/LaunchDaemons/*.plist 2>/dev/null; do
        if [ -f "$plist" ]; then
            ((daemon_count++))
            local plist_name="$(basename "$plist")"
            local label="$(defaults read "$plist" Label 2>/dev/null || echo 'Unknown')"
            
            if [[ "$label" != *com.apple* ]]; then
                echo "Non-Apple daemon: $plist_name" >> "${LAUNCH_DIR}/third_party_daemons.txt"
                ((suspicious_count++))
            fi
            
            local hash="$(shasum -a 256 "$plist" | awk '{print $1}')"
            echo "$plist_name: $hash" >> "${LAUNCH_DIR}/daemon_hashes.txt"
        fi
    done
    
    # System launch agents
    collect_evidence \
        "System launch agents" \
        "$LAUNCH_DIR" \
        "system_agents" \
        "ls -la /Library/LaunchAgents 2>/dev/null; echo '---'; ls -la /System/Library/LaunchAgents 2>/dev/null | head -50"
    
    # User launch agents
    for user in $(get_user_list); do
        if [ -d "/Users/$user/Library/LaunchAgents" ]; then
            ((agent_count++))
            collect_evidence \
                "User launch agents: $user" \
                "$LAUNCH_DIR" \
                "user_agents_${user}" \
                "ls -la /Users/$user/Library/LaunchAgents"
        fi
    done
    
    # Active launch services
    collect_evidence \
        "Active launch services" \
        "$LAUNCH_DIR" \
        "active_services" \
        "launchctl list | grep -v 'com.apple' | head -50"
    
    # Privileged helper tools
    if [ -d "/Library/PrivilegedHelperTools" ]; then
        collect_evidence \
            "Privileged helper tools" \
            "$LAUNCH_DIR" \
            "privileged_helpers" \
            "ls -la /Library/PrivilegedHelperTools"
    fi
    
    echo "Launch Services:" >> "$FINDINGS_FILE"
    echo "  Daemons: $daemon_count" >> "$FINDINGS_FILE"
    echo "  Agents: $agent_count" >> "$FINDINGS_FILE"
    echo "  Non-Apple: $suspicious_count" >> "$FINDINGS_FILE"
}

# Phase 2: Kernel and System Extensions
analyze_extensions() {
    echo ""
    echo "=== PHASE 2: KERNEL AND SYSTEM EXTENSIONS ==="
    
    local kext_count=0
    local non_apple_kext=0
    
    # Loaded kernel extensions
    collect_evidence \
        "Loaded kernel extensions" \
        "$KEXT_DIR" \
        "kextstat" \
        "kextstat"
    
    # Count non-Apple kexts
    kextstat 2>/dev/null | while read line; do
        if [[ "$line" =~ ^Index ]]; then
            continue
        fi
        local kext_name="$(echo "$line" | sed -n 's/.*(\([^)]*\)).*/\1/p')"
        if [ -n "$kext_name" ] && [[ "$kext_name" != *com.apple* ]]; then
            ((non_apple_kext++))
            echo "$line" >> "${KEXT_DIR}/non_apple_kexts.txt"
        fi
    done
    
    # System extensions
    if command -v systemextensionsctl &> /dev/null; then
        collect_evidence \
            "System extensions" \
            "$KEXT_DIR" \
            "system_extensions" \
            "systemextensionsctl list"
    fi
    
    # Kernel extension directories
    collect_evidence \
        "Kernel extension directories" \
        "$KEXT_DIR" \
        "kext_directories" \
        "ls -la /System/Library/Extensions 2>/dev/null | head -50; echo '---'; ls -la /Library/Extensions"
    
    echo "Kernel Extensions:" >> "$FINDINGS_FILE"
    echo "  Non-Apple KEXTs: $non_apple_kext" >> "$FINDINGS_FILE"
}

# Phase 3: Login Items
analyze_login_items() {
    echo ""
    echo "=== PHASE 3: LOGIN ITEMS ==="
    
    local login_items_found=0
    
    # System login items
    collect_evidence \
        "System login items" \
        "$LOGIN_DIR" \
        "system_login_items" \
        "defaults read /Library/Preferences/com.apple.loginitems 2>/dev/null || echo 'No system login items'"
    
    # User login items
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            local plist="/Users/$user/Library/Preferences/com.apple.loginitems.plist"
            if [ -f "$plist" ]; then
                ((login_items_found++))
                collect_evidence \
                    "Login items: $user" \
                    "$LOGIN_DIR" \
                    "login_items_${user}" \
                    "plutil -p '$plist' 2>/dev/null | head -100"
            fi
            
            # Login window preferences
            collect_evidence \
                "Login window: $user" \
                "$LOGIN_DIR" \
                "loginwindow_${user}" \
                "defaults read /Users/$user/Library/Preferences/com.apple.loginwindow 2>/dev/null | head -50"
        fi
    done
    
    # Startup items (legacy)
    if [ -d "/Library/StartupItems" ]; then
        collect_evidence \
            "Startup items" \
            "$LOGIN_DIR" \
            "startup_items" \
            "ls -la /Library/StartupItems"
    fi
    
    echo "Login Items: $login_items_found users with login items" >> "$FINDINGS_FILE"
}

# Phase 4: Scheduled Tasks
analyze_scheduled_tasks() {
    echo ""
    echo "=== PHASE 4: SCHEDULED TASKS ==="
    
    local cron_users=0
    
    # System crontab
    if [ -f "/etc/crontab" ]; then
        collect_evidence \
            "System crontab" \
            "$CRON_DIR" \
            "system_crontab" \
            "cat /etc/crontab"
    fi
    
    # User crontabs
    for user in $(get_user_list); do
        local user_crontab="/usr/lib/cron/tabs/$user"
        if [ -f "$user_crontab" ]; then
            ((cron_users++))
            collect_evidence \
                "Crontab: $user" \
                "$CRON_DIR" \
                "crontab_${user}" \
                "cat '$user_crontab'"
            
            # Check for suspicious entries
            if grep -qE "curl|wget|nc|/tmp" "$user_crontab" 2>/dev/null; then
                echo "SUSPICIOUS: Crontab for $user contains network/temp commands" >> "${CRON_DIR}/suspicious_cron.txt"
            fi
        fi
    done
    
    # Periodic tasks
    collect_evidence \
        "Periodic tasks" \
        "$CRON_DIR" \
        "periodic_tasks" \
        "ls -la /etc/periodic 2>/dev/null; echo '---'; ls -la /etc/periodic/daily 2>/dev/null | head -20"
    
    # LaunchD timers
    collect_evidence \
        "LaunchD timers" \
        "$CRON_DIR" \
        "launchd_timers" \
        "find /Library/LaunchDaemons /Library/LaunchAgents -name '*.plist' -exec grep -l 'StartInterval\\|StartCalendarInterval' {} \\; 2>/dev/null | head -20"
    
    echo "Scheduled Tasks: $cron_users users with crontabs" >> "$FINDINGS_FILE"
}

# Phase 5: Account and SSH Persistence
analyze_account_persistence() {
    echo ""
    echo "=== PHASE 5: ACCOUNT AND SSH PERSISTENCE ==="
    
    local admin_count=0
    local ssh_users=0
    
    # User accounts
    collect_evidence \
        "User accounts" \
        "$ACCOUNT_DIR" \
        "user_accounts" \
        "dscl . list /Users"
    
    # Admin accounts
    collect_evidence \
        "Admin accounts" \
        "$ACCOUNT_DIR" \
        "admin_accounts" \
        "dseditgroup -o read admin"
    
    # Count admins
    for user in $(dseditgroup -o read admin 2>/dev/null | grep -A 999 "GroupMembership:" | grep -v "GroupMembership:" || echo ""); do
        ((admin_count++))
    done
    
    # Hidden accounts check
    dscl . list /Users 2>/dev/null | while read user; do
        if [[ "$user" =~ ^[._] ]] && [[ "$user" != "_*" ]]; then
            echo "Potential hidden account: $user" >> "${ACCOUNT_DIR}/hidden_accounts.txt"
        fi
    done
    
    # SSH keys
    for user in $(get_user_list); do
        if [ -d "/Users/$user/.ssh" ]; then
            ((ssh_users++))
            collect_evidence \
                "SSH directory: $user" \
                "$SSH_DIR" \
                "ssh_${user}" \
                "ls -la /Users/$user/.ssh"
            
            if [ -f "/Users/$user/.ssh/authorized_keys" ]; then
                collect_evidence \
                    "Authorized keys: $user" \
                    "$SSH_DIR" \
                    "authorized_keys_${user}" \
                    "wc -l /Users/$user/.ssh/authorized_keys; echo '---'; head -10 /Users/$user/.ssh/authorized_keys"
            fi
        fi
    done
    
    # Sudoers
    if [ -f "/etc/sudoers" ]; then
        collect_evidence \
            "Sudoers file" \
            "$ACCOUNT_DIR" \
            "sudoers" \
            "grep -v '^#' /etc/sudoers | grep -v '^$'"
    fi
    
    if [ -d "/etc/sudoers.d" ]; then
        collect_evidence \
            "Sudoers directory" \
            "$ACCOUNT_DIR" \
            "sudoers_d" \
            "ls -la /etc/sudoers.d"
    fi
    
    echo "Account Persistence:" >> "$FINDINGS_FILE"
    echo "  Admin accounts: $admin_count" >> "$FINDINGS_FILE"
    echo "  Users with SSH: $ssh_users" >> "$FINDINGS_FILE"
}

# Generate forensic report
generate_forensic_report() {
    echo ""
    echo "=== GENERATING FORENSIC REPORT ==="
    
    local report_file="${OUTPUT_ROOT}/PERSISTENCE_FORENSICS_REPORT.md"
    local acquisition_end="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    cat > "$report_file" <<-EOF
	# PERSISTENCE MECHANISM FORENSIC REPORT
	
	## Executive Summary
	
	This report documents comprehensive persistence mechanism analysis performed on a macOS system. The collection identifies launch services, kernel/system extensions, login items, scheduled tasks, and account-based persistence mechanisms suitable for forensic investigation.
	
	## Case Information
	
	- **Case ID**: $CASE_ID
	- **Examiner**: $EXAMINER
	- **Acquisition ID**: $ACQUISITION_ID
	- **Analysis Period**: $ACQUISITION_START to $acquisition_end
	
	## System Information
	
	- **Hostname**: $HOSTNAME
	- **OS Version**: $OS_VERSION
	- **Architecture**: $(uname -m)
	- **Kernel Version**: $(uname -r)
	
	## Key Findings
	
	$(cat "$FINDINGS_FILE")
	
	## Persistence Mechanisms Identified
	
	### Launch Services
	Analysis of launch daemons, agents, and privileged helper tools. Non-Apple services have been specifically identified for review. All plist files have been hashed for integrity verification.
	
	### Kernel and System Extensions
	Loaded kernel extensions and modern system extensions documented. Non-Apple extensions flagged for additional scrutiny as potential persistence vectors.
	
	### Login Items
	User and system login items collected across all accounts. Legacy startup items checked for completeness.
	
	### Scheduled Tasks
	Crontabs, periodic tasks, and LaunchD timers analyzed. Suspicious commands in scheduled tasks flagged for investigation.
	
	### Account Persistence
	Administrative accounts, SSH configurations, and sudoers modifications documented. Hidden accounts and unauthorized SSH keys identified where present.
	
	## Evidence Integrity
	
	All collected evidence has been hashed and recorded in the manifest file:
	
	\`\`\`
	shasum -c "$MANIFEST_FILE"
	\`\`\`
	
	## Recommendations
	
	1. Review all non-Apple launch services for legitimacy
	2. Investigate any unsigned or third-party kernel extensions
	3. Examine scheduled tasks containing network commands
	4. Verify all administrative accounts are authorized
	5. Audit SSH authorized_keys for unknown entries
	
	---
	
	*Generated by TT06 Persistence Forensics v${SCRIPT_VERSION}*  
	*Report created: $(date)*
	EOF
    
    cat >> "$CHAIN_FILE" <<-EOF
	
	COLLECTION COMPLETED
	-------------------
	End Time: $acquisition_end
	Total Files: $(find "$OUTPUT_ROOT" -type f | wc -l)
	Evidence Size: $(du -sh "$OUTPUT_ROOT" | awk '{print $1}')
	
	Verification:
	  Manifest: $MANIFEST_FILE
	  Manifest Hash: $(shasum -a 256 "$MANIFEST_FILE" | awk '{print $1}')
	
	Examiner Certification:
	  I certify this persistence mechanism forensic collection was conducted
	  in accordance with established forensic procedures.
	  
	  Signature: _______________________
	  
	  Date: ____________________________
	EOF
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Forensic report generated: $report_file"
}

# Finalize evidence
finalize_evidence() {
    echo ""
    echo "=== FINALIZING EVIDENCE PACKAGE ==="
    
    local archive_name="${CASE_ID}_persistence_${ACQUISITION_ID}.tar.gz"
    cd "$(dirname "$OUTPUT_ROOT")" || exit 1
    tar -czf "$archive_name" "$(basename "$OUTPUT_ROOT")"
    cd - > /dev/null || exit 1
    
    local archive_hash="$(shasum -a 256 "$(dirname "$OUTPUT_ROOT")/$archive_name" | awk '{print $1}')"
    
    echo ""
    echo "=========================================="
    echo "PERSISTENCE FORENSICS COLLECTION COMPLETE"
    echo "=========================================="
    echo "Case ID: $CASE_ID"
    echo "Evidence Location: $OUTPUT_ROOT"
    echo "Archive: $(dirname "$OUTPUT_ROOT")/$archive_name"
    echo "Archive SHA256: $archive_hash"
    echo ""
    grep -E ":" "$FINDINGS_FILE" | head -10
    echo ""
    echo "To verify evidence integrity:"
    echo "  shasum -c '$MANIFEST_FILE'"
}

# Main execution
main() {
    echo "================================================"
    echo "PERSISTENCE MECHANISM FORENSICS v${SCRIPT_VERSION}"
    echo "================================================"
    echo "Case ID: $CASE_ID"
    echo "Examiner: $EXAMINER"
    echo ""
    
    initialize_forensic_environment
    
    analyze_launch_services
    analyze_extensions
    analyze_login_items
    analyze_scheduled_tasks
    analyze_account_persistence
    
    generate_forensic_report
    finalize_evidence
}

trap 'echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Collection interrupted"; exit 130' INT TERM

main "$@"

exit 0