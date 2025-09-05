#!/bin/bash

################################################################################
# volatile-state-02.sh - Production macOS Volatile State Forensic Collection
# Version: 2.0.0-PRODUCTION
# Purpose: Capture volatile system state for forensic analysis
# Compatibility: macOS 10.8+ with bash 3.2
# Classification: FORENSIC EVIDENCE COLLECTION
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Script Constants
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="volatile-state-02.sh"
readonly SCRIPT_PURPOSE="Volatile State Forensic Collection"

# Validate execution environment
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Root privileges required for volatile state collection" >&2
    echo "Usage: sudo $0 <case_id> <examiner> [evidence_path]" >&2
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "ERROR: Insufficient parameters" >&2
    echo "Usage: $0 <case_id> <examiner> [evidence_path]" >&2
    echo "Example: $0 CASE-2025-001 'J.Smith' /Volumes/Evidence" >&2
    exit 1
fi

# Case Parameters
readonly CASE_ID="${1}"
readonly EXAMINER="${2}"
readonly EVIDENCE_PATH="${3:-/Volumes/Evidence}"
readonly ACQUISITION_ID="$(uuidgen)"
readonly ACQUISITION_START="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"

# Validate evidence path
if [ ! -d "$EVIDENCE_PATH" ]; then
    echo "ERROR: Evidence path not accessible: $EVIDENCE_PATH" >&2
    echo "Mount an evidence drive or specify a valid path" >&2
    exit 1
fi

# Output Structure
readonly OUTPUT_ROOT="${EVIDENCE_PATH}/volatile_${CASE_ID}_${ACQUISITION_ID}"
readonly VOLATILE_DIR="${OUTPUT_ROOT}/01_volatile"
readonly NETWORK_DIR="${OUTPUT_ROOT}/02_network"
readonly SECURITY_DIR="${OUTPUT_ROOT}/03_security"
readonly SYSTEM_DIR="${OUTPUT_ROOT}/04_system"
readonly METADATA_DIR="${OUTPUT_ROOT}/00_metadata"
readonly LOG_FILE="${METADATA_DIR}/acquisition.log"
readonly MANIFEST_FILE="${METADATA_DIR}/evidence_manifest.sha256"
readonly CHAIN_FILE="${METADATA_DIR}/chain_of_custody.txt"
readonly ERROR_LOG="${METADATA_DIR}/errors.log"

# Initialize evidence structure with proper permissions
initialize_evidence_structure() {
    mkdir -p "$VOLATILE_DIR" "$NETWORK_DIR" "$SECURITY_DIR" "$SYSTEM_DIR" "$METADATA_DIR"
    chmod 700 "$OUTPUT_ROOT"
    
    # Initialize chain of custody
    cat > "$CHAIN_FILE" <<-EOF
	VOLATILE STATE FORENSIC COLLECTION
	===================================
	Acquisition ID: $ACQUISITION_ID
	Case ID: $CASE_ID
	Examiner: $EXAMINER
	Start Time: $ACQUISITION_START
	Script Version: $SCRIPT_VERSION
	Script Hash: $(shasum -a 256 "$0" | awk '{print $1}')
	
	System Information:
	  Hostname: $(hostname)
	  Model: $(sysctl -n hw.model 2>/dev/null || echo "Unknown")
	  OS Version: $(sw_vers -productVersion 2>/dev/null || echo "Unknown")
	  Kernel: $(uname -r)
	  Architecture: $(uname -m)
	  
	Evidence Location: $OUTPUT_ROOT
	
	COLLECTION LOG:
	--------------
	EOF
    
    # Initialize acquisition log
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG" >&2)
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Volatile state collection initialized"
}

# Enhanced capture function with verification
capture_volatile() {
    local description="$1"
    local output_dir="$2"
    local output_file="$3"
    local command="$4"
    local priority="${5:-NORMAL}"
    
    local full_path="${output_dir}/${output_file}.txt"
    local temp_path="${full_path}.tmp"
    local start_time="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    echo "[${start_time}] Capturing: $description"
    
    # Write metadata header
    cat > "$temp_path" <<-EOF
	================================================================================
	Volatile State Capture: $description
	Timestamp: $start_time
	Priority: $priority
	Command: $command
	================================================================================
	
	EOF
    
    # Execute capture with timeout for volatile operations
    if [ "$priority" = "CRITICAL" ]; then
        # Critical volatile data gets shorter timeout to prevent delays
        timeout 10 bash -c "$command" >> "$temp_path" 2>&1 || {
            local exit_code=$?
            echo "ERROR: Command failed with exit code $exit_code" >> "$temp_path"
            echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] ERROR: Failed to capture $description (exit: $exit_code)" >> "$ERROR_LOG"
        }
    else
        # Normal priority gets standard timeout
        timeout 30 bash -c "$command" >> "$temp_path" 2>&1 || {
            local exit_code=$?
            echo "ERROR: Command failed with exit code $exit_code" >> "$temp_path"
            echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] WARNING: Failed to capture $description (exit: $exit_code)" >> "$ERROR_LOG"
        }
    fi
    
    # Add completion footer
    echo "" >> "$temp_path"
    echo "Capture completed: $(date -u +"%Y-%m-%dT%H:%M:%S%z")" >> "$temp_path"
    
    # Move to final location and calculate hash
    mv "$temp_path" "$full_path"
    local file_hash="$(shasum -a 256 "$full_path" | awk '{print $1}')"
    
    # Record in manifest
    echo "${file_hash}  ${full_path#$OUTPUT_ROOT/}" >> "$MANIFEST_FILE"
    
    # Update chain of custody
    echo "[${start_time}] Collected: $description (${file_hash:0:16}...)" >> "$CHAIN_FILE"
}

# Phase 1: Critical Volatile Data (Must be first)
collect_critical_volatile() {
    echo ""
    echo "=== PHASE 1: CRITICAL VOLATILE DATA ==="
    echo "Priority: CRITICAL - Capturing most volatile system state"
    
    # Network connections (extremely volatile)
    capture_volatile \
        "Active network connections" \
        "$VOLATILE_DIR" \
        "network_connections_active" \
        "netstat -an" \
        "CRITICAL"
    
    capture_volatile \
        "Network connections by process" \
        "$VOLATILE_DIR" \
        "network_connections_process" \
        "lsof -i -n -P" \
        "CRITICAL"
    
    # Process state (highly volatile)
    capture_volatile \
        "Running processes (detailed)" \
        "$VOLATILE_DIR" \
        "processes_detailed" \
        "ps auxww" \
        "CRITICAL"
    
    capture_volatile \
        "Process hierarchy" \
        "$VOLATILE_DIR" \
        "processes_hierarchy" \
        "ps -ef" \
        "CRITICAL"
    
    capture_volatile \
        "Open files and handles" \
        "$VOLATILE_DIR" \
        "open_files" \
        "lsof" \
        "CRITICAL"
    
    # Memory state
    capture_volatile \
        "Virtual memory statistics" \
        "$VOLATILE_DIR" \
        "memory_vmstat" \
        "vm_stat" \
        "CRITICAL"
    
    capture_volatile \
        "System resource snapshot" \
        "$VOLATILE_DIR" \
        "system_snapshot" \
        "top -l 1 -n 0" \
        "CRITICAL"
    
    # Login sessions
    capture_volatile \
        "Active user sessions" \
        "$VOLATILE_DIR" \
        "active_sessions" \
        "w" \
        "CRITICAL"
    
    capture_volatile \
        "Login state" \
        "$VOLATILE_DIR" \
        "login_state" \
        "who -a" \
        "CRITICAL"
}

# Phase 2: Network Configuration (Semi-volatile)
collect_network_configuration() {
    echo ""
    echo "=== PHASE 2: NETWORK CONFIGURATION ==="
    echo "Priority: HIGH - Capturing network state and configuration"
    
    # Interface configuration
    capture_volatile \
        "Network interface configuration" \
        "$NETWORK_DIR" \
        "interfaces" \
        "ifconfig -a" \
        "HIGH"
    
    capture_volatile \
        "Routing table" \
        "$NETWORK_DIR" \
        "routing_table" \
        "netstat -rn" \
        "HIGH"
    
    capture_volatile \
        "ARP cache" \
        "$NETWORK_DIR" \
        "arp_cache" \
        "arp -an" \
        "HIGH"
    
    # DNS configuration
    capture_volatile \
        "DNS resolver configuration" \
        "$NETWORK_DIR" \
        "dns_configuration" \
        "scutil --dns" \
        "NORMAL"
    
    capture_volatile \
        "System proxy configuration" \
        "$NETWORK_DIR" \
        "proxy_configuration" \
        "scutil --proxy" \
        "NORMAL"
    
    # Firewall and packet filter
    capture_volatile \
        "Packet filter status" \
        "$NETWORK_DIR" \
        "pf_status" \
        "pfctl -sa 2>/dev/null || echo 'Packet filter not accessible'" \
        "NORMAL"
    
    capture_volatile \
        "Firewall rules" \
        "$NETWORK_DIR" \
        "firewall_rules" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --listapps 2>/dev/null || echo 'Firewall status unavailable'" \
        "NORMAL"
    
    # Network extensions
    capture_volatile \
        "Network extensions" \
        "$NETWORK_DIR" \
        "network_extensions" \
        "systemextensionsctl list 2>/dev/null || echo 'System extensions not available'" \
        "NORMAL"
    
    # Hardware ports
    capture_volatile \
        "Network hardware ports" \
        "$NETWORK_DIR" \
        "hardware_ports" \
        "networksetup -listallhardwareports 2>/dev/null || echo 'Network setup unavailable'" \
        "NORMAL"
}

# Phase 3: Security and System State
collect_security_state() {
    echo ""
    echo "=== PHASE 3: SECURITY STATE ==="
    echo "Priority: HIGH - Capturing security configuration"
    
    # Kernel and extensions
    capture_volatile \
        "Loaded kernel extensions" \
        "$SECURITY_DIR" \
        "kernel_extensions" \
        "kextstat" \
        "HIGH"
    
    capture_volatile \
        "System Integrity Protection status" \
        "$SECURITY_DIR" \
        "sip_status" \
        "csrutil status" \
        "NORMAL"
    
    # Launch services
    capture_volatile \
        "Launch services" \
        "$SECURITY_DIR" \
        "launch_services" \
        "launchctl list" \
        "HIGH"
    
    capture_volatile \
        "System launch daemons" \
        "$SECURITY_DIR" \
        "launch_daemons_system" \
        "ls -la /Library/LaunchDaemons/ 2>/dev/null || echo 'Not accessible'" \
        "NORMAL"
    
    capture_volatile \
        "System launch agents" \
        "$SECURITY_DIR" \
        "launch_agents_system" \
        "ls -la /Library/LaunchAgents/ 2>/dev/null || echo 'Not accessible'" \
        "NORMAL"
    
    # FileVault and disk encryption
    capture_volatile \
        "FileVault status" \
        "$SECURITY_DIR" \
        "filevault_status" \
        "fdesetup status 2>/dev/null || echo 'FileVault status unavailable'" \
        "NORMAL"
    
    capture_volatile \
        "APFS volumes" \
        "$SECURITY_DIR" \
        "apfs_volumes" \
        "diskutil apfs list 2>/dev/null || diskutil list" \
        "NORMAL"
    
    # Gatekeeper and XProtect
    capture_volatile \
        "Gatekeeper status" \
        "$SECURITY_DIR" \
        "gatekeeper_status" \
        "spctl --status 2>/dev/null || echo 'Gatekeeper status unavailable'" \
        "NORMAL"
    
    capture_volatile \
        "XProtect configuration" \
        "$SECURITY_DIR" \
        "xprotect_status" \
        "system_profiler SPInstallHistoryDataType | grep -A 5 -i xprotect 2>/dev/null || echo 'XProtect information unavailable'" \
        "NORMAL"
    
    # Code signing
    capture_volatile \
        "Code signing authorities" \
        "$SECURITY_DIR" \
        "codesigning_authorities" \
        "security find-identity -p codesigning 2>/dev/null || echo 'No codesigning identities found'" \
        "NORMAL"
}

# Phase 4: System Information
collect_system_information() {
    echo ""
    echo "=== PHASE 4: SYSTEM INFORMATION ==="
    echo "Priority: NORMAL - Capturing system configuration"
    
    # Hardware information
    capture_volatile \
        "Hardware overview" \
        "$SYSTEM_DIR" \
        "hardware_overview" \
        "system_profiler SPHardwareDataType" \
        "NORMAL"
    
    capture_volatile \
        "Software overview" \
        "$SYSTEM_DIR" \
        "software_overview" \
        "system_profiler SPSoftwareDataType" \
        "NORMAL"
    
    # System configuration
    capture_volatile \
        "Kernel parameters" \
        "$SYSTEM_DIR" \
        "kernel_parameters" \
        "sysctl -a 2>/dev/null | head -1000" \
        "NORMAL"
    
    capture_volatile \
        "NVRAM variables" \
        "$SYSTEM_DIR" \
        "nvram_variables" \
        "nvram -p" \
        "NORMAL"
    
    # IO Registry (limited)
    capture_volatile \
        "IO Registry summary" \
        "$SYSTEM_DIR" \
        "ioregistry_summary" \
        "ioreg -l -w 0 | head -5000" \
        "NORMAL"
    
    # Time configuration
    capture_volatile \
        "System time configuration" \
        "$SYSTEM_DIR" \
        "time_configuration" \
        "echo 'Current time: '$(date); echo 'UTC time: '$(date -u); systemsetup -gettimezone 2>/dev/null || echo 'Timezone unavailable'" \
        "NORMAL"
    
    # Power state
    capture_volatile \
        "Power management state" \
        "$SYSTEM_DIR" \
        "power_state" \
        "pmset -g" \
        "NORMAL"
    
    capture_volatile \
        "Thermal state" \
        "$SYSTEM_DIR" \
        "thermal_state" \
        "pmset -g therm" \
        "NORMAL"
}

# Phase 5: User and Account Data
collect_user_data() {
    echo ""
    echo "=== PHASE 5: USER AND ACCOUNT DATA ==="
    echo "Priority: NORMAL - Capturing user account information"
    
    # User accounts
    capture_volatile \
        "Local user accounts" \
        "$SYSTEM_DIR" \
        "local_users" \
        "dscl . list /Users | grep -v '^_'" \
        "NORMAL"
    
    capture_volatile \
        "User login history" \
        "$SYSTEM_DIR" \
        "login_history" \
        "last -20" \
        "NORMAL"
    
    # Installed software
    capture_volatile \
        "Applications directory" \
        "$SYSTEM_DIR" \
        "applications" \
        "ls -la /Applications/ | head -100" \
        "NORMAL"
    
    capture_volatile \
        "Installed packages" \
        "$SYSTEM_DIR" \
        "installed_packages" \
        "pkgutil --pkgs | head -500" \
        "NORMAL"
    
    # Diagnostic logs
    capture_volatile \
        "Recent unified log entries" \
        "$SYSTEM_DIR" \
        "unified_log_recent" \
        "log show --last 5m --style compact 2>/dev/null | head -1000 || echo 'Unified log unavailable'" \
        "NORMAL"
}

# Phase 6: Evidence Integrity
create_evidence_integrity() {
    echo ""
    echo "=== PHASE 6: EVIDENCE INTEGRITY ==="
    echo "Creating integrity verification..."
    
    # Generate file listing
    local file_listing="${METADATA_DIR}/file_listing.txt"
    find "$OUTPUT_ROOT" -type f -not -path "${METADATA_DIR}/*" | sort > "$file_listing"
    
    # Create integrity summary
    local integrity_file="${METADATA_DIR}/integrity_verification.txt"
    cat > "$integrity_file" <<-EOF
	EVIDENCE INTEGRITY VERIFICATION
	================================
	Acquisition ID: $ACQUISITION_ID
	Case ID: $CASE_ID
	
	Collection Statistics:
	  Total files: $(find "$OUTPUT_ROOT" -type f | wc -l | tr -d ' ')
	  Volatile captures: $(find "$VOLATILE_DIR" -type f | wc -l | tr -d ' ')
	  Network captures: $(find "$NETWORK_DIR" -type f | wc -l | tr -d ' ')
	  Security captures: $(find "$SECURITY_DIR" -type f | wc -l | tr -d ' ')
	  System captures: $(find "$SYSTEM_DIR" -type f | wc -l | tr -d ' ')
	  
	Errors encountered: $(wc -l < "$ERROR_LOG" | tr -d ' ')
	
	Manifest verification:
	  To verify all files: shasum -c "$MANIFEST_FILE"
	  
	Evidence location: $OUTPUT_ROOT
	EOF
    
    # Calculate manifest hash
    local manifest_hash="$(shasum -a 256 "$MANIFEST_FILE" | awk '{print $1}')"
    echo "Manifest SHA256: $manifest_hash" >> "$integrity_file"
}

# Finalization
finalize_collection() {
    local acquisition_end="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    echo ""
    echo "=== FINALIZING COLLECTION ==="
    
    # Update chain of custody
    cat >> "$CHAIN_FILE" <<-EOF
	
	COLLECTION COMPLETED
	-------------------
	End Time: $acquisition_end
	Files Collected: $(find "$OUTPUT_ROOT" -type f | wc -l | tr -d ' ')
	Total Size: $(du -sh "$OUTPUT_ROOT" | awk '{print $1}')
	Errors Logged: $(wc -l < "$ERROR_LOG" | tr -d ' ')
	
	VERIFICATION:
	  Manifest: $MANIFEST_FILE
	  Manifest Hash: $(shasum -a 256 "$MANIFEST_FILE" | awk '{print $1}')
	  
	To verify integrity:
	  shasum -c "$MANIFEST_FILE"
	
	Examiner Certification:
	  I certify that this volatile state collection was performed
	  in accordance with forensic best practices.
	  
	  Examiner: ___________________________
	  
	  Date: _______________________________
	  
	  Signature: __________________________
	EOF
    
    # Create summary report
    local summary_file="${OUTPUT_ROOT}/COLLECTION_SUMMARY.txt"
    cat > "$summary_file" <<-EOF
	VOLATILE STATE COLLECTION SUMMARY
	==================================
	
	CASE INFORMATION
	----------------
	Case ID: $CASE_ID
	Examiner: $EXAMINER
	Acquisition ID: $ACQUISITION_ID
	
	COLLECTION TIMELINE
	-------------------
	Start: $ACQUISITION_START
	End: $acquisition_end
	
	SYSTEM INFORMATION
	------------------
	Hostname: $(hostname)
	OS Version: $(sw_vers -productVersion 2>/dev/null || echo "Unknown")
	Kernel: $(uname -r)
	Architecture: $(uname -m)
	
	EVIDENCE COLLECTED
	------------------
	Location: $OUTPUT_ROOT
	Total Files: $(find "$OUTPUT_ROOT" -type f | wc -l | tr -d ' ')
	Total Size: $(du -sh "$OUTPUT_ROOT" | awk '{print $1}')
	
	COLLECTION PHASES
	-----------------
	1. Critical Volatile Data: $(find "$VOLATILE_DIR" -type f | wc -l | tr -d ' ') files
	2. Network Configuration: $(find "$NETWORK_DIR" -type f | wc -l | tr -d ' ') files  
	3. Security State: $(find "$SECURITY_DIR" -type f | wc -l | tr -d ' ') files
	4. System Information: $(find "$SYSTEM_DIR" -type f | wc -l | tr -d ' ') files
	
	VERIFICATION
	------------
	Manifest Location: $MANIFEST_FILE
	Verification Command: shasum -c "$MANIFEST_FILE"
	
	ERRORS AND WARNINGS
	-------------------
	$(if [ -s "$ERROR_LOG" ]; then
	    echo "Errors logged: $(wc -l < "$ERROR_LOG" | tr -d ' ')"
	    echo "See $ERROR_LOG for details"
	else
	    echo "No errors encountered"
	fi)
	
	NEXT STEPS
	----------
	1. Verify evidence integrity using the manifest
	2. Secure the evidence directory
	3. Complete chain of custody documentation
	4. Create working copy for analysis
	5. Preserve original evidence
	EOF
    
    # Display summary
    echo ""
    echo "================================"
    echo "COLLECTION COMPLETE"
    echo "================================"
    echo "Case ID: $CASE_ID"
    echo "Evidence Location: $OUTPUT_ROOT"
    echo "Summary: $summary_file"
    echo "Chain of Custody: $CHAIN_FILE"
    echo "Manifest: $MANIFEST_FILE"
    echo ""
    echo "Files Collected: $(find "$OUTPUT_ROOT" -type f | wc -l | tr -d ' ')"
    echo "Total Size: $(du -sh "$OUTPUT_ROOT" | awk '{print $1}')"
    echo ""
    echo "To verify integrity:"
    echo "  shasum -c '$MANIFEST_FILE'"
    echo ""
    echo "Collection completed at: $acquisition_end"
}

# Main execution
main() {
    echo "================================================"
    echo "VOLATILE STATE FORENSIC COLLECTION v${SCRIPT_VERSION}"
    echo "================================================"
    echo "Case ID: $CASE_ID"
    echo "Examiner: $EXAMINER"
    echo "Evidence Path: $EVIDENCE_PATH"
    echo "Starting: $ACQUISITION_START"
    echo ""
    
    # Initialize evidence structure
    initialize_evidence_structure
    
    # Execute collection phases in forensic order
    collect_critical_volatile
    collect_network_configuration
    collect_security_state
    collect_system_information
    collect_user_data
    
    # Create integrity verification
    create_evidence_integrity
    
    # Finalize collection
    finalize_collection
}

# Trap signals to ensure proper cleanup
trap 'echo "Collection interrupted - partial evidence at: $OUTPUT_ROOT"' INT TERM

# Execute main function
main "$@"

exit 0