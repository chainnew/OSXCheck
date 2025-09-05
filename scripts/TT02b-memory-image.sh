#!/bin/bash

################################################################################
# TT02b-memory-forensics.sh - Production SIP-Compliant Memory Forensics
# Version: 2.0.0-PRODUCTION
# Purpose: Memory analysis and injection detection within SIP constraints
# Platform: macOS 10.12+ with System Integrity Protection enabled
# Classification: FORENSIC EVIDENCE COLLECTION - MEMORY ANALYSIS
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Script Constants
readonly SCRIPT_VERSION="2.0.0-PRODUCTION"
readonly SCRIPT_NAME="TT02b-memory-forensics.sh"
readonly SCRIPT_PURPOSE="SIP-Compliant Memory Forensics"
readonly SCRIPT_HASH="$(shasum -a 256 "$0" | awk '{print $1}')"

# Validate execution requirements
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
readonly SIP_STATUS="$(csrutil status 2>/dev/null || echo 'Unknown')"

# Validate evidence path
if [ ! -d "$EVIDENCE_PATH" ]; then
    echo "ERROR: Evidence path not accessible: $EVIDENCE_PATH" >&2
    echo "Mount an evidence drive or specify a valid path" >&2
    exit 1
fi

# Evidence Structure
readonly OUTPUT_ROOT="${EVIDENCE_PATH}/memory_${CASE_ID}_${ACQUISITION_ID}"
readonly MEMORY_DIR="${OUTPUT_ROOT}/01_memory_analysis"
readonly PROCESS_DIR="${OUTPUT_ROOT}/02_process_analysis"
readonly NETWORK_DIR="${OUTPUT_ROOT}/03_network_analysis"
readonly INJECTION_DIR="${OUTPUT_ROOT}/04_injection_detection"
readonly SECURITY_DIR="${OUTPUT_ROOT}/05_security_config"
readonly METADATA_DIR="${OUTPUT_ROOT}/00_metadata"
readonly LOG_FILE="${METADATA_DIR}/acquisition.log"
readonly ERROR_LOG="${METADATA_DIR}/errors.log"
readonly MANIFEST_FILE="${METADATA_DIR}/evidence_manifest.sha256"
readonly CHAIN_FILE="${METADATA_DIR}/chain_of_custody.txt"
readonly FINDINGS_FILE="${METADATA_DIR}/findings_summary.txt"

# Known legitimate JIT processes
readonly -a LEGITIMATE_JIT_PROCESSES=(
    "Safari" "WebKit" "Chrome" "Firefox" "Microsoft Edge"
    "JavaScriptCore" "node" "java" "dotnet" "Python" "ruby"
)

# Initialize forensic environment
initialize_forensic_environment() {
    # Create evidence structure
    mkdir -p "$MEMORY_DIR" "$PROCESS_DIR" "$NETWORK_DIR" "$INJECTION_DIR" "$SECURITY_DIR" "$METADATA_DIR"
    chmod 700 "$OUTPUT_ROOT"
    
    # Initialize chain of custody
    cat > "$CHAIN_FILE" <<-EOF
	SIP-COMPLIANT MEMORY FORENSICS CHAIN OF CUSTODY
	================================================
	Case ID: $CASE_ID
	Acquisition ID: $ACQUISITION_ID
	Examiner: $EXAMINER
	Start Time: $ACQUISITION_START
	
	System Information:
	  Hostname: $HOSTNAME
	  OS Version: $OS_VERSION
	  SIP Status: $SIP_STATUS
	  Architecture: $(uname -m)
	  Kernel: $(uname -r)
	
	Script Information:
	  Version: $SCRIPT_VERSION
	  Hash: $SCRIPT_HASH
	
	Evidence Location: $OUTPUT_ROOT
	
	COLLECTION LOG:
	--------------
	EOF
    
    # Initialize findings summary
    cat > "$FINDINGS_FILE" <<-EOF
	MEMORY FORENSICS FINDINGS SUMMARY
	==================================
	Generated: $ACQUISITION_START
	Case ID: $CASE_ID
	
	CRITICAL FINDINGS:
	------------------
	EOF
    
    # Redirect output for logging
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG" >&2)
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Memory forensics initialized"
}

# Logging function with severity levels
log_message() {
    local severity="$1"
    local message="$2"
    local timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    echo "[$timestamp] [$severity] $message" >> "$LOG_FILE"
    
    case "$severity" in
        CRITICAL)
            echo "[$timestamp] CRITICAL: $message" >> "$FINDINGS_FILE"
            echo "[$timestamp] CRITICAL: $message" >&2
            ;;
        ERROR)
            echo "[$timestamp] ERROR: $message" >> "$ERROR_LOG"
            ;;
        WARNING)
            echo "[$timestamp] WARNING: $message"
            ;;
        INFO)
            echo "[$timestamp] $message"
            ;;
    esac
}

# Secure evidence collection with verification
collect_evidence() {
    local description="$1"
    local output_dir="$2"
    local output_file="$3"
    local command="$4"
    local timeout_seconds="${5:-30}"
    
    local full_path="${output_dir}/${output_file}.txt"
    local temp_path="${full_path}.tmp"
    local start_time="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    log_message "INFO" "Collecting: $description"
    
    # Write metadata header
    {
        echo "Evidence Collection: $description"
        echo "Timestamp: $start_time"
        echo "Command: $command"
        echo "=========================================="
        echo ""
    } > "$temp_path"
    
    # Execute with timeout
    if timeout "$timeout_seconds" bash -c "$command" >> "$temp_path" 2>&1; then
        local exit_code=0
    else
        local exit_code=$?
        echo "Collection failed with exit code: $exit_code" >> "$temp_path"
        log_message "WARNING" "Failed to collect $description (exit: $exit_code)"
    fi
    
    # Finalize and hash
    mv "$temp_path" "$full_path"
    local file_hash="$(shasum -a 256 "$full_path" | awk '{print $1}')"
    echo "${file_hash}  ${full_path#$OUTPUT_ROOT/}" >> "$MANIFEST_FILE"
    
    # Update chain of custody
    echo "[$start_time] Collected: $description (${file_hash:0:16}...)" >> "$CHAIN_FILE"
    
    return $exit_code
}

# System profiling and configuration
collect_system_profile() {
    log_message "INFO" "=== PHASE 1: SYSTEM PROFILING ==="
    
    collect_evidence \
        "Hardware profile" \
        "$METADATA_DIR" \
        "hardware_profile" \
        "system_profiler SPHardwareDataType"
    
    collect_evidence \
        "Software profile" \
        "$METADATA_DIR" \
        "software_profile" \
        "system_profiler SPSoftwareDataType"
    
    collect_evidence \
        "Security configuration" \
        "$SECURITY_DIR" \
        "security_config" \
        "csrutil status; spctl --status; fdesetup status 2>/dev/null || echo 'FileVault unavailable'"
    
    collect_evidence \
        "Kernel parameters" \
        "$METADATA_DIR" \
        "kernel_parameters" \
        "sysctl -a 2>/dev/null | head -5000"
}

# Process memory analysis
analyze_process_memory() {
    log_message "INFO" "=== PHASE 2: PROCESS MEMORY ANALYSIS ==="
    
    local total_processes=0
    local rwx_processes=0
    local unsigned_processes=0
    local suspicious_processes=0
    
    # Analyze all running processes
    for pid in $(ps -A -o pid= 2>/dev/null); do
        [ -z "$pid" ] && continue
        ((total_processes++))
        
        local proc_name="$(ps -p "$pid" -o comm= 2>/dev/null || continue)"
        local proc_user="$(ps -p "$pid" -o user= 2>/dev/null || echo 'unknown')"
        
        # Skip kernel processes
        [ "$proc_name" = "kernel_task" ] && continue
        
        # Attempt memory mapping (may require privileges)
        if [ -x /usr/bin/vmmap ]; then
            local vm_output="$(vmmap "$pid" 2>/dev/null || echo '')"
            
            if [ -n "$vm_output" ]; then
                # Save memory map
                echo "$vm_output" > "${MEMORY_DIR}/pid_${pid}_${proc_name}_vmmap.txt"
                
                # Check for RWX regions
                local rwx_regions="$(echo "$vm_output" | grep -c "rwx/rwx" || echo "0")"
                if [ "$rwx_regions" -gt 0 ]; then
                    ((rwx_processes++))
                    
                    # Check if legitimate JIT process
                    local is_legitimate=false
                    for legit in "${LEGITIMATE_JIT_PROCESSES[@]}"; do
                        if [[ "$proc_name" == *"$legit"* ]]; then
                            is_legitimate=true
                            break
                        fi
                    done
                    
                    if [ "$is_legitimate" = false ]; then
                        ((suspicious_processes++))
                        log_message "WARNING" "Non-JIT process with RWX memory: $proc_name (PID: $pid)"
                        echo "SUSPICIOUS: $proc_name (PID: $pid) - $rwx_regions RWX regions" >> "${INJECTION_DIR}/suspicious_rwx.txt"
                    fi
                fi
                
                # Check for anonymous executable mappings
                if echo "$vm_output" | grep -q "r-x.*\["; then
                    log_message "CRITICAL" "Anonymous executable memory in $proc_name (PID: $pid)"
                    echo "CRITICAL: Anonymous executable memory detected" >> "${INJECTION_DIR}/anonymous_exec.txt"
                    echo "Process: $proc_name (PID: $pid, User: $proc_user)" >> "${INJECTION_DIR}/anonymous_exec.txt"
                fi
            fi
        fi
        
        # Check code signature
        local proc_path="$(lsof -p "$pid" 2>/dev/null | awk '$4=="txt" {print $9}' | head -1)"
        if [ -n "$proc_path" ] && [ -f "$proc_path" ]; then
            local codesign_status="$(codesign -vv "$proc_path" 2>&1 || echo '')"
            
            if echo "$codesign_status" | grep -q "code object is not signed"; then
                ((unsigned_processes++))
                echo "Unsigned: $proc_name (PID: $pid, Path: $proc_path)" >> "${PROCESS_DIR}/unsigned_processes.txt"
            elif echo "$codesign_status" | grep -q "signature invalid"; then
                log_message "CRITICAL" "Invalid signature: $proc_name (PID: $pid)"
                echo "CRITICAL: Invalid signature - $proc_name" >> "${PROCESS_DIR}/invalid_signatures.txt"
            fi
        fi
    done
    
    # Summary statistics
    cat >> "$FINDINGS_FILE" <<-EOF
	
	Process Analysis Summary:
	  Total processes analyzed: $total_processes
	  Processes with RWX memory: $rwx_processes
	  Unsigned processes: $unsigned_processes
	  Suspicious processes: $suspicious_processes
	EOF
}

# Network memory correlation
analyze_network_memory() {
    log_message "INFO" "=== PHASE 3: NETWORK MEMORY ANALYSIS ==="
    
    collect_evidence \
        "Network connections" \
        "$NETWORK_DIR" \
        "network_connections" \
        "netstat -an"
    
    collect_evidence \
        "Network interfaces" \
        "$NETWORK_DIR" \
        "network_interfaces" \
        "ifconfig -a"
    
    collect_evidence \
        "Packet filter status" \
        "$NETWORK_DIR" \
        "packet_filter" \
        "pfctl -sa 2>/dev/null || echo 'Packet filter not accessible'"
    
    # Analyze processes with network connections
    local network_process_count=0
    lsof -i -n -P 2>/dev/null | awk 'NR>1 {print $2}' | sort -u | while read pid; do
        [ -z "$pid" ] && continue
        ((network_process_count++))
        
        local proc_name="$(ps -p "$pid" -o comm= 2>/dev/null || continue)"
        
        # Get connections
        lsof -i -n -P -p "$pid" 2>/dev/null > "${NETWORK_DIR}/pid_${pid}_${proc_name}_connections.txt"
        
        # Check for RWX memory in network processes
        if [ -x /usr/bin/vmmap ]; then
            local rwx_check="$(vmmap "$pid" 2>/dev/null | grep -c "rwx" || echo "0")"
            
            if [ "$rwx_check" -gt 0 ]; then
                log_message "WARNING" "Network process with RWX memory: $proc_name (PID: $pid)"
                echo "Network RWX: $proc_name (PID: $pid) - $rwx_check regions" >> "${NETWORK_DIR}/network_rwx_processes.txt"
            fi
        fi
    done
}

# Injection detection analysis
detect_injection_patterns() {
    log_message "INFO" "=== PHASE 4: INJECTION DETECTION ==="
    
    # Check for DYLD injection
    local dyld_count=0
    for pid in $(ps -A -o pid= 2>/dev/null | head -50); do
        [ -z "$pid" ] && continue
        
        local environ="$(ps -E -p "$pid" 2>/dev/null | grep -E "DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH" || echo '')"
        if [ -n "$environ" ]; then
            ((dyld_count++))
            log_message "CRITICAL" "DYLD injection detected in PID $pid"
            echo "PID $pid: $environ" >> "${INJECTION_DIR}/dyld_injection.txt"
        fi
    done
    
    # Check for suspicious library loads
    collect_evidence \
        "Loaded libraries analysis" \
        "$INJECTION_DIR" \
        "loaded_libraries" \
        "lsof | grep -E '\.dylib|\.so' | head -1000"
    
    # Check launch agents/daemons for persistence
    collect_evidence \
        "Launch agents" \
        "$INJECTION_DIR" \
        "launch_agents" \
        "ls -la /Library/LaunchAgents /System/Library/LaunchAgents 2>/dev/null"
    
    collect_evidence \
        "Launch daemons" \
        "$INJECTION_DIR" \
        "launch_daemons" \
        "ls -la /Library/LaunchDaemons /System/Library/LaunchDaemons 2>/dev/null"
    
    # Check for hidden processes
    local ps_count="$(ps -A | wc -l)"
    local lsof_count="$(lsof | awk '{print $2}' | sort -u | wc -l)"
    
    if [ "$lsof_count" -gt "$ps_count" ]; then
        local difference=$((lsof_count - ps_count))
        log_message "WARNING" "Possible hidden processes detected: $difference discrepancy"
    fi
    
    echo "DYLD injection attempts: $dyld_count" >> "$FINDINGS_FILE"
}

# SkyWalk framework analysis
analyze_skywalk() {
    log_message "INFO" "=== PHASE 5: SKYWALK ANALYSIS ==="
    
    if command -v skywalkctl &> /dev/null; then
        collect_evidence \
            "SkyWalk overview" \
            "$NETWORK_DIR" \
            "skywalk_overview" \
            "skywalkctl show"
        
        collect_evidence \
            "SkyWalk statistics" \
            "$NETWORK_DIR" \
            "skywalk_stats" \
            "skywalkctl stats"
        
        collect_evidence \
            "SkyWalk channels" \
            "$NETWORK_DIR" \
            "skywalk_channels" \
            "skywalkctl channel"
    else
        log_message "WARNING" "SkyWalk tools not available"
    fi
}

# Private Relay detection
detect_private_relay() {
    log_message "INFO" "=== PHASE 6: PRIVATE RELAY DETECTION ==="
    
    collect_evidence \
        "Proxy configuration" \
        "$NETWORK_DIR" \
        "proxy_config" \
        "scutil --proxy"
    
    collect_evidence \
        "DNS configuration" \
        "$NETWORK_DIR" \
        "dns_config" \
        "scutil --dns"
    
    # Check for Private Relay indicators
    local private_relay_detected=false
    
    if networksetup -getsecurewebproxy Wi-Fi 2>/dev/null | grep -q "proxy"; then
        private_relay_detected=true
        log_message "INFO" "Private Relay proxy configuration detected"
    fi
    
    if [ -d "/Applications/Utilities/Private Relay.app" ]; then
        private_relay_detected=true
        log_message "INFO" "Private Relay application found"
    fi
    
    if [ "$private_relay_detected" = true ]; then
        echo "Private Relay: DETECTED" >> "$FINDINGS_FILE"
    else
        echo "Private Relay: NOT DETECTED" >> "$FINDINGS_FILE"
    fi
}

# Critical system process verification
verify_critical_processes() {
    log_message "INFO" "=== PHASE 7: CRITICAL PROCESS VERIFICATION ==="
    
    local critical_processes=("launchd" "kernel_task" "WindowServer" "loginwindow" "securityd")
    
    for process in "${critical_processes[@]}"; do
        local pids="$(pgrep -x "$process" || echo '')"
        
        if [ -z "$pids" ]; then
            log_message "CRITICAL" "Critical process not running: $process"
            echo "MISSING: $process" >> "${PROCESS_DIR}/critical_processes.txt"
        else
            for pid in $pids; do
                # Verify process integrity
                local proc_path="$(lsof -p "$pid" 2>/dev/null | awk '$4=="txt" {print $9}' | head -1)"
                
                if [ -n "$proc_path" ] && [ -f "$proc_path" ]; then
                    local hash="$(shasum -a 256 "$proc_path" | awk '{print $1}')"
                    echo "$process (PID: $pid): $hash" >> "${PROCESS_DIR}/critical_processes.txt"
                    
                    # Check signature
                    if ! codesign -vv "$proc_path" 2>/dev/null; then
                        log_message "CRITICAL" "Critical process signature invalid: $process"
                    fi
                fi
            done
        fi
    done
}

# Generate forensic report
generate_forensic_report() {
    log_message "INFO" "=== GENERATING FORENSIC REPORT ==="
    
    local report_file="${OUTPUT_ROOT}/MEMORY_FORENSICS_REPORT.md"
    local acquisition_end="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    cat > "$report_file" <<-EOF
	# SIP-COMPLIANT MEMORY FORENSICS REPORT
	
	## Executive Summary
	
	This report documents a System Integrity Protection (SIP) compliant memory forensics analysis conducted on a macOS system. Due to SIP restrictions, full physical memory acquisition was not possible. However, comprehensive analysis was performed using alternative methodologies to identify memory anomalies, potential injections, and security violations.
	
	## Case Information
	
	- **Case ID**: $CASE_ID
	- **Examiner**: $EXAMINER
	- **Acquisition ID**: $ACQUISITION_ID
	- **Analysis Period**: $ACQUISITION_START to $acquisition_end
	
	## System Information
	
	- **Hostname**: $HOSTNAME
	- **OS Version**: $OS_VERSION
	- **SIP Status**: $SIP_STATUS
	- **Architecture**: $(uname -m)
	- **Kernel Version**: $(uname -r)
	
	## Key Findings
	
	$(cat "$FINDINGS_FILE")
	
	## Memory Analysis Results
	
	### Process Memory Anomalies
	
	The analysis examined $(ps -A | wc -l) running processes for memory anomalies including:
	
	- Read-Write-Execute (RWX) memory regions
	- Anonymous executable mappings
	- Code signature violations
	- Injection indicators
	
	$(if [ -f "${INJECTION_DIR}/suspicious_rwx.txt" ]; then
	    echo "#### Suspicious RWX Regions"
	    echo '```'
	    head -20 "${INJECTION_DIR}/suspicious_rwx.txt"
	    echo '```'
	fi)
	
	$(if [ -f "${INJECTION_DIR}/anonymous_exec.txt" ]; then
	    echo "#### Anonymous Executable Memory"
	    echo '```'
	    cat "${INJECTION_DIR}/anonymous_exec.txt"
	    echo '```'
	fi)
	
	### Network Process Analysis
	
	Analysis of processes with active network connections revealed:
	
	$(if [ -f "${NETWORK_DIR}/network_rwx_processes.txt" ]; then
	    echo "#### Network Processes with RWX Memory"
	    echo '```'
	    cat "${NETWORK_DIR}/network_rwx_processes.txt"
	    echo '```'
	fi)
	
	### Injection Detection
	
	$(if [ -f "${INJECTION_DIR}/dyld_injection.txt" ]; then
	    echo "#### DYLD Injection Attempts"
	    echo '```'
	    cat "${INJECTION_DIR}/dyld_injection.txt"
	    echo '```'
	fi)
	
	## Recommendations
	
	### Immediate Actions
	
	1. Investigate all processes with anonymous executable memory regions
	2. Verify integrity of unsigned and invalidly signed processes
	3. Examine network connections from processes with memory anomalies
	4. Review DYLD injection attempts if detected
	
	### Further Investigation
	
	1. Correlate findings with system and application logs
	2. Perform timeline analysis of suspicious process creation
	3. Compare process baselines with known-good systems
	4. Consider full forensic imaging if critical findings warrant
	
	## Evidence Integrity
	
	All collected evidence has been hashed and recorded in the manifest file. To verify integrity:
	
	\`\`\`
	shasum -c "$MANIFEST_FILE"
	\`\`\`
	
	## Limitations
	
	This analysis was conducted within the constraints of System Integrity Protection (SIP):
	
	- Full physical memory dumps were not obtained
	- Kernel memory access was restricted
	- Some system processes could not be fully analyzed
	- Direct memory injection detection was limited to indirect indicators
	
	## Conclusion
	
	This SIP-compliant memory forensics analysis represents the most comprehensive investigation possible within system constraints. All findings should be considered in conjunction with other forensic artifacts and system logs for complete incident reconstruction.
	
	---
	
	*Generated by TT02b Memory Forensics v${SCRIPT_VERSION}*  
	*Report created: $(date)*
	EOF
    
    # Update chain of custody
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
	  I certify this memory forensics analysis was conducted
	  in accordance with established forensic procedures.
	  
	  Signature: _______________________
	  
	  Date: ____________________________
	EOF
    
    log_message "INFO" "Forensic report generated: $report_file"
}

# Finalize evidence package
finalize_evidence() {
    log_message "INFO" "=== FINALIZING EVIDENCE PACKAGE ==="
    
    # Generate file hashes
    find "$OUTPUT_ROOT" -type f -name "*.txt" -o -name "*.log" -o -name "*.md" | while read -r file; do
        shasum -a 256 "$file" >> "${METADATA_DIR}/complete_hashes.sha256"
    done
    
    # Create evidence archive
    local archive_name="${CASE_ID}_memory_${ACQUISITION_ID}.tar.gz"
    cd "$(dirname "$OUTPUT_ROOT")" || exit 1
    tar -czf "$archive_name" "$(basename "$OUTPUT_ROOT")"
    cd - > /dev/null || exit 1
    
    local archive_hash="$(shasum -a 256 "$(dirname "$OUTPUT_ROOT")/$archive_name" | awk '{print $1}')"
    
    # Display summary
    echo ""
    echo "=========================================="
    echo "MEMORY FORENSICS COLLECTION COMPLETE"
    echo "=========================================="
    echo "Case ID: $CASE_ID"
    echo "Evidence Location: $OUTPUT_ROOT"
    echo "Archive: $(dirname "$OUTPUT_ROOT")/$archive_name"
    echo "Archive SHA256: $archive_hash"
    echo ""
    echo "Critical Findings: $(grep -c "CRITICAL" "$FINDINGS_FILE" 2>/dev/null || echo "0")"
    echo "Warnings: $(grep -c "WARNING" "$LOG_FILE" 2>/dev/null || echo "0")"
    echo ""
    echo "To verify evidence integrity:"
    echo "  shasum -c '$MANIFEST_FILE'"
}

# Main execution
main() {
    echo "================================================"
    echo "SIP-COMPLIANT MEMORY FORENSICS v${SCRIPT_VERSION}"
    echo "================================================"
    echo "Case ID: $CASE_ID"
    echo "Examiner: $EXAMINER"
    echo ""
    
    # Check for recommended privileges
    if [ "$EUID" -ne 0 ]; then
        echo "WARNING: Running without root privileges"
        echo "Some memory analysis capabilities will be limited"
        echo "For complete analysis, run with: sudo $0"
        echo ""
        read -p "Continue with limited analysis? (y/n): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    
    # Initialize environment
    initialize_forensic_environment
    
    # Execute analysis phases
    collect_system_profile
    analyze_process_memory
    analyze_network_memory
    detect_injection_patterns
    analyze_skywalk
    detect_private_relay
    verify_critical_processes
    
    # Generate reports and finalize
    generate_forensic_report
    finalize_evidence
}

# Signal handling for clean termination
trap 'log_message "ERROR" "Collection interrupted"; exit 130' INT TERM

# Execute main function
main "$@"

exit 0