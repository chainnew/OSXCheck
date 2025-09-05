#!/bin/bash

################################################################################
# TT04-filesystem-artifacts.sh - Production Filesystem Forensics with Integrity
# Version: 4.0.0-PRODUCTION
# Purpose: Comprehensive filesystem analysis with system integrity verification
# Platform: macOS 10.12+ with bash 3.2 compatibility
# Classification: FORENSIC EVIDENCE COLLECTION - FILESYSTEM ARTIFACTS
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Script Constants
readonly SCRIPT_VERSION="4.0.0-PRODUCTION"
readonly SCRIPT_NAME="TT04-filesystem-artifacts.sh"
readonly SCRIPT_PURPOSE="Filesystem Forensics with Integrity Analysis"
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
readonly OUTPUT_ROOT="${EVIDENCE_PATH}/filesystem_${CASE_ID}_${ACQUISITION_ID}"
readonly INTEGRITY_DIR="${OUTPUT_ROOT}/01_integrity"
readonly BINARIES_DIR="${OUTPUT_ROOT}/02_binaries"
readonly PERSISTENCE_DIR="${OUTPUT_ROOT}/03_persistence"
readonly HIDDEN_DIR="${OUTPUT_ROOT}/04_hidden"
readonly CORRELATION_DIR="${OUTPUT_ROOT}/05_correlation"
readonly KEXT_DIR="${OUTPUT_ROOT}/06_kexts"
readonly LAUNCH_DIR="${OUTPUT_ROOT}/07_launch"
readonly METADATA_DIR="${OUTPUT_ROOT}/00_metadata"
readonly LOG_FILE="${METADATA_DIR}/acquisition.log"
readonly ERROR_LOG="${METADATA_DIR}/errors.log"
readonly MANIFEST_FILE="${METADATA_DIR}/evidence_manifest.sha256"
readonly CHAIN_FILE="${METADATA_DIR}/chain_of_custody.txt"
readonly FINDINGS_FILE="${METADATA_DIR}/findings_summary.txt"

# Critical system binaries for integrity checking
readonly -a CRITICAL_BINARIES=(
    "/usr/bin/lsof" "/usr/bin/ps" "/usr/bin/netstat" "/usr/bin/top"
    "/usr/sbin/sysctl" "/usr/bin/csrutil" "/usr/bin/dtrace" "/usr/bin/nvram"
    "/bin/ls" "/bin/ps" "/sbin/mount" "/usr/sbin/system_profiler"
    "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/dscl" "/usr/bin/kextstat"
)

# Initialize forensic environment
initialize_forensic_environment() {
    # Create evidence structure
    mkdir -p "$INTEGRITY_DIR" "$BINARIES_DIR" "$PERSISTENCE_DIR" "$HIDDEN_DIR"
    mkdir -p "$CORRELATION_DIR" "$KEXT_DIR" "$LAUNCH_DIR" "$METADATA_DIR"
    chmod 700 "$OUTPUT_ROOT"
    
    # Initialize chain of custody
    cat > "$CHAIN_FILE" <<-EOF
	FILESYSTEM FORENSICS WITH INTEGRITY ANALYSIS - CHAIN OF CUSTODY
	================================================================
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
    
    # Initialize findings summary
    cat > "$FINDINGS_FILE" <<-EOF
	FILESYSTEM FORENSICS FINDINGS SUMMARY
	======================================
	Generated: $ACQUISITION_START
	Case ID: $CASE_ID
	
	SYSTEM INTEGRITY STATUS:
	------------------------
	EOF
    
    # Redirect output for logging
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG" >&2)
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Filesystem forensics initialized"
}

# Secure evidence collection function
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
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] WARNING: Failed to collect $description (exit: $exit_code)" >> "$ERROR_LOG"
    fi
    
    # Finalize and hash
    mv "$temp_path" "$full_path"
    local file_hash="$(shasum -a 256 "$full_path" | awk '{print $1}')"
    echo "${file_hash}  ${full_path#$OUTPUT_ROOT/}" >> "$MANIFEST_FILE"
    
    # Update chain of custody
    echo "[$start_time] Collected: $description (${file_hash:0:16}...)" >> "$CHAIN_FILE"
    
    return $exit_code
}

# Phase 1: System Integrity Foundation
analyze_system_integrity() {
    echo ""
    echo "=== PHASE 1: SYSTEM INTEGRITY FOUNDATION ==="
    
    # NVRAM analysis
    collect_evidence \
        "NVRAM configuration" \
        "$INTEGRITY_DIR" \
        "nvram_config" \
        "nvram -p"
    
    collect_evidence \
        "NVRAM XML export" \
        "$INTEGRITY_DIR" \
        "nvram_xml" \
        "nvram -xp"
    
    # SIP status comprehensive check
    collect_evidence \
        "SIP status check" \
        "$INTEGRITY_DIR" \
        "sip_status" \
        "csrutil status; csrutil authenticated-root status 2>/dev/null || echo 'Authenticated root not available'"
    
    # Check for SIP bypass indicators
    local sip_status="$(csrutil status 2>/dev/null || echo 'Unknown')"
    echo "SIP Status: $sip_status" >> "$FINDINGS_FILE"
    
    if echo "$sip_status" | grep -q "disabled"; then
        echo "  WARNING: SIP is DISABLED" >> "$FINDINGS_FILE"
    elif echo "$sip_status" | grep -q "enabled"; then
        echo "  SIP is enabled" >> "$FINDINGS_FILE"
    fi
    
    # Boot arguments analysis
    local boot_args="$(nvram boot-args 2>/dev/null || echo '')"
    if [ -n "$boot_args" ]; then
        echo "Boot Arguments: $boot_args" >> "$FINDINGS_FILE"
        
        # Check for suspicious boot arguments
        if echo "$boot_args" | grep -qE "amfi_get_out_of_my_way|rootless=0|cs_enforcement_disable"; then
            echo "  CRITICAL: Security bypass boot arguments detected" >> "$FINDINGS_FILE"
        fi
    fi
    
    # Kernel security parameters
    collect_evidence \
        "Kernel security parameters" \
        "$INTEGRITY_DIR" \
        "kernel_security" \
        "sysctl -a 2>/dev/null | grep -E 'sip|rootless|csr|amfi|dtrace'"
    
    # rootless.conf analysis
    if [ -f "/System/Library/Sandbox/rootless.conf" ]; then
        collect_evidence \
            "rootless.conf content" \
            "$INTEGRITY_DIR" \
            "rootless_conf" \
            "cat /System/Library/Sandbox/rootless.conf"
        
        # Hash rootless.conf
        local rootless_hash="$(shasum -a 256 /System/Library/Sandbox/rootless.conf | awk '{print $1}')"
        echo "rootless.conf SHA256: $rootless_hash" >> "${INTEGRITY_DIR}/file_hashes.txt"
    fi
}

# Phase 2: Critical Binary Integrity
verify_critical_binaries() {
    echo ""
    echo "=== PHASE 2: CRITICAL BINARY INTEGRITY ==="
    
    local unsigned_count=0
    local invalid_count=0
    
    for binary in "${CRITICAL_BINARIES[@]}"; do
        if [ -f "$binary" ]; then
            # Generate hash
            local hash="$(shasum -a 256 "$binary" | awk '{print $1}')"
            echo "$binary: $hash" >> "${BINARIES_DIR}/binary_hashes.txt"
            
            # Check code signature
            local codesign_output="$(codesign -vv "$binary" 2>&1 || echo '')"
            
            if echo "$codesign_output" | grep -q "code object is not signed"; then
                ((unsigned_count++))
                echo "UNSIGNED: $binary" >> "${BINARIES_DIR}/unsigned_binaries.txt"
            elif echo "$codesign_output" | grep -q "signature invalid"; then
                ((invalid_count++))
                echo "INVALID SIGNATURE: $binary" >> "${BINARIES_DIR}/invalid_signatures.txt"
            fi
            
            # Capture file metadata
            stat -f "%N %p %u %g %z %Sm" "$binary" >> "${BINARIES_DIR}/binary_metadata.txt"
        fi
    done
    
    echo "Critical Binaries Analysis:" >> "$FINDINGS_FILE"
    echo "  Total checked: ${#CRITICAL_BINARIES[@]}" >> "$FINDINGS_FILE"
    echo "  Unsigned: $unsigned_count" >> "$FINDINGS_FILE"
    echo "  Invalid signatures: $invalid_count" >> "$FINDINGS_FILE"
}

# Phase 3: Kernel Extension Analysis
analyze_kernel_extensions() {
    echo ""
    echo "=== PHASE 3: KERNEL EXTENSION ANALYSIS ==="
    
    collect_evidence \
        "Loaded kernel extensions" \
        "$KEXT_DIR" \
        "kextstat" \
        "kextstat"
    
    # Analyze non-Apple kexts
    local non_apple_count=0
    kextstat | while read line; do
        if [[ "$line" =~ ^Index ]]; then
            continue
        fi
        
        local kext_name="$(echo "$line" | sed -n 's/.*(\([^)]*\)).*/\1/p')"
        
        if [ -n "$kext_name" ] && [[ "$kext_name" != *com.apple* ]]; then
            ((non_apple_count++))
            echo "$line" >> "${KEXT_DIR}/non_apple_kexts.txt"
        fi
    done
    
    # Check kext directories
    for dir in "/System/Library/Extensions" "/Library/Extensions"; do
        if [ -d "$dir" ]; then
            collect_evidence \
                "Kernel extensions in $dir" \
                "$KEXT_DIR" \
                "kext_directory_$(basename "$dir")" \
                "ls -la $dir"
            
            # Find non-Apple kexts
            find "$dir" -name "*.kext" -not -path "*/Apple*" 2>/dev/null | while read kext; do
                local kext_id="$(defaults read "$kext/Contents/Info" CFBundleIdentifier 2>/dev/null || echo 'Unknown')"
                local kext_version="$(defaults read "$kext/Contents/Info" CFBundleVersion 2>/dev/null || echo 'Unknown')"
                
                echo "Non-Apple KEXT: $kext" >> "${KEXT_DIR}/third_party_kexts.txt"
                echo "  Identifier: $kext_id" >> "${KEXT_DIR}/third_party_kexts.txt"
                echo "  Version: $kext_version" >> "${KEXT_DIR}/third_party_kexts.txt"
            done
        fi
    done
    
    echo "Kernel Extensions: $non_apple_count non-Apple kexts loaded" >> "$FINDINGS_FILE"
}

# Phase 4: Persistence Mechanism Detection
detect_persistence_mechanisms() {
    echo ""
    echo "=== PHASE 4: PERSISTENCE MECHANISM DETECTION ==="
    
    # System launch daemons
    if [ -d "/Library/LaunchDaemons" ]; then
        collect_evidence \
            "System launch daemons" \
            "$LAUNCH_DIR" \
            "system_daemons" \
            "ls -la /Library/LaunchDaemons"
        
        # Analyze each daemon
        for plist in /Library/LaunchDaemons/*.plist; do
            if [ -f "$plist" ]; then
                local plist_name="$(basename "$plist")"
                local plist_hash="$(shasum -a 256 "$plist" | awk '{print $1}')"
                
                echo "$plist_name: $plist_hash" >> "${LAUNCH_DIR}/daemon_hashes.txt"
                
                # Extract key information
                local label="$(defaults read "$plist" Label 2>/dev/null || echo 'Unknown')"
                
                if [[ "$label" != *com.apple* ]]; then
                    echo "Non-Apple daemon: $plist_name ($label)" >> "${LAUNCH_DIR}/third_party_daemons.txt"
                fi
            fi
        done
    fi
    
    # System launch agents
    if [ -d "/Library/LaunchAgents" ]; then
        collect_evidence \
            "System launch agents" \
            "$LAUNCH_DIR" \
            "system_agents" \
            "ls -la /Library/LaunchAgents"
    fi
    
    # User launch agents
    for userdir in /Users/*; do
        local username="$(basename "$userdir")"
        if [ -d "$userdir/Library/LaunchAgents" ] && [ "$username" != "Shared" ]; then
            collect_evidence \
                "User launch agents for $username" \
                "$LAUNCH_DIR" \
                "user_agents_${username}" \
                "ls -la $userdir/Library/LaunchAgents"
        fi
    done
    
    # Cron jobs
    if [ -f "/etc/crontab" ]; then
        collect_evidence \
            "System crontab" \
            "$PERSISTENCE_DIR" \
            "crontab" \
            "cat /etc/crontab"
    fi
    
    # Login items
    for userdir in /Users/*; do
        local username="$(basename "$userdir")"
        if [ "$username" != "Shared" ]; then
            local loginwindow_plist="$userdir/Library/Preferences/com.apple.loginwindow.plist"
            if [ -f "$loginwindow_plist" ]; then
                collect_evidence \
                    "Login items for $username" \
                    "$PERSISTENCE_DIR" \
                    "login_items_${username}" \
                    "defaults read $loginwindow_plist 2>/dev/null || echo 'Unable to read preferences'"
            fi
        fi
    done
    
    echo "Persistence Mechanisms: Analysis complete" >> "$FINDINGS_FILE"
}

# Phase 5: Hidden and Obfuscated Artifacts
detect_hidden_artifacts() {
    echo ""
    echo "=== PHASE 5: HIDDEN AND OBFUSCATED ARTIFACTS ==="
    
    # Hidden files with dot prefix
    collect_evidence \
        "Hidden files in critical directories" \
        "$HIDDEN_DIR" \
        "dot_files" \
        "find /Applications /Library /System -name '.*' -type f 2>/dev/null | head -100"
    
    # Files with suspicious extensions
    collect_evidence \
        "Files with suspicious extensions" \
        "$HIDDEN_DIR" \
        "suspicious_extensions" \
        "find /Applications /Library -type f \\( -name '*.exe' -o -name '*.dll' -o -name '*.bat' -o -name '*.cmd' -o -name '*.scr' \\) 2>/dev/null"
    
    # Zero-byte files
    collect_evidence \
        "Zero-byte files in system directories" \
        "$HIDDEN_DIR" \
        "zero_byte" \
        "find /Applications /Library -size 0 -type f 2>/dev/null | head -50"
    
    # Extended attributes
    collect_evidence \
        "Files with extended attributes" \
        "$HIDDEN_DIR" \
        "extended_attributes" \
        "find /Applications -type f -exec xattr {} \\; 2>/dev/null | head -100"
    
    # Quarantine attributes
    collect_evidence \
        "Files with quarantine attributes" \
        "$HIDDEN_DIR" \
        "quarantine" \
        "mdfind 'kMDItemWhereFroms == *' 2>/dev/null | head -50"
    
    echo "Hidden Artifacts: Scan complete" >> "$FINDINGS_FILE"
}

# Phase 6: Temporal Correlation Analysis
perform_correlation_analysis() {
    echo ""
    echo "=== PHASE 6: TEMPORAL CORRELATION ANALYSIS ==="
    
    # Files modified in last 24 hours
    collect_evidence \
        "Recently modified files (24h)" \
        "$CORRELATION_DIR" \
        "modified_24h" \
        "find /Applications /Library -type f -mtime -1 2>/dev/null | head -100"
    
    # Files created in last 24 hours
    collect_evidence \
        "Recently created files (24h)" \
        "$CORRELATION_DIR" \
        "created_24h" \
        "find /Applications /Library -type f -ctime -1 2>/dev/null | head -100"
    
    # SUID/SGID files
    collect_evidence \
        "SUID/SGID files" \
        "$CORRELATION_DIR" \
        "suid_sgid" \
        "find /usr /bin /sbin -type f \\( -perm -4000 -o -perm -2000 \\) -ls 2>/dev/null"
    
    # Files not owned by root in system directories
    collect_evidence \
        "Non-root owned files in system directories" \
        "$CORRELATION_DIR" \
        "non_root_system" \
        "find /System /usr /bin /sbin -not -user root 2>/dev/null | head -50"
    
    # World-writable files
    collect_evidence \
        "World-writable files in system directories" \
        "$CORRELATION_DIR" \
        "world_writable" \
        "find /Applications /Library -perm -002 -type f 2>/dev/null | head -50"
    
    echo "Correlation Analysis: Complete" >> "$FINDINGS_FILE"
}

# Phase 7: SIP Verification Testing
perform_sip_verification() {
    echo ""
    echo "=== PHASE 7: SIP VERIFICATION TESTING ==="
    
    local sip_test_results="${INTEGRITY_DIR}/sip_verification_results.txt"
    local test_failures=0
    
    {
        echo "SIP Verification Tests"
        echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%S%z")"
        echo ""
        
        # Test 1: Protected directory write attempt
        echo "Test 1: Protected directory write attempt"
        local test_dir="/System/Library/sip_test_$(date +%s)"
        if mkdir "$test_dir" 2>/dev/null; then
            echo "  FAILED: Created directory in protected location"
            rmdir "$test_dir" 2>/dev/null
            ((test_failures++))
        else
            echo "  PASSED: Directory creation blocked"
        fi
        echo ""
        
        # Test 2: System binary modification attempt
        echo "Test 2: System binary modification attempt"
        if cp /usr/bin/stat /usr/bin/stat.bak 2>/dev/null; then
            echo "  FAILED: Copied system binary"
            rm /usr/bin/stat.bak 2>/dev/null
            ((test_failures++))
        else
            echo "  PASSED: System binary copy blocked"
        fi
        echo ""
        
        # Test 3: Kernel extension validation
        echo "Test 3: Kernel extension validation"
        if kextload /nonexistent.kext 2>&1 | grep -q "failed to load"; then
            echo "  PASSED: Kext validation working"
        else
            echo "  WARNING: Unable to verify kext validation"
        fi
        echo ""
        
        echo "Summary: $test_failures tests failed"
    } > "$sip_test_results"
    
    echo "SIP Verification:" >> "$FINDINGS_FILE"
    if [ $test_failures -eq 0 ]; then
        echo "  All SIP protections appear active" >> "$FINDINGS_FILE"
    else
        echo "  WARNING: $test_failures SIP tests failed - possible bypass" >> "$FINDINGS_FILE"
    fi
}

# Generate forensic report
generate_forensic_report() {
    echo ""
    echo "=== GENERATING FORENSIC REPORT ==="
    
    local report_file="${OUTPUT_ROOT}/FILESYSTEM_FORENSICS_REPORT.md"
    local acquisition_end="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    cat > "$report_file" <<-EOF
	# FILESYSTEM FORENSICS WITH INTEGRITY ANALYSIS REPORT
	
	## Executive Summary
	
	This report documents comprehensive filesystem forensics with system integrity verification performed on a macOS system. The analysis encompasses system integrity foundation assessment, critical binary verification, persistence mechanism detection, hidden artifact discovery, and temporal correlation analysis.
	
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
	
	## System Integrity Analysis
	
	### SIP Status
	
	System Integrity Protection status was assessed through multiple verification methods including csrutil status checks, NVRAM boot argument analysis, and practical verification tests. The complete results are documented in the integrity analysis section.
	
	### Critical Binary Integrity
	
	Analysis of ${#CRITICAL_BINARIES[@]} critical system binaries was performed including hash generation and code signature verification. Any unsigned or invalidly signed binaries have been documented for further investigation.
	
	### Kernel Extensions
	
	All loaded kernel extensions were analyzed with particular attention to non-Apple extensions that may indicate system modifications or third-party security tools. The complete kext analysis is preserved in the kernel extension section.
	
	## Persistence Mechanisms
	
	Multiple persistence vectors were examined including launch daemons, launch agents, cron jobs, and login items. Each mechanism was analyzed for both system-level and user-specific configurations. Non-Apple persistence items have been specifically identified for review.
	
	## Hidden and Obfuscated Artifacts
	
	The filesystem was analyzed for hidden files, suspicious extensions, zero-byte files, and extended attributes that may indicate anti-forensic techniques or malware presence. Quarantine attributes were examined to identify recently downloaded files and their origins.
	
	## Temporal Correlation
	
	Temporal analysis identified recently modified and created files within critical system directories. This correlation helps establish timelines for potential system modifications or compromise activities.
	
	## Evidence Integrity
	
	All collected evidence has been hashed and recorded in the manifest file. To verify integrity:
	
	\`\`\`
	shasum -c "$MANIFEST_FILE"
	\`\`\`
	
	## Recommendations
	
	### Immediate Actions
	
	1. Review all non-Apple kernel extensions and persistence mechanisms
	2. Investigate any critical binaries with invalid signatures
	3. Examine recently modified system files for unauthorized changes
	4. Analyze hidden artifacts for potential malware indicators
	
	### Further Investigation
	
	1. Correlate temporal findings with system logs and user activity
	2. Compare system binary hashes against known-good baselines
	3. Analyze persistence mechanisms for unauthorized additions
	4. Review extended attributes for suspicious metadata
	
	## Conclusion
	
	This filesystem forensic analysis with integrity verification provides comprehensive documentation of system state, potential compromises, and persistence mechanisms. All evidence has been collected following forensic best practices with proper chain of custody documentation.
	
	---
	
	*Generated by TT04 Filesystem Forensics v${SCRIPT_VERSION}*  
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
	  I certify this filesystem forensic collection was conducted
	  in accordance with established forensic procedures.
	  
	  Signature: _______________________
	  
	  Date: ____________________________
	EOF
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Forensic report generated: $report_file"
}

# Finalize evidence package
finalize_evidence() {
    echo ""
    echo "=== FINALIZING EVIDENCE PACKAGE ==="
    
    # Create evidence archive
    local archive_name="${CASE_ID}_filesystem_${ACQUISITION_ID}.tar.gz"
    cd "$(dirname "$OUTPUT_ROOT")" || exit 1
    tar -czf "$archive_name" "$(basename "$OUTPUT_ROOT")"
    cd - > /dev/null || exit 1
    
    local archive_hash="$(shasum -a 256 "$(dirname "$OUTPUT_ROOT")/$archive_name" | awk '{print $1}')"
    
    # Display summary
    echo ""
    echo "=========================================="
    echo "FILESYSTEM FORENSICS COLLECTION COMPLETE"
    echo "=========================================="
    echo "Case ID: $CASE_ID"
    echo "Evidence Location: $OUTPUT_ROOT"
    echo "Archive: $(dirname "$OUTPUT_ROOT")/$archive_name"
    echo "Archive SHA256: $archive_hash"
    echo ""
    echo "Key Findings:"
    grep -E "SIP|Binaries|Extensions|Persistence" "$FINDINGS_FILE" | head -10
    echo ""
    echo "To verify evidence integrity:"
    echo "  shasum -c '$MANIFEST_FILE'"
}

# Main execution
main() {
    echo "================================================"
    echo "FILESYSTEM FORENSICS v${SCRIPT_VERSION}"
    echo "================================================"
    echo "Case ID: $CASE_ID"
    echo "Examiner: $EXAMINER"
    echo ""
    
    # Check for recommended privileges
    if [ "$EUID" -ne 0 ]; then
        echo "WARNING: Running without root privileges"
        echo "Some filesystem analysis will be limited"
        echo "SIP verification tests will be skipped"
        echo ""
    fi
    
    # Initialize environment
    initialize_forensic_environment
    
    # Execute analysis phases
    analyze_system_integrity
    verify_critical_binaries
    analyze_kernel_extensions
    detect_persistence_mechanisms
    detect_hidden_artifacts
    perform_correlation_analysis
    
    # Perform SIP verification only with appropriate privileges
    if [ "$EUID" -eq 0 ]; then
        perform_sip_verification
    else
        echo "SIP Verification: Skipped (requires root)" >> "$FINDINGS_FILE"
    fi
    
    # Generate reports and finalize
    generate_forensic_report
    finalize_evidence
}

# Signal handling for clean termination
trap 'echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Collection interrupted"; exit 130' INT TERM

# Execute main function
main "$@"

exit 0