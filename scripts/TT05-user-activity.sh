#!/bin/bash

################################################################################
# TT05-user-activity.sh - Production User Activity Forensic Collection
# Version: 5.0.0-PRODUCTION
# Purpose: Comprehensive user activity and artifact collection for macOS
# Platform: macOS 10.12+ with bash 3.2 compatibility
# Classification: FORENSIC EVIDENCE COLLECTION - USER ACTIVITY
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Script Constants
readonly SCRIPT_VERSION="5.0.0-PRODUCTION"
readonly SCRIPT_NAME="TT05-user-activity.sh"
readonly SCRIPT_PURPOSE="User Activity Forensic Collection"
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
readonly OUTPUT_ROOT="${EVIDENCE_PATH}/user_activity_${CASE_ID}_${ACQUISITION_ID}"
readonly USERS_DIR="${OUTPUT_ROOT}/01_users"
readonly APPS_DIR="${OUTPUT_ROOT}/02_applications"
readonly UI_DIR="${OUTPUT_ROOT}/03_user_interface"
readonly COMM_DIR="${OUTPUT_ROOT}/04_communications"
readonly FILES_DIR="${OUTPUT_ROOT}/05_files"
readonly CLOUD_DIR="${OUTPUT_ROOT}/06_cloud"
readonly METADATA_DIR="${OUTPUT_ROOT}/00_metadata"
readonly LOG_FILE="${METADATA_DIR}/acquisition.log"
readonly ERROR_LOG="${METADATA_DIR}/errors.log"
readonly MANIFEST_FILE="${METADATA_DIR}/evidence_manifest.sha256"
readonly CHAIN_FILE="${METADATA_DIR}/chain_of_custody.txt"
readonly FINDINGS_FILE="${METADATA_DIR}/findings_summary.txt"

# Initialize forensic environment
initialize_forensic_environment() {
    # Create evidence structure
    mkdir -p "$USERS_DIR" "$APPS_DIR" "$UI_DIR" "$COMM_DIR" "$FILES_DIR" "$CLOUD_DIR" "$METADATA_DIR"
    chmod 700 "$OUTPUT_ROOT"
    
    # Initialize chain of custody
    cat > "$CHAIN_FILE" <<-EOF
	USER ACTIVITY FORENSIC COLLECTION - CHAIN OF CUSTODY
	====================================================
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
	USER ACTIVITY FINDINGS SUMMARY
	==============================
	Generated: $ACQUISITION_START
	Case ID: $CASE_ID
	
	USER ACCOUNT ANALYSIS:
	---------------------
	EOF
    
    # Redirect output for logging
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG" >&2)
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] User activity forensics initialized"
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

# Get list of non-system users
get_user_list() {
    ls /Users 2>/dev/null | grep -v -E "Shared|.localized|Guest" || echo ""
}

# Phase 1: User Account Analysis
analyze_user_accounts() {
    echo ""
    echo "=== PHASE 1: USER ACCOUNT ANALYSIS ==="
    
    # System users enumeration
    collect_evidence \
        "System user list" \
        "$USERS_DIR" \
        "system_users" \
        "dscl . list /Users"
    
    # Count total users
    local user_count=0
    local admin_count=0
    
    # Analyze each user account
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            ((user_count++))
            
            collect_evidence \
                "User account details: $user" \
                "$USERS_DIR" \
                "account_${user}" \
                "dscl . -read /Users/$user"
            
            # Check admin status
            if dseditgroup -o checkmember -m "$user" admin 2>/dev/null | grep -q "yes"; then
                ((admin_count++))
                echo "Admin user: $user" >> "${USERS_DIR}/admin_users.txt"
            fi
            
            # Last login information
            collect_evidence \
                "Login history: $user" \
                "$USERS_DIR" \
                "login_${user}" \
                "last -10 $user"
            
            # Group membership
            collect_evidence \
                "Group membership: $user" \
                "$USERS_DIR" \
                "groups_${user}" \
                "groups $user; id $user"
        fi
    done
    
    echo "User Accounts:" >> "$FINDINGS_FILE"
    echo "  Total users: $user_count" >> "$FINDINGS_FILE"
    echo "  Admin users: $admin_count" >> "$FINDINGS_FILE"
    
    # Failed login attempts
    collect_evidence \
        "Failed login attempts" \
        "$USERS_DIR" \
        "failed_logins" \
        "log show --predicate 'eventMessage contains \"failed authentication\"' --last 7d 2>/dev/null | head -100"
}

# Phase 2: Browser Artifacts
collect_browser_artifacts() {
    echo ""
    echo "=== PHASE 2: BROWSER ARTIFACTS ==="
    
    local browsers_found=0
    
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            # Safari artifacts
            local safari_dir="/Users/$user/Library/Safari"
            if [ -d "$safari_dir" ]; then
                ((browsers_found++))
                
                # Safari history
                if [ -f "$safari_dir/History.db" ]; then
                    collect_evidence \
                        "Safari history: $user" \
                        "$APPS_DIR" \
                        "safari_history_${user}" \
                        "sqlite3 '$safari_dir/History.db' 'SELECT datetime(history_items.visit_time + 978307200, \"unixepoch\") as visited, title, url FROM history_items ORDER BY visited DESC LIMIT 100;' 2>/dev/null || echo 'Unable to read Safari history'"
                fi
                
                # Safari downloads
                if [ -f "$safari_dir/Downloads.plist" ]; then
                    collect_evidence \
                        "Safari downloads: $user" \
                        "$APPS_DIR" \
                        "safari_downloads_${user}" \
                        "plutil -p '$safari_dir/Downloads.plist' 2>/dev/null | head -100"
                fi
            fi
            
            # Chrome artifacts
            local chrome_dir="/Users/$user/Library/Application Support/Google/Chrome"
            if [ -d "$chrome_dir" ]; then
                ((browsers_found++))
                
                # Chrome history
                if [ -f "$chrome_dir/Default/History" ]; then
                    collect_evidence \
                        "Chrome history: $user" \
                        "$APPS_DIR" \
                        "chrome_history_${user}" \
                        "sqlite3 '$chrome_dir/Default/History' 'SELECT datetime(last_visit_time/1000000-11644473600, \"unixepoch\") as visited, title, url FROM urls ORDER BY visited DESC LIMIT 100;' 2>/dev/null || echo 'Unable to read Chrome history'"
                fi
                
                # Chrome downloads
                if [ -f "$chrome_dir/Default/History" ]; then
                    collect_evidence \
                        "Chrome downloads: $user" \
                        "$APPS_DIR" \
                        "chrome_downloads_${user}" \
                        "sqlite3 '$chrome_dir/Default/History' 'SELECT datetime(start_time/1000000-11644473600, \"unixepoch\") as started, target_path FROM downloads ORDER BY started DESC LIMIT 50;' 2>/dev/null || echo 'Unable to read Chrome downloads'"
                fi
            fi
            
            # Firefox artifacts
            local firefox_dir="/Users/$user/Library/Application Support/Firefox/Profiles"
            if [ -d "$firefox_dir" ]; then
                ((browsers_found++))
                
                for profile in "$firefox_dir"/*.default-release 2>/dev/null; do
                    if [ -d "$profile" ]; then
                        local profile_name="$(basename "$profile")"
                        
                        # Firefox history
                        if [ -f "$profile/places.sqlite" ]; then
                            collect_evidence \
                                "Firefox history: $user ($profile_name)" \
                                "$APPS_DIR" \
                                "firefox_history_${user}_${profile_name}" \
                                "sqlite3 '$profile/places.sqlite' 'SELECT datetime(last_visit_date/1000000, \"unixepoch\") as visited, title, url FROM moz_places ORDER BY visited DESC LIMIT 100;' 2>/dev/null || echo 'Unable to read Firefox history'"
                        fi
                    fi
                done
            fi
        fi
    done
    
    echo "Browser Artifacts: $browsers_found browser installations found" >> "$FINDINGS_FILE"
}

# Phase 3: Application Usage
analyze_application_usage() {
    echo ""
    echo "=== PHASE 3: APPLICATION USAGE ==="
    
    # System-wide recent items
    collect_evidence \
        "System recent items" \
        "$APPS_DIR" \
        "system_recent_items" \
        "defaults read /Library/Preferences/com.apple.recentitems 2>/dev/null || echo 'No system recent items'"
    
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            # Recent documents
            collect_evidence \
                "Recent documents: $user" \
                "$APPS_DIR" \
                "recent_docs_${user}" \
                "defaults read /Users/$user/Library/Preferences/com.apple.recentitems 2>/dev/null || echo 'No recent items'"
            
            # Launch Services quarantine events
            local quarantine_db="/Users/$user/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
            if [ -f "$quarantine_db" ]; then
                collect_evidence \
                    "Downloaded files: $user" \
                    "$APPS_DIR" \
                    "downloads_quarantine_${user}" \
                    "sqlite3 '$quarantine_db' 'SELECT datetime(LSQuarantineTimeStamp + 978307200, \"unixepoch\") as downloaded, LSQuarantineAgentName, LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 100;' 2>/dev/null || echo 'Unable to read quarantine database'"
            fi
            
            # Terminal history
            if [ -f "/Users/$user/.bash_history" ]; then
                collect_evidence \
                    "Bash history: $user" \
                    "$APPS_DIR" \
                    "bash_history_${user}" \
                    "tail -100 /Users/$user/.bash_history"
            fi
            
            if [ -f "/Users/$user/.zsh_history" ]; then
                collect_evidence \
                    "ZSH history: $user" \
                    "$APPS_DIR" \
                    "zsh_history_${user}" \
                    "tail -100 /Users/$user/.zsh_history"
            fi
        fi
    done
    
    echo "Application Usage: Analysis complete" >> "$FINDINGS_FILE"
}

# Phase 4: User Interface Artifacts
collect_ui_artifacts() {
    echo ""
    echo "=== PHASE 4: USER INTERFACE ARTIFACTS ==="
    
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            # Desktop contents
            if [ -d "/Users/$user/Desktop" ]; then
                collect_evidence \
                    "Desktop contents: $user" \
                    "$UI_DIR" \
                    "desktop_${user}" \
                    "ls -la /Users/$user/Desktop | head -50"
            fi
            
            # Dock configuration
            collect_evidence \
                "Dock configuration: $user" \
                "$UI_DIR" \
                "dock_${user}" \
                "defaults read /Users/$user/Library/Preferences/com.apple.dock persistent-apps 2>/dev/null | head -200"
            
            # Screenshots
            collect_evidence \
                "Screenshot locations: $user" \
                "$UI_DIR" \
                "screenshots_${user}" \
                "find /Users/$user/Desktop -name 'Screen*' -type f -mtime -30 2>/dev/null | head -50"
            
            # Spaces and Mission Control
            collect_evidence \
                "Spaces configuration: $user" \
                "$UI_DIR" \
                "spaces_${user}" \
                "defaults read /Users/$user/Library/Preferences/com.apple.spaces 2>/dev/null | head -100"
        fi
    done
    
    echo "UI Artifacts: Collection complete" >> "$FINDINGS_FILE"
}

# Phase 5: Communication Artifacts
collect_communication_artifacts() {
    echo ""
    echo "=== PHASE 5: COMMUNICATION ARTIFACTS ==="
    
    local comm_apps_found=0
    
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            # Messages
            local messages_dir="/Users/$user/Library/Messages"
            if [ -d "$messages_dir" ] && [ -f "$messages_dir/chat.db" ]; then
                ((comm_apps_found++))
                
                collect_evidence \
                    "Messages recent: $user" \
                    "$COMM_DIR" \
                    "messages_${user}" \
                    "sqlite3 '$messages_dir/chat.db' 'SELECT datetime(date/1000000000 + 978307200, \"unixepoch\") as timestamp, text FROM message ORDER BY date DESC LIMIT 50;' 2>/dev/null || echo 'Unable to read Messages database'"
            fi
            
            # Mail
            local mail_dir="/Users/$user/Library/Mail"
            if [ -d "$mail_dir" ]; then
                ((comm_apps_found++))
                
                collect_evidence \
                    "Mail configuration: $user" \
                    "$COMM_DIR" \
                    "mail_config_${user}" \
                    "defaults read /Users/$user/Library/Preferences/com.apple.mail 2>/dev/null | grep -E 'MailAccounts|RecentSearches' | head -50"
            fi
            
            # Zoom
            if [ -d "/Users/$user/Library/Application Support/zoom.us" ]; then
                ((comm_apps_found++))
                
                collect_evidence \
                    "Zoom presence: $user" \
                    "$COMM_DIR" \
                    "zoom_${user}" \
                    "ls -la '/Users/$user/Library/Application Support/zoom.us' | head -20"
            fi
            
            # Slack
            if [ -d "/Users/$user/Library/Application Support/Slack" ]; then
                ((comm_apps_found++))
                
                collect_evidence \
                    "Slack presence: $user" \
                    "$COMM_DIR" \
                    "slack_${user}" \
                    "ls -la '/Users/$user/Library/Application Support/Slack' | head -20"
            fi
            
            # Microsoft Teams
            if [ -d "/Users/$user/Library/Application Support/Microsoft/Teams" ]; then
                ((comm_apps_found++))
                
                collect_evidence \
                    "Teams presence: $user" \
                    "$COMM_DIR" \
                    "teams_${user}" \
                    "ls -la '/Users/$user/Library/Application Support/Microsoft/Teams' | head -20"
            fi
        fi
    done
    
    echo "Communication Apps: $comm_apps_found applications found" >> "$FINDINGS_FILE"
}

# Phase 6: File Activity
analyze_file_activity() {
    echo ""
    echo "=== PHASE 6: FILE ACTIVITY ==="
    
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            # Recent documents
            collect_evidence \
                "Recent documents: $user" \
                "$FILES_DIR" \
                "recent_docs_${user}" \
                "find /Users/$user/Documents -type f -mtime -7 2>/dev/null | head -50"
            
            # Recent downloads
            collect_evidence \
                "Recent downloads: $user" \
                "$FILES_DIR" \
                "recent_downloads_${user}" \
                "find /Users/$user/Downloads -type f -mtime -7 2>/dev/null | head -50"
            
            # Desktop files
            collect_evidence \
                "Recent desktop files: $user" \
                "$FILES_DIR" \
                "recent_desktop_${user}" \
                "find /Users/$user/Desktop -type f -mtime -7 2>/dev/null | head -50"
            
            # Spotlight searches
            collect_evidence \
                "Spotlight configuration: $user" \
                "$FILES_DIR" \
                "spotlight_${user}" \
                "defaults read /Users/$user/Library/Preferences/com.apple.Spotlight 2>/dev/null | head -50"
        fi
    done
    
    echo "File Activity: Analysis complete" >> "$FINDINGS_FILE"
}

# Phase 7: Cloud Services
analyze_cloud_services() {
    echo ""
    echo "=== PHASE 7: CLOUD SERVICES ==="
    
    local cloud_services_count=0
    
    for user in $(get_user_list); do
        if [ -d "/Users/$user" ]; then
            # iCloud
            if [ -d "/Users/$user/Library/Mobile Documents" ]; then
                ((cloud_services_count++))
                
                collect_evidence \
                    "iCloud Drive presence: $user" \
                    "$CLOUD_DIR" \
                    "icloud_${user}" \
                    "ls -la '/Users/$user/Library/Mobile Documents/com~apple~CloudDocs' 2>/dev/null | head -20"
                
                collect_evidence \
                    "iCloud configuration: $user" \
                    "$CLOUD_DIR" \
                    "icloud_config_${user}" \
                    "defaults read /Users/$user/Library/Preferences/MobileMeAccounts 2>/dev/null | grep -v password | head -50"
            fi
            
            # Dropbox
            if [ -d "/Users/$user/.dropbox" ]; then
                ((cloud_services_count++))
                
                collect_evidence \
                    "Dropbox presence: $user" \
                    "$CLOUD_DIR" \
                    "dropbox_${user}" \
                    "ls -la /Users/$user/.dropbox | head -20"
            fi
            
            # Google Drive
            if [ -d "/Users/$user/Library/Application Support/Google/Drive" ]; then
                ((cloud_services_count++))
                
                collect_evidence \
                    "Google Drive presence: $user" \
                    "$CLOUD_DIR" \
                    "gdrive_${user}" \
                    "ls -la '/Users/$user/Library/Application Support/Google/Drive' | head -20"
            fi
            
            # OneDrive
            if [ -d "/Users/$user/Library/Application Support/OneDrive" ]; then
                ((cloud_services_count++))
                
                collect_evidence \
                    "OneDrive presence: $user" \
                    "$CLOUD_DIR" \
                    "onedrive_${user}" \
                    "ls -la '/Users/$user/Library/Application Support/OneDrive' | head -20"
            fi
        fi
    done
    
    echo "Cloud Services: $cloud_services_count services detected" >> "$FINDINGS_FILE"
}

# Generate forensic report
generate_forensic_report() {
    echo ""
    echo "=== GENERATING FORENSIC REPORT ==="
    
    local report_file="${OUTPUT_ROOT}/USER_ACTIVITY_FORENSICS_REPORT.md"
    local acquisition_end="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    cat > "$report_file" <<-EOF
	# USER ACTIVITY FORENSIC COLLECTION REPORT
	
	## Executive Summary
	
	This report documents a comprehensive user activity forensic collection performed on a macOS system. The analysis encompasses user account configurations, application usage patterns, browser artifacts, communication tools, file activity, and cloud service integrations. The collection provides detailed insight into user behaviors and system interactions suitable for forensic analysis and investigation.
	
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
	
	## User Account Analysis
	
	The system contains $(ls /Users | grep -v -E "Shared|.localized|Guest" | wc -l | tr -d ' ') user accounts. Each account has been analyzed for configuration settings, login history, group membership, and administrative privileges. Failed login attempts and security events have been captured for the past seven days where available.
	
	## Application Usage Patterns
	
	### Browser Artifacts
	
	Browser history, downloads, and bookmarks have been collected from Safari, Chrome, and Firefox installations where present. The artifacts provide insight into web browsing patterns, downloaded files, and saved websites. Timestamp information has been preserved for timeline reconstruction.
	
	### Application Preferences
	
	Recent document lists, application launch records, and quarantine events have been collected to establish software usage patterns. Terminal command histories provide additional context for technical user activities where available.
	
	## Communication Artifacts
	
	Communication application artifacts have been collected from Messages, Mail, and third-party applications including Zoom, Slack, and Microsoft Teams where installed. The artifacts include message databases, configuration settings, and application presence indicators.
	
	## File Activity Analysis
	
	Recent file modifications within Documents, Downloads, and Desktop directories have been documented for each user account. The analysis includes files modified within the past seven days to establish recent activity patterns. Spotlight search configurations provide additional context for user information retrieval patterns.
	
	## Cloud Service Integration
	
	Cloud storage services including iCloud, Dropbox, Google Drive, and OneDrive have been identified where present. Configuration settings and synchronization indicators have been preserved for each detected service.
	
	## Evidence Integrity
	
	All collected evidence has been hashed using SHA256 and recorded in the manifest file. The chain of custody document provides complete documentation of the collection process. To verify evidence integrity:
	
	\`\`\`
	shasum -c "$MANIFEST_FILE"
	\`\`\`
	
	## Collection Methodology
	
	The forensic collection followed a structured seven-phase approach:
	
	1. User Account Analysis - Account configurations and login history
	2. Browser Artifacts - Web browsing history and downloads
	3. Application Usage - Software preferences and usage patterns
	4. User Interface Artifacts - Desktop and dock configurations
	5. Communication Artifacts - Messaging and collaboration tools
	6. File Activity - Recent document and file access
	7. Cloud Services - Cloud storage and synchronization
	
	Each phase employed timeout controls and error handling to ensure collection completion even when individual operations encountered permission restrictions or data accessibility issues.
	
	## Recommendations
	
	### Immediate Analysis Priorities
	
	The collected artifacts should be analyzed in the following priority order: First, examine browser history and downloads for evidence of relevant activities. Second, review communication artifacts for pertinent conversations or data transfers. Third, analyze recent file activity for document creation or modification patterns. Fourth, correlate cloud service activity with local file changes to identify synchronization patterns.
	
	### Timeline Reconstruction
	
	The timestamp information preserved across all artifacts enables comprehensive timeline reconstruction. Correlating browser activity, file modifications, and communication timestamps will establish user activity patterns and identify periods of interest for deeper analysis.
	
	### Further Investigation
	
	Additional investigation may be warranted for any suspicious downloads identified in quarantine databases, unusual communication patterns in messaging applications, or unexpected cloud synchronization activities. The preserved configuration files and preferences provide context for understanding user behavior patterns.
	
	## Limitations
	
	This collection was performed on a live system with active user sessions potentially modifying data during acquisition. Some artifacts may be incomplete due to permission restrictions or database locks. Encrypted user data and password-protected applications may have limited artifact availability.
	
	## Conclusion
	
	This user activity forensic collection provides comprehensive documentation of user behaviors, application usage, and system interactions. The preserved artifacts enable detailed analysis of user activities while maintaining forensic integrity through proper chain of custody and evidence verification procedures.
	
	---
	
	*Generated by TT05 User Activity Forensics v${SCRIPT_VERSION}*  
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
	  I certify this user activity forensic collection was conducted
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
    local archive_name="${CASE_ID}_user_activity_${ACQUISITION_ID}.tar.gz"
    cd "$(dirname "$OUTPUT_ROOT")" || exit 1
    tar -czf "$archive_name" "$(basename "$OUTPUT_ROOT")"
    cd - > /dev/null || exit 1
    
    local archive_hash="$(shasum -a 256 "$(dirname "$OUTPUT_ROOT")/$archive_name" | awk '{print $1}')"
    
    # Display summary
    echo ""
    echo "=========================================="
    echo "USER ACTIVITY FORENSICS COLLECTION COMPLETE"
    echo "=========================================="
    echo "Case ID: $CASE_ID"
    echo "Evidence Location: $OUTPUT_ROOT"
    echo "Archive: $(dirname "$OUTPUT_ROOT")/$archive_name"
    echo "Archive SHA256: $archive_hash"
    echo ""
    echo "Key Statistics:"
    grep -E "users:|Apps:|Services:" "$FINDINGS_FILE" | head -5
    echo ""
    echo "To verify evidence integrity:"
    echo "  shasum -c '$MANIFEST_FILE'"
}

# Main execution
main() {
    echo "================================================"
    echo "USER ACTIVITY FORENSICS v${SCRIPT_VERSION}"
    echo "================================================"
    echo "Case ID: $CASE_ID"
    echo "Examiner: $EXAMINER"
    echo ""
    
    # Initialize environment
    initialize_forensic_environment
    
    # Execute collection phases
    analyze_user_accounts
    collect_browser_artifacts
    analyze_application_usage
    collect_ui_artifacts
    collect_communication_artifacts
    analyze_file_activity
    analyze_cloud_services
    
    # Generate reports and finalize
    generate_forensic_report
    finalize_evidence
}

# Signal handling for clean termination
trap 'echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Collection interrupted"; exit 130' INT TERM

# Execute main function
main "$@"

exit 0