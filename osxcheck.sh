#!/bin/bash
# Compatible with bash 3.2 (macOS default)

# ============================================================================
# macOS Security and Forensics Assessment Script
#
# Purpose:    Comprehensive security analysis and forensic assessment for
#             macOS systems with enhanced detection and reporting.
# Author:     Security Assessment Team (Enhanced Version)
# Version:    2.0.1 (Fixed)
# Date:       2025-07-11
#
# ============================================================================

set -euo pipefail

# ============================================================================
# SCRIPT CONFIGURATION
# ============================================================================

readonly SCRIPT_VERSION="2.0.1"
readonly SCRIPT_NAME="macOS Security Assessment"

# --- Default Settings ---
ASSESSMENT_MODE="standard"
OUTPUT_DIR=""
MAX_PARALLEL=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
SIMULATE_MODE=false
DEBUG_MODE=false
ENCRYPT_OUTPUT=true
JSON_OUTPUT=false
HTML_OUTPUT=false
INTERACTIVE_MODE=false
CURRENT_DATE=$(date '+%Y-%m-%d %H:%M:%S')
THREAT_SCORE=0
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
MEDIUM_FINDINGS=0
LOW_FINDINGS=0
ENCRYPTION_PASSWORD=""
PROGRESS_COUNTER=0
TOTAL_CHECKS=0

# --- Architecture Detection ---
ARCH=$(uname -m)
IS_APPLE_SILICON=false
[[ "$ARCH" == "arm64" ]] && IS_APPLE_SILICON=true

# --- Color Codes ---
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_RESET='\033[0m'

# ============================================================================
# ENHANCED IOC DEFINITIONS - Bash 3.2 Compatible
# ============================================================================

# IOC definitions stored as delimited strings for bash 3.2 compatibility
# Format: check_name|pattern|score|severity|category|description|remediation

IOC_DEFINITIONS="
sip_disabled|disabled|100|CRITICAL|System|System Integrity Protection (SIP) is disabled|Enable SIP by booting into Recovery Mode and running 'csrutil enable'
gatekeeper_disabled|disabled|75|HIGH|System|Gatekeeper is disabled|Enable Gatekeeper with 'sudo spctl --master-enable'
filevault_off|Off|50|HIGH|System|FileVault encryption is disabled|Enable FileVault in System Preferences > Security & Privacy
xprotect_outdated|[0-9]{4}/(0[1-9]|1[0-2])/([0-2][0-9]|3[01])|30|MEDIUM|System|XProtect definitions may be outdated|Update XProtect via System Preferences
firewall_disabled|0|50|HIGH|System|Application firewall is disabled|Enable firewall via System Preferences > Security & Privacy
unsigned_kext|com\.(?!apple)|40|MEDIUM|Kernel|Unsigned third-party kernel extension|Review and remove unnecessary kernel extensions
suspicious_kext|(keylogger|rootkit|backdoor)|100|CRITICAL|Kernel|Suspicious kernel extension name|Immediately investigate and remove suspicious kernel extension
nvram_boot_args|boot-args.*(?!debug)|60|HIGH|System|Modified NVRAM boot arguments|Reset NVRAM by holding Cmd+Option+P+R during startup
promiscuous_mode|PROMISC|80|HIGH|Network|Network interface in promiscuous mode|Investigate why interface is in promiscuous mode
suspicious_hosts|^(?!#|127\.0\.0\.1|255\.255\.255\.255|::1|fe80::1%).*\.(tk|ml|ga|cf)|40|MEDIUM|Network|Suspicious domain in hosts file|Review and clean /etc/hosts file
open_sharing|(AFP|SMB|VNC|SSH).*LISTEN|30|MEDIUM|Network|File sharing service is active|Review sharing settings in System Preferences
suspicious_dns|(8\.8\.8\.8|1\.1\.1\.1)|20|LOW|Network|Non-default DNS servers configured|Verify DNS settings are intentional
hidden_launch_item|\\/\\.|60|HIGH|Persistence|Hidden LaunchAgent/Daemon|Investigate hidden launch items
suspicious_launch_program|(bash -c|curl|wget|nc|python.*-c)|80|HIGH|Persistence|Suspicious command in launch item|Review and remove suspicious launch items
user_launch_daemon|/Users/.*/Library/LaunchDaemons|70|HIGH|Persistence|User-level LaunchDaemon (unusual)|LaunchDaemons should typically be system-level only
login_hook|com\.apple\.loginwindow.*LoginHook|50|HIGH|Persistence|Login hook configured|Review login hooks for unauthorized entries
known_malware|(Adload|Bundlore|Pirrit|Genieo|Shlayer|OSX/Dok|Silver\\.Sparrow|XCSSET)|100|CRITICAL|Malware|Known malware family detected|Run malware removal tool and full system scan
cryptominer|(xmrig|minerd|coinhive|cryptonight)|90|HIGH|Malware|Cryptocurrency miner detected|Remove mining software immediately
backdoor_pattern|(meterpreter|empire|covenant|pupy|osxreversetcp)|100|CRITICAL|Malware|Backdoor/C2 framework detected|Isolate system and perform incident response
obfuscation|(base64.*decode|eval.*base64|gzinflate|str_rot13)|70|HIGH|Malware|Code obfuscation detected|Analyze obfuscated code for malicious content
unsigned_app|code object is not signed|60|HIGH|Application|Unsigned application detected|Remove or verify unsigned applications
revoked_cert|CSSMERR_TP_CERT_REVOKED|90|HIGH|Application|Application certificate revoked|Remove application with revoked certificate
modified_app|code signature invalid|80|HIGH|Application|Application has been modified|Reinstall application from trusted source
suspicious_app_name|(MacKeeper|CleanMyMac|MacCleaner|Advanced Mac Cleaner)|40|MEDIUM|Application|Potentially unwanted application|Consider removing PUA software
suspicious_extension|(hola|ultrasurf|zenmate)|30|MEDIUM|Browser|Suspicious browser extension|Review and remove suspicious browser extensions
browser_hijack|(searchbaron|searchmarquis|mybrowser-search)|70|HIGH|Browser|Browser hijacker detected|Reset browser settings and remove hijacker
hidden_process|\\s+\\.|40|MEDIUM|Process|Hidden process name detected|Investigate hidden processes
suspicious_port|(4444|31337|1337|6666|6667)|50|HIGH|Process|Process using suspicious port|Investigate process network activity
high_cpu_unknown|[8-9][0-9]\\.[0-9]|30|MEDIUM|Process|Unknown process with high CPU usage|Identify and investigate high CPU process
hidden_executable|\\/\\..*\\.(sh|py|rb|pl|jar)$|50|HIGH|Filesystem|Hidden executable file|Review hidden executables
temp_executable|\\/tmp.*\\.(sh|py|command|app|jar)$|60|HIGH|Filesystem|Executable in temp directory|Remove executables from temp directories
suspicious_binary_location|\\/Users\\/.*\\/(Pictures|Documents|Movies)\\/.*\\/(bash|sh|python|perl|ruby)$|70|HIGH|Filesystem|System binary in unusual location|Investigate relocated system binaries
auth_failure_spike|authentication failure.*([5-9]|[1-9][0-9]+) times|40|MEDIUM|Security|Multiple authentication failures|Review failed login attempts
privilege_escalation|sudo.*COMMAND.*\\/tmp|60|HIGH|Security|Suspicious sudo usage from temp|Investigate privilege escalation attempts
log_deletion|log.*deleted|removed.*\\.log|50|HIGH|Security|Log deletion detected|Investigate log tampering
unknown_mdm|com\\.(?!apple|jamf|vmware|microsoft|mosyle)|50|HIGH|Profile|Unknown MDM profile|Verify MDM profile legitimacy
suspicious_profile_payload|(PayloadType.*com\\.apple\\.security)|60|HIGH|Profile|Security-modifying configuration profile|Review profile payloads carefully
invalid_kext_signature|Signature: INVALID|80|HIGH|Kernel|Kernel extension has invalid signature|Investigate and remove untrusted kexts
"

# Custom IOCs storage
CUSTOM_IOCS=""
EXTERNAL_IOC_FILE="${HOME}/.macos_security_assessment/custom_iocs.conf"

# Helper function to get IOC definition by name
get_ioc_definition() {
    local check_name="$1"
    echo "$IOC_DEFINITIONS" | grep "^$check_name|" | head -1
}

# ============================================================================
# HELP AND ARGUMENT PARSING
# ============================================================================

show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION

A comprehensive security and forensics assessment script for macOS with
enhanced detection capabilities and reporting.

USAGE:
    $(basename "$0") [OPTIONS]

OPTIONS:
    --full          Run comprehensive analysis (all checks)
    --quick         Run quick analysis (essential checks only)
    --standard      Run standard analysis (default)
    --interactive   Interactive mode - choose specific modules
    --output DIR    Specify output directory (default: ./assessment_TIMESTAMP)
    --parallel N    Set max parallel jobs (default: CPU cores)
    --json          Enable JSON/JSONL report output
    --html          Enable HTML report with visualizations
    --simulate      Run in simulation mode (no commands executed)
    --debug         Enable debug logging
    --no-encrypt    Disable encryption of final archive
    --load-iocs FILE Load custom IOC definitions from file
    --help          Show this help message

ASSESSMENT MODES:
    quick:    Essential security checks (~2 minutes)
    standard: Comprehensive security assessment (~10 minutes)
    full:     Deep forensic analysis (~30+ minutes)

EXAMPLES:
    # Quick security check
    $(basename "$0") --quick
    
    # Full assessment with HTML report
    sudo $(basename "$0") --full --html --output ~/Desktop/mac_assessment
    
    # Interactive mode with custom IOCs
    $(basename "$0") --interactive --load-iocs ~/my_iocs.conf
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --full) ASSESSMENT_MODE="full"; shift ;;
            --quick) ASSESSMENT_MODE="quick"; shift ;;
            --standard) ASSESSMENT_MODE="standard"; shift ;;
            --interactive) INTERACTIVE_MODE=true; shift ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            --parallel) MAX_PARALLEL="$2"; shift 2 ;;
            --simulate) SIMULATE_MODE=true; shift ;;
            --debug) DEBUG_MODE=true; shift ;;
            --no-encrypt) ENCRYPT_OUTPUT=false; shift ;;
            --json) JSON_OUTPUT=true; shift ;;
            --html) HTML_OUTPUT=true; shift ;;
            --load-iocs) 
                if [[ -n "${2:-}" ]]; then
                    load_external_iocs "$2"
                    shift 2
                else
                    echo "Error: --load-iocs requires a file argument"
                    exit 1
                fi
                ;;
            --help) show_help; exit 0 ;;
            *) echo "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done
}

# ============================================================================
# INITIALIZATION AND UTILITIES
# ============================================================================

# --- Progress Tracking ---
update_progress() {
    local task="$1"
    ((PROGRESS_COUNTER++)) || true
    local percentage=0
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        percentage=$((PROGRESS_COUNTER * 100 / TOTAL_CHECKS))
    fi
    printf "\r${COLOR_CYAN}[%3d%%]${COLOR_RESET} %-50s" "$percentage" "$task"
    if [[ $PROGRESS_COUNTER -eq $TOTAL_CHECKS ]]; then
        echo ""
    fi
}

# --- Logging with Levels ---
init_logging() {
    mkdir -p "$OUTPUT_DIR"
    cat > "$LOG_FILE" << EOF
$SCRIPT_NAME v$SCRIPT_VERSION
Assessment started: $CURRENT_DATE
Mode: $ASSESSMENT_MODE
Architecture: $ARCH (Apple Silicon: $IS_APPLE_SILICON)
Output directory: $OUTPUT_DIR
Parallel jobs: $MAX_PARALLEL
JSON Report: $JSON_OUTPUT
HTML Report: $HTML_OUTPUT
EOF
}

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] $message"
    
    echo "$log_entry" >> "$LOG_FILE"
    
    # Console output with colors
    if [[ "$level" == "DEBUG" ]] && ! $DEBUG_MODE; then
        return
    fi

    case "$level" in
        "INFO")    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $message" ;;
        "SUCCESS") echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $message" ;;
        "WARNING") echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $message" ;;
        "ERROR")   echo -e "${COLOR_RED}[✗]${COLOR_RESET} $message" ;;
        "DEBUG")   echo -e "${COLOR_MAGENTA}[DEBUG]${COLOR_RESET} $message" ;;
        "CRITICAL") echo -e "${COLOR_RED}[CRITICAL]${COLOR_RESET} $message" ;;
    esac
}

# --- External IOC Loading ---
load_external_iocs() {
    local file="$1"
    if [[ -f "$file" ]]; then
        log "INFO" "Loading external IOCs from $file"
        local count=0
        while IFS='|' read -r pattern score severity category desc remediation; do
            [[ "$pattern" =~ ^#.*$ ]] && continue
            [[ -z "$pattern" ]] && continue
            local key="custom_$(echo "$pattern" | md5)"
            CUSTOM_IOCS="${CUSTOM_IOCS}${key}|${pattern}|${score}|${severity}|${category}|${desc}|${remediation}
"
            ((count++))
        done < "$file"
        log "SUCCESS" "Loaded $count custom IOC patterns"
    else
        log "WARNING" "External IOC file not found: $file"
    fi
}

# --- Prerequisite Checks ---
check_dependencies() {
    local deps=("jq" "sqlite3" "codesign" "spctl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "WARNING" "Optional dependencies missing: ${missing[*]}"
        log "INFO" "Some features may be limited. Install with: brew install ${missing[*]}"
    fi
    
    # Check for required tools based on options
    if $JSON_OUTPUT && ! command -v jq &> /dev/null; then
        log "ERROR" "'jq' is required for JSON output but is not installed"
        exit 1
    fi
}

# --- System Capability Detection ---
detect_capabilities() {
    # Check for T2 chip if system_profiler is available
    if command -v system_profiler >/dev/null 2>&1; then
        if system_profiler SPiBridgeDataType 2>/dev/null | grep -q "Apple T2"; then
            echo "T2_CHIP=true" >> "$OUTPUT_DIR/.capabilities"
        fi
    fi

    # Check for Secure Enclave
    if $IS_APPLE_SILICON || ([[ -f "$OUTPUT_DIR/.capabilities" ]] && grep -q "T2_CHIP=true" "$OUTPUT_DIR/.capabilities"); then
        echo "SECURE_ENCLAVE=true" >> "$OUTPUT_DIR/.capabilities"
    fi

    # Check macOS version if sw_vers exists
    local os_version="unknown"
    if command -v sw_vers >/dev/null 2>&1; then
        os_version=$(sw_vers -productVersion)
    fi
    echo "OS_VERSION=$os_version" >> "$OUTPUT_DIR/.capabilities"

    # Check for admin privileges
    if groups | grep -q admin; then
        echo "IS_ADMIN=true" >> "$OUTPUT_DIR/.capabilities"
    fi
}

# --- Interactive Mode ---
run_interactive_mode() {
    echo -e "\n${COLOR_CYAN}=== Interactive Mode ===${COLOR_RESET}\n"
    echo "Select modules to run (enter number or letter):"
    
    local modules=(
        "System Information & Security Settings"
        "Network Configuration & Connections"
        "Security & Privacy Settings"
        "Persistence Mechanisms"
        "Application Analysis"
        "Process & Memory Analysis"
        "Browser Security"
        "Filesystem Scan"
        "Log Analysis"
        "Full Assessment (All Modules)"
    )
    
    local selected=()
    
    # Simple selection menu
    while true; do
        clear
        echo -e "${COLOR_CYAN}Select Assessment Modules:${COLOR_RESET}\n"
        for i in "${!modules[@]}"; do
            local num=$((i + 1))
            if [[ " ${selected[*]} " =~ " $i " ]]; then
                echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $num. ${modules[$i]}"
            else
                echo -e "[ ] $num. ${modules[$i]}"
            fi
        done
        echo -e "\nOptions: 1-${#modules[@]} to toggle, 'a' for all, 'n' for none, 'q' to start"
        
        read -r -n 1 choice
        case "$choice" in
            [1-9]|10)
                local idx=$((choice - 1))
                if [[ $idx -lt ${#modules[@]} ]]; then
                    if [[ " ${selected[*]} " =~ " $idx " ]]; then
                        selected=("${selected[@]/$idx/}")
                    else
                        selected+=("$idx")
                    fi
                fi
                ;;
            a) selected=(0 1 2 3 4 5 6 7 8); break ;;
            n) selected=(); ;;
            q) break ;;
        esac
    done
    
    # Run selected modules
    for idx in "${selected[@]}"; do
        case $idx in
            0) assess_system_info ;;
            1) assess_network ;;
            2) assess_security ;;
            3) assess_persistence ;;
            4) assess_applications ;;
            5) assess_processes ;;
            6) assess_browser_security ;;
            7) assess_filesystem ;;
            8) assess_logs ;;
            9) ASSESSMENT_MODE="full"; return ;;
        esac
    done
}

# --- Enhanced Command Execution ---
execute_command() {
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    local requires_sudo="${4:-false}"
    local timeout="${5:-60}"
    
    update_progress "$description"
    log "DEBUG" "Executing: $description"
    
    if $SIMULATE_MODE; then
        log "INFO" "[SIM] Would execute: $cmd"
        echo "Simulated output for: $cmd" > "$output_file"
        return 0
    fi
    
    mkdir -p "$(dirname "$output_file")"
    
    local exec_cmd="$cmd"
    if [[ "$requires_sudo" == "true" ]] && [[ $EUID -ne 0 ]]; then
        if ! sudo -n true 2>/dev/null; then
            log "WARNING" "Skipping $description (requires sudo)"
            echo "Skipped: Requires sudo privileges" > "$output_file"
            return 1
        fi
        exec_cmd="sudo $cmd"
    fi
    
    # Execute with timeout and proper error handling
    if command -v timeout >/dev/null 2>&1; then
        # GNU timeout
        timeout "$timeout" bash -c "$exec_cmd" > "$output_file" 2>&1 || true
    elif command -v gtimeout >/dev/null 2>&1; then
        # macOS with GNU coreutils
        gtimeout "$timeout" bash -c "$exec_cmd" > "$output_file" 2>&1 || true
    else
        # Fallback without timeout
        bash -c "$exec_cmd" > "$output_file" 2>&1 || true
    fi
    
    if [[ -s "$output_file" ]]; then
        log "SUCCESS" "$description completed"
        local hash
        hash=$(calculate_hash "$output_file")
        echo "{\"file\": \"$output_file\", \"hash\": \"$hash\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$HASH_FILE.tmp"
    else
        log "WARNING" "$description produced no output"
    fi
}

# --- Enhanced IOC Analysis ---
analyze_file() {
    local file_to_analyze="$1"
    local check_name="$2"
    local custom="${3:-false}"
    
    if [[ ! -f "$file_to_analyze" ]]; then
        return
    fi
    
    local ioc_def=""
    if [[ "$custom" == "true" ]]; then
        # Get custom IOC definition
        ioc_def=$(echo "$CUSTOM_IOCS" | grep "^$check_name|" | head -1)
    else
        # Get built-in IOC definition
        ioc_def=$(get_ioc_definition "$check_name")
    fi
    
    if [[ -z "$ioc_def" ]]; then
        return
    fi
    
    # Parse IOC definition - skip the check name
    local pattern=$(echo "$ioc_def" | cut -d'|' -f2)
    local score=$(echo "$ioc_def" | cut -d'|' -f3)
    local severity=$(echo "$ioc_def" | cut -d'|' -f4)
    local category=$(echo "$ioc_def" | cut -d'|' -f5)
    local description=$(echo "$ioc_def" | cut -d'|' -f6)
    local remediation=$(echo "$ioc_def" | cut -d'|' -f7)
    
    local matches
    matches=$(grep -Eic "$pattern" "$file_to_analyze" 2>/dev/null || echo "0")
    
    if [[ $matches -gt 0 ]]; then
        THREAT_SCORE=$((THREAT_SCORE + matches * score))
        
        # Update severity counters
        case "$severity" in
            "CRITICAL") ((CRITICAL_FINDINGS += matches)) ;;
            "HIGH") ((HIGH_FINDINGS += matches)) ;;
            "MEDIUM") ((MEDIUM_FINDINGS += matches)) ;;
            "LOW") ((LOW_FINDINGS += matches)) ;;
        esac
        
        log "$severity" "Found $matches instance(s): $description"
        
        local sample_findings
        sample_findings=$(grep -Ei "$pattern" "$file_to_analyze" | head -5)
        
        # Enhanced text report
        {
            echo "=== Finding: $description ==="
            echo "Severity: $severity"
            echo "Category: $category"
            echo "Risk Score: $score (Total: $((matches * score)))"
            echo "Source: $file_to_analyze"
            echo "Pattern: $pattern"
            echo "Instances: $matches"
            echo "Remediation: $remediation"
            echo "Sample Matches:"
            echo "$sample_findings"
            echo ""
        } >> "$IOC_FILE"
        
        # JSON output
        if $JSON_OUTPUT && command -v jq >/dev/null 2>&1; then
            local json_payload
            json_payload=$(jq -n \
                --arg sev "$severity" \
                --arg cat "$category" \
                --arg desc "$description" \
                --arg pat "$pattern" \
                --arg file "$file_to_analyze" \
                --argjson mat "$matches" \
                --argjson scr "$score" \
                --arg rem "$remediation" \
                --arg samp "$sample_findings" \
                '{
                    severity: $sev,
                    category: $cat,
                    description: $desc,
                    pattern: $pat,
                    file: $file,
                    matches: $mat,
                    score_per_match: $scr,
                    total_score: ($mat * $scr),
                    remediation: $rem,
                    sample_findings: $samp,
                    timestamp: now | todateiso8601
                }')
            echo "$json_payload" >> "$JSONL_REPORT_FILE"
        fi
    fi
}

# ============================================================================
# ENHANCED ASSESSMENT MODULES
# ============================================================================

# Count total checks for progress tracking
count_total_checks() {
    case "$ASSESSMENT_MODE" in
        "quick") TOTAL_CHECKS=16 ;;
        "standard") TOTAL_CHECKS=51 ;;
        "full") TOTAL_CHECKS=101 ;;
    esac
}

assess_system_info() {
    log "INFO" "Starting System Information assessment..."
    
    local commands=(
        "execute_command 'sw_vers' '$OUTPUT_DIR/system/os_version.txt' 'OS Version'"
        "execute_command 'uname -a' '$OUTPUT_DIR/system/kernel_info.txt' 'Kernel Info'"
        "execute_command 'system_profiler SPHardwareDataType' '$OUTPUT_DIR/system/hardware_profile.txt' 'Hardware Profile'"
        "execute_command 'csrutil status' '$OUTPUT_DIR/system/sip_status.txt' 'SIP Status'"
        "execute_command 'spctl --status' '$OUTPUT_DIR/system/gatekeeper_status.txt' 'Gatekeeper Status'"
        "execute_command 'fdesetup status' '$OUTPUT_DIR/system/filevault_status.txt' 'FileVault Status'"
        "execute_command 'nvram -p' '$OUTPUT_DIR/system/nvram_variables.txt' 'NVRAM Variables' true"
        "execute_command 'kextstat' '$OUTPUT_DIR/system/kernel_extensions.txt' 'Kernel Extensions'"
        "execute_command 'diskutil list' '$OUTPUT_DIR/system/disk_layout.txt' 'Disk Layout'"
        "execute_command 'diskutil apfs list' '$OUTPUT_DIR/system/apfs_layout.txt' 'APFS Layout'"
        "execute_command 'tmutil status' '$OUTPUT_DIR/system/time_machine_status.txt' 'Time Machine Status'"
        "execute_command 'softwareupdate --list' '$OUTPUT_DIR/system/pending_updates.txt' 'Pending Updates'"
        "execute_command 'system_profiler SPiBridgeDataType' '$OUTPUT_DIR/system/t2_chip_info.txt' 'T2 Chip Info'"
    )
    
    # XProtect and MRT status
    if [[ -f "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist" ]]; then
        execute_command "plutil -p '/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist'" \
            "$OUTPUT_DIR/system/xprotect_version.txt" "XProtect Version"
    fi
    
    # Run commands
    for cmd in "${commands[@]}"; do
        eval "$cmd"
    done
    
    # Analysis
    analyze_file "$OUTPUT_DIR/system/sip_status.txt" "sip_disabled"
    analyze_file "$OUTPUT_DIR/system/gatekeeper_status.txt" "gatekeeper_disabled"
    analyze_file "$OUTPUT_DIR/system/filevault_status.txt" "filevault_off"
    analyze_file "$OUTPUT_DIR/system/nvram_variables.txt" "nvram_boot_args"
    analyze_file "$OUTPUT_DIR/system/kernel_extensions.txt" "unsigned_kext"
    analyze_file "$OUTPUT_DIR/system/kernel_extensions.txt" "suspicious_kext"
    analyze_file "$OUTPUT_DIR/system/xprotect_version.txt" "xprotect_outdated"

    log "INFO" "System Information assessment completed"
}

# Check kernel extension signatures
assess_kernel_signing() {
    log "INFO" "Checking kernel extension signatures..."

    local output_file="$OUTPUT_DIR/kernel/kext_signatures.txt"
    : > "$output_file"

    local kext_dir="$OUTPUT_DIR/signatures/kexts"
    mkdir -p "$kext_dir"

    local loaded_kexts installed_kexts kext_list

    if command -v kmutil &>/dev/null; then
        loaded_kexts=$(kmutil showloaded --json 2>/dev/null | jq -r '.[].path')
    else
        loaded_kexts=$(kextstat | awk '/^ *[0-9]+/ {print $NF}' | grep '^/' | sort -u)
    fi

    installed_kexts=$(find /Library/Extensions /System/Library/Extensions -maxdepth 1 -name '*.kext' 2>/dev/null)

    kext_list=$(printf '%s\n%s' "$loaded_kexts" "$installed_kexts" | sort -u)

    for kext in $kext_list; do
        if [[ -d "$kext" ]]; then
            local base
            base=$(basename "$kext")
            local detail_file="$kext_dir/${base}.txt"
            {
                echo "Kext: $kext"
                codesign -dvvv "$kext" 2>&1 | grep -E "Authority|TeamIdentifier" || echo "No signature"
                if codesign --verify --deep --strict "$kext" &>/dev/null; then
                    echo "Signature: VALID"
                else
                    echo "Signature: INVALID"
                fi
                echo ""
            } > "$detail_file"
            cat "$detail_file" >> "$output_file"
        fi
    done

    analyze_file "$output_file" "invalid_kext_signature"
    log "INFO" "Kernel extension signature check completed"
}

assess_network() {
    log "INFO" "Starting Network assessment..."
    
    local commands=(
        "execute_command 'ifconfig -a' '$OUTPUT_DIR/network/interfaces.txt' 'Network Interfaces'"
        "execute_command 'netstat -nr' '$OUTPUT_DIR/network/routing_table.txt' 'Routing Table'"
        "execute_command 'netstat -an' '$OUTPUT_DIR/network/network_connections_all.txt' 'All Network Connections'"
        "execute_command 'lsof -i -P' '$OUTPUT_DIR/network/network_connections_lsof.txt' 'Active Network Connections' true"
        "execute_command 'scutil --dns' '$OUTPUT_DIR/network/dns_config.txt' 'DNS Configuration'"
        "execute_command 'scutil --proxy' '$OUTPUT_DIR/network/proxy_config.txt' 'Proxy Configuration'"
        "execute_command 'cat /etc/hosts' '$OUTPUT_DIR/network/hosts_file.txt' 'Hosts File'"
        "execute_command 'dscacheutil -q host' '$OUTPUT_DIR/network/dns_cache.txt' 'DNS Cache'"
        "execute_command 'pfctl -s rules' '$OUTPUT_DIR/network/pf_rules.txt' 'Packet Filter Rules' true"
        "execute_command '/usr/libexec/ApplicationFirewall/socketfilterfw --listapps' '$OUTPUT_DIR/network/firewall_apps.txt' 'Firewall App List' true"
        "execute_command '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate' '$OUTPUT_DIR/network/firewall_state.txt' 'Firewall State' true"
        "execute_command 'networksetup -listallhardwareports' '$OUTPUT_DIR/network/hardware_ports.txt' 'Network Hardware Ports'"
    )
    
    for cmd in "${commands[@]}"; do
        eval "$cmd"
    done
    
    # Analysis
    analyze_file "$OUTPUT_DIR/network/interfaces.txt" "promiscuous_mode"
    analyze_file "$OUTPUT_DIR/network/hosts_file.txt" "suspicious_hosts"
    analyze_file "$OUTPUT_DIR/network/network_connections_all.txt" "open_sharing"
    analyze_file "$OUTPUT_DIR/network/dns_config.txt" "suspicious_dns"
    analyze_file "$OUTPUT_DIR/network/firewall_state.txt" "firewall_disabled"
    analyze_file "$OUTPUT_DIR/network/network_connections_lsof.txt" "suspicious_port"
    
    log "INFO" "Network assessment completed"
}

assess_security() {
    log "INFO" "Starting Security assessment..."
    
    local commands=(
        "execute_command 'security list-keychains' '$OUTPUT_DIR/security/keychains.txt' 'Keychains'"
        "execute_command 'security dump-trust-settings' '$OUTPUT_DIR/security/trust_settings.txt' 'Trust Settings' true"
        "execute_command 'profiles -L' '$OUTPUT_DIR/security/configuration_profiles.txt' 'Configuration Profiles' true"
        "execute_command 'profiles -C -v' '$OUTPUT_DIR/security/detailed_profiles.txt' 'Detailed Profiles' true"
        "execute_command 'pmset -g' '$OUTPUT_DIR/security/power_settings.txt' 'Power Settings'"
        "execute_command 'defaults read /Library/Preferences/com.apple.security.libraryvalidation' '$OUTPUT_DIR/security/library_validation.txt' 'Library Validation'"
        "execute_command 'defaults read /Library/Preferences/com.apple.alf' '$OUTPUT_DIR/security/alf_preferences.txt' 'ALF Preferences' true"
    )
    
    # TCC Database analysis (with proper escaping)
    if [[ -f "/Library/Application Support/com.apple.TCC/TCC.db" ]]; then
        execute_command "sqlite3 '/Library/Application Support/com.apple.TCC/TCC.db' 'SELECT client, service, auth_value FROM access WHERE auth_value > 0' 2>/dev/null || echo 'TCC database access denied'" \
            "$OUTPUT_DIR/security/tcc_permissions.txt" "TCC Permissions" true
    fi
    
    # Gatekeeper database
    if [[ -f "/var/db/SystemPolicy" ]]; then
        execute_command "sqlite3 /var/db/SystemPolicy 'SELECT * FROM authority WHERE disabled = 0' 2>/dev/null || echo 'Gatekeeper database access denied'" \
            "$OUTPUT_DIR/security/gatekeeper_db.txt" "Gatekeeper Database" true
    fi
    
    for cmd in "${commands[@]}"; do
        eval "$cmd"
    done
    
    # MDM and Profile analysis
    analyze_file "$OUTPUT_DIR/security/detailed_profiles.txt" "unknown_mdm"
    analyze_file "$OUTPUT_DIR/security/detailed_profiles.txt" "suspicious_profile_payload"
    
    log "INFO" "Security assessment completed"
}

assess_persistence() {
    log "INFO" "Starting Persistence Mechanisms assessment..."
    
    local launch_locations=(
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
        "/System/Library/LaunchDaemons"
        "/System/Library/LaunchAgents"
        "$HOME/Library/LaunchAgents"
    )
    
    # Check each location
    for location in "${launch_locations[@]}"; do
        if [[ -d "$location" ]]; then
            local safe_name
            safe_name=$(echo "$location" | tr '/' '_')
            execute_command "ls -la '$location'" "$OUTPUT_DIR/persistence/launch_items${safe_name}.txt" "Launch Items in $location"
            
            # Detailed plist analysis
            find "$location" -name "*.plist" -type f 2>/dev/null | while read -r plist; do
                local plist_name
                plist_name=$(basename "$plist")
                local output_file="$OUTPUT_DIR/persistence/plists/${plist_name}.txt"
                mkdir -p "$(dirname "$output_file")"
                
                {
                    echo "=== Plist: $plist ==="
                    plutil -p "$plist" 2>/dev/null || cat "$plist"
                    echo ""
                    
                    # Check signature of associated program
                    local program
                    program=$(defaults read "$plist" Program 2>/dev/null || \
                             defaults read "$plist" ProgramArguments 2>/dev/null | grep -o '/[^ ]*' | head -1 || true)
                    
                    if [[ -n "$program" && -f "$program" ]]; then
                        echo "Program: $program"
                        echo "Signature check:"
                        codesign -dvvv "$program" 2>&1 || echo "No signature"
                    fi
                } > "$output_file"
            done
        fi
    done
    
    # Login/Logout Hooks
    execute_command "defaults read com.apple.loginwindow 2>/dev/null || echo 'No login window preferences'" "$OUTPUT_DIR/persistence/login_window_prefs.txt" "Login Window Preferences"
    
    # Cron jobs
    execute_command "crontab -l 2>/dev/null || echo 'No user crontab'" "$OUTPUT_DIR/persistence/user_crontab.txt" "User Crontab"
    execute_command "ls -la /usr/lib/cron/tabs/ 2>/dev/null || echo 'No system crontabs found'" "$OUTPUT_DIR/persistence/system_crontabs.txt" "System Crontabs" true
    
    # at jobs
    execute_command "atq 2>/dev/null || echo 'No at jobs found'" "$OUTPUT_DIR/persistence/at_queue.txt" "AT Queue"
    
    # Startup Items (legacy)
    execute_command "ls -la /Library/StartupItems/ 2>/dev/null || echo 'No startup items found'" "$OUTPUT_DIR/persistence/startup_items.txt" "Startup Items"
    
    # Analysis
    find "$OUTPUT_DIR/persistence/plists" -name "*.txt" -type f 2>/dev/null | while read -r file; do
        analyze_file "$file" "hidden_launch_item"
        analyze_file "$file" "suspicious_launch_program"
    done
    
    analyze_file "$OUTPUT_DIR/persistence/login_window_prefs.txt" "login_hook"
    analyze_file "$OUTPUT_DIR/persistence/user_crontab.txt" "suspicious_launch_program"
    
    # Check for user-level LaunchDaemons (unusual)
    if [[ -d "$HOME/Library/LaunchDaemons" ]]; then
        local home_escaped=$(echo "$HOME" | sed 's/\//\\\//g')
        analyze_file "$OUTPUT_DIR/persistence/launch_items_${home_escaped}_Library_LaunchDaemons.txt" "user_launch_daemon"
    fi
    
    log "INFO" "Persistence assessment completed"
}

assess_applications() {
    log "INFO" "Starting Application Analysis..."
    
    # Find all applications
    execute_command "mdfind 'kMDItemKind == Application' 2>/dev/null | head -500 || echo 'Spotlight search failed'" "$OUTPUT_DIR/apps/all_applications.txt" "All Applications via Spotlight"
    
    # Detailed application analysis
    log "INFO" "Analyzing application signatures and notarization..."
    
    # Create directories safely
    mkdir -p "$OUTPUT_DIR/apps/details"
    
    # Find applications in common locations
    local app_dirs=("/Applications" "/System/Applications")
    [[ -d "$HOME/Applications" ]] && app_dirs+=("$HOME/Applications")
    
    for app_dir in "${app_dirs[@]}"; do
        find "$app_dir" -name "*.app" -maxdepth 3 -type d 2>/dev/null | \
        head -100 | while read -r app; do
            local app_name
            app_name=$(basename "$app" | tr ' ' '_' | tr '/' '_')
            local output_file="$OUTPUT_DIR/apps/details/${app_name}.txt"
            
            {
                echo "=== Application: $app ==="
                echo "Bundle ID: $(defaults read "$app/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || echo 'Unknown')"
                echo "Version: $(defaults read "$app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo 'Unknown')"
                echo ""
                echo "Code Signature:"
                codesign -dvvv "$app" 2>&1 | grep -E "Authority|TeamIdentifier|Timestamp|Info.plist" || echo "No signature information"
                echo ""
                echo "Verification:"
                if codesign --verify --deep --strict "$app" &>/dev/null; then
                    echo "✓ Valid signature"
                else
                    echo "✗ Invalid signature"
                fi
                echo ""
                echo "Notarization:"
                if spctl -a -vvv "$app" 2>&1 | grep -q "accepted"; then
                    echo "✓ Notarized"
                else
                    echo "✗ Not notarized"
                fi
                echo ""
                echo "Gatekeeper:"
                spctl -a -vvv "$app" 2>&1 || echo "Gatekeeper check failed"
            } > "$output_file" 2>&1
            
            # Quick analysis on the fly
            grep -q "Invalid signature\|Not notarized" "$output_file" && {
                echo "$app" >> "$OUTPUT_DIR/apps/suspicious_apps.txt"
            }
        done
    done
    
    # Installed packages
    execute_command "pkgutil --pkgs 2>/dev/null | head -500 || echo 'No packages found'" "$OUTPUT_DIR/apps/installed_packages.txt" "Installed Packages"
    execute_command "brew list --versions 2>/dev/null || echo 'Homebrew not installed'" "$OUTPUT_DIR/apps/homebrew_packages.txt" "Homebrew Packages" false 10
    execute_command "port installed 2>/dev/null || echo 'MacPorts not installed'" "$OUTPUT_DIR/apps/macports_packages.txt" "MacPorts Packages" false 10
    
    # App Store apps
    execute_command "find /Applications -path '*Contents/_MASReceipt/receipt' -maxdepth 4 -print 2>/dev/null | sed 's|/Contents/_MASReceipt/receipt||g' | head -100" \
        "$OUTPUT_DIR/apps/app_store_apps.txt" "App Store Applications"
    
    # Analysis
    if [[ -f "$OUTPUT_DIR/apps/suspicious_apps.txt" ]]; then
        analyze_file "$OUTPUT_DIR/apps/suspicious_apps.txt" "unsigned_app"
    fi
    
    find "$OUTPUT_DIR/apps/details" -name "*.txt" -type f 2>/dev/null | while read -r file; do
        analyze_file "$file" "unsigned_app"
        analyze_file "$file" "revoked_cert"
        analyze_file "$file" "modified_app"
    done
    
    analyze_file "$OUTPUT_DIR/apps/all_applications.txt" "suspicious_app_name"
    analyze_file "$OUTPUT_DIR/apps/installed_packages.txt" "known_malware"
    
    log "INFO" "Application analysis completed"
}

assess_processes() {
    log "INFO" "Starting Process Analysis..."
    
    local commands=(
        "execute_command 'ps aux' '$OUTPUT_DIR/processes/all_processes.txt' 'All Processes'"
        "execute_command 'ps aux | sort -nrk 3,3 | head -20' '$OUTPUT_DIR/processes/top_cpu_processes.txt' 'Top CPU Processes'"
        "execute_command 'ps aux | sort -nrk 4,4 | head -20' '$OUTPUT_DIR/processes/top_memory_processes.txt' 'Top Memory Processes'"
        "execute_command 'lsof -n 2>/dev/null | head -1000 || echo \"lsof failed\"' '$OUTPUT_DIR/processes/open_files.txt' 'Open Files' true 30"
        "execute_command 'lsof -i 2>/dev/null || echo \"lsof -i failed\"' '$OUTPUT_DIR/processes/network_connections.txt' 'Process Network Connections' true"
    )
    
    # Skip dtrace on newer macOS versions due to SIP restrictions
    if csrutil status 2>/dev/null | grep -q "disabled"; then
        commands+=("execute_command 'sudo dtrace -n \"syscall:::entry { @[execname] = count(); }\" -o /dev/stdout 2>/dev/null || echo \"dtrace failed\"' '$OUTPUT_DIR/processes/syscall_summary.txt' 'System Call Summary' true 5")
    fi
    
    for cmd in "${commands[@]}"; do
        eval "$cmd"
    done
    
    # Process tree
    if command -v pstree &>/dev/null; then
        execute_command "pstree" "$OUTPUT_DIR/processes/process_tree.txt" "Process Tree"
    fi
    
    # Running code analysis
    log "INFO" "Checking running process signatures..."
    ps aux | awk '{print $11}' | grep -E "^/" | sort -u | head -50 | while read -r binary; do
        if [[ -f "$binary" ]]; then
            local binary_name
            binary_name=$(basename "$binary")
            {
                echo "Binary: $binary"
                codesign -dvvv "$binary" 2>&1 | grep -E "Authority|TeamIdentifier" || echo "No signature"
                echo ""
            } >> "$OUTPUT_DIR/processes/running_binary_signatures.txt"
        fi
    done
    
    # Analysis
    analyze_file "$OUTPUT_DIR/processes/all_processes.txt" "hidden_process"
    analyze_file "$OUTPUT_DIR/processes/network_connections.txt" "suspicious_port"
    analyze_file "$OUTPUT_DIR/processes/top_cpu_processes.txt" "high_cpu_unknown"
    analyze_file "$OUTPUT_DIR/processes/running_binary_signatures.txt" "unsigned_app"
    
    log "INFO" "Process analysis completed"
}

assess_browser_security() {
    log "INFO" "Starting Browser Security assessment..."
    
    # Safari
    if [[ -d "$HOME/Library/Safari" ]]; then
        execute_command "defaults read com.apple.Safari 2>/dev/null | head -500 || echo 'Safari preferences not accessible'" "$OUTPUT_DIR/browser/safari_preferences.txt" "Safari Preferences"
        execute_command "sqlite3 '$HOME/Library/Safari/History.db' 'SELECT url, visit_count FROM history_items ORDER BY visit_count DESC LIMIT 20' 2>/dev/null || echo 'Safari history not accessible'" \
            "$OUTPUT_DIR/browser/safari_top_sites.txt" "Safari Top Sites"
        execute_command "ls -la '$HOME/Library/Safari/Extensions/' 2>/dev/null || echo 'No Safari extensions found'" "$OUTPUT_DIR/browser/safari_extensions.txt" "Safari Extensions"
    fi
    
    # Chrome
    if [[ -d "$HOME/Library/Application Support/Google/Chrome" ]]; then
        execute_command "ls -la '$HOME/Library/Application Support/Google/Chrome/Default/Extensions/' 2>/dev/null || echo 'No Chrome extensions found'" \
            "$OUTPUT_DIR/browser/chrome_extensions.txt" "Chrome Extensions"
        execute_command "sqlite3 '$HOME/Library/Application Support/Google/Chrome/Default/History' 'SELECT url, visit_count FROM urls ORDER BY visit_count DESC LIMIT 20' 2>/dev/null || echo 'Chrome history not accessible'" \
            "$OUTPUT_DIR/browser/chrome_top_sites.txt" "Chrome Top Sites"
    fi
    
    # Firefox
    if [[ -d "$HOME/Library/Application Support/Firefox" ]]; then
        local profile
        profile=$(find "$HOME/Library/Application Support/Firefox/Profiles" -name "*.default*" -type d 2>/dev/null | head -1)
        if [[ -n "$profile" ]]; then
            execute_command "ls -la '$profile/extensions/' 2>/dev/null || echo 'No Firefox extensions found'" "$OUTPUT_DIR/browser/firefox_extensions.txt" "Firefox Extensions"
        fi
    fi
    
    # Analysis
    for browser_file in "$OUTPUT_DIR/browser/"*extensions*.txt; do
        [[ -f "$browser_file" ]] && analyze_file "$browser_file" "suspicious_extension"
    done
    
    for history_file in "$OUTPUT_DIR/browser/"*top_sites*.txt; do
        [[ -f "$history_file" ]] && analyze_file "$history_file" "browser_hijack"
    done
    
    log "INFO" "Browser security assessment completed"
}

assess_filesystem() {
    log "INFO" "Starting Filesystem Scan..."
    
    # Temporary directories
    execute_command "find /tmp /var/tmp -type f -name '.*' -maxdepth 3 -ls 2>/dev/null | head -100" \
        "$OUTPUT_DIR/filesystem/hidden_tmp_files.txt" "Hidden files in temp directories"
    execute_command "find /tmp /var/tmp -type f \\( -name '*.sh' -o -name '*.py' -o -name '*.rb' -o -name '*.pl' \\) -maxdepth 3 -ls 2>/dev/null | head -100" \
        "$OUTPUT_DIR/filesystem/scripts_in_tmp.txt" "Scripts in temp directories"
    
    # User directories suspicious files
    local user_dirs=("Downloads" "Desktop" "Documents")
    for dir in "${user_dirs[@]}"; do
        if [[ -d "$HOME/$dir" ]]; then
            execute_command "find '$HOME/$dir' -type f \\( -name '.*' -a \\( -name '*.sh' -o -name '*.command' -o -name '*.py' \\) \\) -maxdepth 2 -ls 2>/dev/null | head -50" \
                "$OUTPUT_DIR/filesystem/hidden_executables_$dir.txt" "Hidden executables in $dir"
        fi
    done
    
    # Recently modified system files
    execute_command "find /usr/bin /usr/sbin -type f -mtime -30 -ls 2>/dev/null | head -100" \
        "$OUTPUT_DIR/filesystem/recently_modified_system_files.txt" "Recently modified system files" true
    
    # World-writable files (limited scope for performance)
    execute_command "find /tmp /var/tmp -perm -002 -type f -ls 2>/dev/null | head -100" \
        "$OUTPUT_DIR/filesystem/world_writable_files.txt" "World-writable files in temp" false 30
    
    # SUID/SGID files (limited scope)
    execute_command "find /usr/local -perm -4000 -o -perm -2000 -type f -ls 2>/dev/null | head -50" \
        "$OUTPUT_DIR/filesystem/suid_sgid_files.txt" "Non-standard SUID/SGID files" true 30
    
    # Analysis
    analyze_file "$OUTPUT_DIR/filesystem/hidden_tmp_files.txt" "hidden_executable"
    analyze_file "$OUTPUT_DIR/filesystem/scripts_in_tmp.txt" "temp_executable"
    
    for file in "$OUTPUT_DIR/filesystem/hidden_executables_"*.txt; do
        [[ -f "$file" ]] && analyze_file "$file" "hidden_executable"
    done
    
    analyze_file "$OUTPUT_DIR/filesystem/recently_modified_system_files.txt" "suspicious_binary_location"
    
    log "INFO" "Filesystem scan completed"
}

assess_logs() {
    log "INFO" "Starting Log Analysis..."
    
    # Unified logging (macOS 10.12+)
    if command -v log &>/dev/null; then
        execute_command "log show --style syslog --last 1h --predicate 'process == \"sudo\"' 2>/dev/null | head -500" \
            "$OUTPUT_DIR/logs/sudo_activity.txt" "Recent sudo activity"
        execute_command "log show --style syslog --last 1d --predicate 'eventMessage contains \"authentication failure\"' 2>/dev/null | head -500" \
            "$OUTPUT_DIR/logs/auth_failures.txt" "Authentication failures"
        execute_command "log show --style syslog --last 1d --predicate 'eventMessage contains[c] \"error\" OR eventMessage contains[c] \"fail\"' 2>/dev/null | head -1000" \
            "$OUTPUT_DIR/logs/errors_and_failures.txt" "System errors and failures"
        execute_command "log show --style syslog --last 1h --predicate 'subsystem == \"com.apple.securityd\"' 2>/dev/null | head -500" \
            "$OUTPUT_DIR/logs/security_subsystem.txt" "Security subsystem logs"
    fi
    
    # Traditional logs
    local log_files=(
        "/var/log/system.log"
        "/var/log/install.log"
        "/var/log/wifi.log"
    )
    
    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            local log_name
            log_name=$(basename "$log_file")
            execute_command "tail -5000 '$log_file' 2>/dev/null || echo 'Log not accessible'" "$OUTPUT_DIR/logs/$log_name" "Log: $log_name" true
        fi
    done
    
    # ASL logs
    execute_command "syslog -F std -T utc 2>/dev/null | tail -1000 || echo 'Syslog not accessible'" "$OUTPUT_DIR/logs/asl_recent.txt" "Recent ASL logs"
    
    # Analysis
    analyze_file "$OUTPUT_DIR/logs/auth_failures.txt" "auth_failure_spike"
    analyze_file "$OUTPUT_DIR/logs/sudo_activity.txt" "privilege_escalation"
    analyze_file "$OUTPUT_DIR/logs/errors_and_failures.txt" "log_deletion"
    
    # Check for suspicious patterns across all logs
    for log_file in "$OUTPUT_DIR/logs/"*.txt "$OUTPUT_DIR/logs/"*.log; do
        if [[ -f "$log_file" ]]; then
            analyze_file "$log_file" "backdoor_pattern"
            analyze_file "$log_file" "cryptominer"
            analyze_file "$log_file" "known_malware"
        fi
    done
    
    log "INFO" "Log analysis completed"
}

# ============================================================================
# ENHANCED REPORTING
# ============================================================================

generate_report() {
    log "INFO" "Generating comprehensive security report..."
    
    # Calculate risk level
    local risk_level="Low"
    local risk_color=$COLOR_GREEN
    local risk_emoji="✅"
    
    if (( CRITICAL_FINDINGS > 0 )) || (( THREAT_SCORE > 200 )); then
        risk_level="Critical"
        risk_color=$COLOR_RED
        risk_emoji="🚨"
    elif (( HIGH_FINDINGS > 0 )) || (( THREAT_SCORE > 100 )); then
        risk_level="High"
        risk_color=$COLOR_RED  
        risk_emoji="⚠️"
    elif (( MEDIUM_FINDINGS > 0 )) || (( THREAT_SCORE > 50 )); then
        risk_level="Medium"
        risk_color=$COLOR_YELLOW
        risk_emoji="🔶"
    elif (( THREAT_SCORE > 20 )); then
        risk_level="Low"
        risk_color=$COLOR_GREEN
        risk_emoji="✅"
    else
        risk_level="Minimal"
        risk_color=$COLOR_GREEN
        risk_emoji="✅"
    fi
    
    # Generate Markdown report
    cat > "$REPORT_FILE" << EOF
# macOS Security Assessment Report

**Generated**: $CURRENT_DATE  
**System**: macOS $(sw_vers -productVersion 2>/dev/null || echo "Unknown")  
**Architecture**: $ARCH (Apple Silicon: $IS_APPLE_SILICON)  
**Assessment Mode**: $ASSESSMENT_MODE  
**Script Version**: $SCRIPT_VERSION  

---

## Executive Summary

### $risk_emoji Overall Risk Assessment: **$risk_level**

| Metric | Value |
|--------|-------|
| **Total Threat Score** | $THREAT_SCORE |
| **Critical Findings** | $CRITICAL_FINDINGS |
| **High Risk Findings** | $HIGH_FINDINGS |
| **Medium Risk Findings** | $MEDIUM_FINDINGS |
| **Low Risk Findings** | $LOW_FINDINGS |

### Assessment Summary

EOF

    # Add risk-appropriate summary
    case "$risk_level" in
        "Critical")
            cat >> "$REPORT_FILE" << EOF
**🚨 IMMEDIATE ACTION REQUIRED**: Critical security issues detected that require immediate attention. 
Your system shows signs of potential compromise or severe misconfiguration. 
Review the critical findings below and take immediate remediation steps.

EOF
            ;;
        "High")
            cat >> "$REPORT_FILE" << EOF
**⚠️ HIGH RISK DETECTED**: Significant security issues found that should be addressed promptly.
Your system has important security gaps that could be exploited.
Review and remediate the high-priority findings as soon as possible.

EOF
            ;;
        "Medium")
            cat >> "$REPORT_FILE" << EOF
**🔶 MODERATE RISK**: Some security issues detected that warrant attention.
While not immediately critical, these findings should be reviewed and addressed
to improve your system's security posture.

EOF
            ;;
        *)
            cat >> "$REPORT_FILE" << EOF
**✅ GOOD SECURITY POSTURE**: Your system shows good security configuration overall.
Only minor issues were detected. Continue to maintain good security practices
and stay vigilant.

EOF
            ;;
    esac
    
    # System Status Overview
    cat >> "$REPORT_FILE" << EOF
### System Security Status

| Security Feature | Status | Risk |
|-----------------|--------|------|
EOF
    
    # Check key security features
    local sip_status="Unknown"
    local gatekeeper_status="Unknown"
    local filevault_status="Unknown"
    local firewall_status="Unknown"
    
    [[ -f "$OUTPUT_DIR/system/sip_status.txt" ]] && {
        grep -q "enabled" "$OUTPUT_DIR/system/sip_status.txt" && sip_status="✅ Enabled" || sip_status="❌ Disabled"
    }
    [[ -f "$OUTPUT_DIR/system/gatekeeper_status.txt" ]] && {
        grep -q "enabled" "$OUTPUT_DIR/system/gatekeeper_status.txt" && gatekeeper_status="✅ Enabled" || gatekeeper_status="❌ Disabled"
    }
    [[ -f "$OUTPUT_DIR/system/filevault_status.txt" ]] && {
        grep -q "On" "$OUTPUT_DIR/system/filevault_status.txt" && filevault_status="✅ Enabled" || filevault_status="❌ Disabled"
    }
    [[ -f "$OUTPUT_DIR/network/firewall_state.txt" ]] && {
        grep -q "1" "$OUTPUT_DIR/network/firewall_state.txt" && firewall_status="✅ Enabled" || firewall_status="❌ Disabled"
    }
    
    cat >> "$REPORT_FILE" << EOF
| System Integrity Protection (SIP) | $sip_status | $([ "$sip_status" = "✅ Enabled" ] && echo "Low" || echo "Critical") |
| Gatekeeper | $gatekeeper_status | $([ "$gatekeeper_status" = "✅ Enabled" ] && echo "Low" || echo "High") |
| FileVault Encryption | $filevault_status | $([ "$filevault_status" = "✅ Enabled" ] && echo "Low" || echo "High") |
| Application Firewall | $firewall_status | $([ "$firewall_status" = "✅ Enabled" ] && echo "Low" || echo "Medium") |

---

## Detailed Findings

EOF
    
    # Add findings by severity
    if [[ -s "$IOC_FILE" ]]; then
        echo "### Security Findings by Severity" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        
        # Group findings by severity
        for severity in "CRITICAL" "HIGH" "MEDIUM" "LOW"; do
            local findings
            findings=$(grep -A 10 "Severity: $severity" "$IOC_FILE" 2>/dev/null || true)
            if [[ -n "$findings" ]]; then
                echo "#### $severity Severity Findings" >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
                echo '```' >> "$REPORT_FILE"
                echo "$findings" | head -100 >> "$REPORT_FILE"
                echo '```' >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
            fi
        done
    else
        echo "### No Security Issues Detected" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "The assessment did not identify any security issues matching the configured patterns." >> "$REPORT_FILE"
    fi
    
    # Add recommendations
    cat >> "$REPORT_FILE" << EOF

---

## Recommendations

### Immediate Actions (if applicable)

EOF
    
    if (( CRITICAL_FINDINGS > 0 )); then
        cat >> "$REPORT_FILE" << EOF
1. **Isolate the System**: If malware or backdoors were detected, consider disconnecting from network
2. **Change Credentials**: Reset all passwords and revoke suspicious certificates
3. **Enable Security Features**: Immediately enable any disabled security features (SIP, Gatekeeper, FileVault)
4. **Run Full Malware Scan**: Use additional malware scanning tools for comprehensive cleaning
5. **Review Persistence Mechanisms**: Check all LaunchAgents/Daemons and remove unauthorized entries

EOF
    fi
    
    cat >> "$REPORT_FILE" << EOF
### General Security Hardening

1. **Keep macOS Updated**: Install all security updates promptly
2. **Enable All Security Features**: Ensure SIP, Gatekeeper, FileVault, and Firewall are enabled
3. **Review Installed Applications**: Remove unused or suspicious applications
4. **Audit User Accounts**: Ensure all accounts are legitimate and have appropriate permissions
5. **Regular Security Assessments**: Run this tool periodically to monitor security posture
6. **Backup Important Data**: Maintain regular backups using Time Machine or other solutions
7. **Use Strong Authentication**: Enable two-factor authentication where possible
8. **Monitor System Activity**: Regularly check Activity Monitor and system logs

### Security Resources

- [Apple Security Updates](https://support.apple.com/en-us/HT201222)
- [macOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Objective-See Security Tools](https://objective-see.com/tools.html)

---

## Technical Details

### Assessment Coverage

- Total Checks Performed: $PROGRESS_COUNTER
- IOC Patterns Checked: $(echo "$IOC_DEFINITIONS" | grep -c '^[^#]' | tr -d ' ')
- Files Analyzed: $(find "$OUTPUT_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
- Data Collected: $(du -sh "$OUTPUT_DIR" 2>/dev/null | awk '{print $1}')

### File Integrity

All collected files have been hashed for integrity verification. 
See \`file_hashes.json\` for SHA-256 hashes of all output files.

---

*Report generated by $SCRIPT_NAME v$SCRIPT_VERSION*  
*For questions or updates: security-team@company.com*
EOF
    
    # Generate HTML report if requested
    if $HTML_OUTPUT; then
        generate_html_report
    fi
}

generate_html_report() {
    log "INFO" "Generating HTML report..."
    
    # First, create the HTML file with placeholders
    cat > "$HTML_REPORT_FILE" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>macOS Security Assessment Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f7;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .risk-critical { color: #dc2626; font-weight: bold; }
        .risk-high { color: #f59e0b; font-weight: bold; }
        .risk-medium { color: #f59e0b; }
        .risk-low { color: #10b981; }
        .card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 1.5rem;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        .stat-card {
            background: #f9fafb;
            padding: 1rem;
            border-radius: 6px;
            text-align: center;
            border: 1px solid #e5e7eb;
        }
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            margin: 0.5rem 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        th {
            background: #f9fafb;
            font-weight: 600;
        }
        .finding {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 4px;
        }
        .finding.critical {
            background: #fee2e2;
            border-left-color: #dc2626;
        }
        .finding.high {
            background: #fed7aa;
            border-left-color: #ea580c;
        }
        .remediation {
            background: #dbeafe;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            margin-top: 0.5rem;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e5e7eb;
            border-radius: 10px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #10b981 0%, #f59e0b 50%, #dc2626 100%);
            transition: width 0.3s ease;
        }
        pre {
            background: #1f2937;
            color: #f3f4f6;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin: 2rem 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>macOS Security Assessment Report</h1>
        <p>Generated: REPORT_DATE</p>
        <p>System: SYSTEM_VERSION | Assessment Mode: ASSESSMENT_MODE</p>
    </div>
    
    <div class="card">
        <h2>Executive Summary</h2>
        <p class="RISK_CLASS">Overall Risk Level: <strong>RISK_LEVEL</strong></p>
        
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-number risk-critical">CRITICAL_COUNT</div>
                <div>Critical Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number risk-high">HIGH_COUNT</div>
                <div>High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number risk-medium">MEDIUM_COUNT</div>
                <div>Medium Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number risk-low">LOW_COUNT</div>
                <div>Low Risk</div>
            </div>
        </div>
        
        <div class="progress-bar">
            <div class="progress-fill" style="width: THREAT_PERCENTAGE%;"></div>
        </div>
        <p>Threat Score: THREAT_SCORE / 500</p>
    </div>
    
    <div class="card">
        <h2>Security Status Overview</h2>
        <table>
            <tr>
                <th>Security Feature</th>
                <th>Status</th>
                <th>Risk Level</th>
            </tr>
            <tr>
                <td>System Integrity Protection (SIP)</td>
                <td>SIP_STATUS</td>
                <td>SIP_RISK</td>
            </tr>
            <tr>
                <td>Gatekeeper</td>
                <td>GATEKEEPER_STATUS</td>
                <td>GATEKEEPER_RISK</td>
            </tr>
            <tr>
                <td>FileVault Encryption</td>
                <td>FILEVAULT_STATUS</td>
                <td>FILEVAULT_RISK</td>
            </tr>
            <tr>
                <td>Application Firewall</td>
                <td>FIREWALL_STATUS</td>
                <td>FIREWALL_RISK</td>
            </tr>
        </table>
    </div>
</body>
</html>
EOF
    
    # Replace placeholders with actual values using a more portable method
    local threat_percentage=$((THREAT_SCORE * 100 / 500))
    [[ $threat_percentage -gt 100 ]] && threat_percentage=100
    
    # Get security status values
    local sip_status="Unknown"
    local gatekeeper_status="Unknown"
    local filevault_status="Unknown"
    local firewall_status="Unknown"
    
    [[ -f "$OUTPUT_DIR/system/sip_status.txt" ]] && {
        grep -q "enabled" "$OUTPUT_DIR/system/sip_status.txt" && sip_status="✅ Enabled" || sip_status="❌ Disabled"
    }
    [[ -f "$OUTPUT_DIR/system/gatekeeper_status.txt" ]] && {
        grep -q "enabled" "$OUTPUT_DIR/system/gatekeeper_status.txt" && gatekeeper_status="✅ Enabled" || gatekeeper_status="❌ Disabled"
    }
    [[ -f "$OUTPUT_DIR/system/filevault_status.txt" ]] && {
        grep -q "On" "$OUTPUT_DIR/system/filevault_status.txt" && filevault_status="✅ Enabled" || filevault_status="❌ Disabled"
    }
    [[ -f "$OUTPUT_DIR/network/firewall_state.txt" ]] && {
        grep -q "1" "$OUTPUT_DIR/network/firewall_state.txt" && firewall_status="✅ Enabled" || firewall_status="❌ Disabled"
    }
    
    # Create temporary file for replacements
    local temp_html="${HTML_REPORT_FILE}.tmp"
    cp "$HTML_REPORT_FILE" "$temp_html"
    
    # Convert risk level to lowercase for CSS class
    local risk_class="risk-$(echo "$risk_level" | tr '[:upper:]' '[:lower:]')"
    
    # Use perl for portable in-place substitution
    if command -v perl >/dev/null 2>&1; then
        perl -pi -e "s/REPORT_DATE/$CURRENT_DATE/g" "$temp_html"
        perl -pi -e "s/SYSTEM_VERSION/$(sw_vers -productVersion 2>/dev/null || echo 'Unknown')/g" "$temp_html"
        perl -pi -e "s/ASSESSMENT_MODE/$ASSESSMENT_MODE/g" "$temp_html"
        perl -pi -e "s/RISK_LEVEL/$risk_level/g" "$temp_html"
        perl -pi -e "s/RISK_CLASS/$risk_class/g" "$temp_html"
        perl -pi -e "s/CRITICAL_COUNT/$CRITICAL_FINDINGS/g" "$temp_html"
        perl -pi -e "s/HIGH_COUNT/$HIGH_FINDINGS/g" "$temp_html"
        perl -pi -e "s/MEDIUM_COUNT/$MEDIUM_FINDINGS/g" "$temp_html"
        perl -pi -e "s/LOW_COUNT/$LOW_FINDINGS/g" "$temp_html"
        perl -pi -e "s/THREAT_SCORE/$THREAT_SCORE/g" "$temp_html"
        perl -pi -e "s/THREAT_PERCENTAGE/$threat_percentage/g" "$temp_html"
        perl -pi -e "s/SIP_STATUS/$sip_status/g" "$temp_html"
        perl -pi -e "s/GATEKEEPER_STATUS/$gatekeeper_status/g" "$temp_html"
        perl -pi -e "s/FILEVAULT_STATUS/$filevault_status/g" "$temp_html"
        perl -pi -e "s/FIREWALL_STATUS/$firewall_status/g" "$temp_html"
        perl -pi -e "s/SIP_RISK/$([ "$sip_status" = "✅ Enabled" ] && echo "Low" || echo "Critical")/g" "$temp_html"
        perl -pi -e "s/GATEKEEPER_RISK/$([ "$gatekeeper_status" = "✅ Enabled" ] && echo "Low" || echo "High")/g" "$temp_html"
        perl -pi -e "s/FILEVAULT_RISK/$([ "$filevault_status" = "✅ Enabled" ] && echo "Low" || echo "High")/g" "$temp_html"
        perl -pi -e "s/FIREWALL_RISK/$([ "$firewall_status" = "✅ Enabled" ] && echo "Low" || echo "Medium")/g" "$temp_html"
    else
        # Fallback: Use awk if perl is not available
        log "WARNING" "Using fallback method for HTML generation"
        # Create a simple HTML report without complex replacements
        cat > "$temp_html" << EOFHTML
<!DOCTYPE html>
<html>
<head>
    <title>macOS Security Assessment Report</title>
    <style>
        body { font-family: -apple-system, sans-serif; margin: 20px; background: #f5f5f7; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .critical { color: #dc2626; font-weight: bold; }
        .high { color: #f59e0b; font-weight: bold; }
        .medium { color: #eab308; }
        .low { color: #10b981; }
    </style>
</head>
<body>
    <div class="container">
        <h1>macOS Security Assessment Report</h1>
        <p><strong>Generated:</strong> $CURRENT_DATE</p>
        <p><strong>System:</strong> macOS $(sw_vers -productVersion 2>/dev/null || echo "Unknown")</p>
        <p><strong>Assessment Mode:</strong> $ASSESSMENT_MODE</p>
        
        <h2>Summary</h2>
        <p><strong>Overall Risk Level:</strong> $risk_level</p>
        <p><strong>Threat Score:</strong> $THREAT_SCORE</p>
        
        <table>
            <tr>
                <th>Finding Type</th>
                <th>Count</th>
            </tr>
            <tr>
                <td class="critical">Critical</td>
                <td>$CRITICAL_FINDINGS</td>
            </tr>
            <tr>
                <td class="high">High</td>
                <td>$HIGH_FINDINGS</td>
            </tr>
            <tr>
                <td class="medium">Medium</td>
                <td>$MEDIUM_FINDINGS</td>
            </tr>
            <tr>
                <td class="low">Low</td>
                <td>$LOW_FINDINGS</td>
            </tr>
        </table>
        
        <h2>Security Status</h2>
        <table>
            <tr>
                <th>Feature</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>SIP</td>
                <td>$sip_status</td>
            </tr>
            <tr>
                <td>Gatekeeper</td>
                <td>$gatekeeper_status</td>
            </tr>
            <tr>
                <td>FileVault</td>
                <td>$filevault_status</td>
            </tr>
            <tr>
                <td>Firewall</td>
                <td>$firewall_status</td>
            </tr>
        </table>
        
        <p><em>See the markdown report for detailed findings and recommendations.</em></p>
    </div>
</body>
</html>
EOFHTML
    fi
    
    # Move temp file to final location
    mv "$temp_html" "$HTML_REPORT_FILE"
    
    log "SUCCESS" "HTML report generated: $HTML_REPORT_FILE"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    parse_args "$@"
    
    # Setup output directory
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="./assessment_$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Define output files
    readonly LOG_FILE="$OUTPUT_DIR/assessment.log"
    readonly REPORT_FILE="$OUTPUT_DIR/security_report.md"
    readonly HTML_REPORT_FILE="$OUTPUT_DIR/security_report.html"
    readonly HASH_FILE="$OUTPUT_DIR/file_hashes.json"
    readonly IOC_FILE="$OUTPUT_DIR/findings.txt"
    readonly JSONL_REPORT_FILE="$OUTPUT_DIR/findings.jsonl"
    
    # Create directory structure
    mkdir -p "$OUTPUT_DIR"/{system,network,security,persistence,apps,processes,browser,filesystem,logs,kernel}
    mkdir -p "$OUTPUT_DIR"/{apps/details,persistence/plists,signatures/apps,signatures/kexts}
    
    # Initialize
    init_logging
    trap cleanup EXIT
    
    # Banner
    echo -e "${COLOR_BLUE}╔═══════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_BLUE}║     macOS Security Assessment v$SCRIPT_VERSION      ║${COLOR_RESET}"
    echo -e "${COLOR_BLUE}╚═══════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    
    # Pre-checks
    check_dependencies
    check_privileges "$@"
    detect_capabilities
    
    # Merge custom IOCs with built-in
    if [[ -f "$EXTERNAL_IOC_FILE" ]]; then
        load_external_iocs "$EXTERNAL_IOC_FILE"
    fi
    
    # Interactive mode
    if $INTERACTIVE_MODE; then
        run_interactive_mode
    fi
    
    # Count checks for progress tracking
    count_total_checks
    PROGRESS_COUNTER=0
    
    # Encryption setup
    if $ENCRYPT_OUTPUT; then
        generate_password
        display_password
        read -n 1 -s -r -p "Press any key to continue after saving the password..."
        echo ""
    fi
    
    # Initialize report files
    echo "# Security Assessment Findings" > "$IOC_FILE"
    echo "# Generated: $CURRENT_DATE" >> "$IOC_FILE"
    echo "" >> "$IOC_FILE"
    
    if $JSON_OUTPUT; then
        touch "$JSONL_REPORT_FILE"
    fi
    
    # Run assessment based on mode
    log "INFO" "Starting $ASSESSMENT_MODE assessment..."
    echo ""
    
    case "$ASSESSMENT_MODE" in
        "quick")
            assess_system_info
            assess_kernel_signing
            assess_applications
            ;;
        "standard")
            assess_system_info
            assess_kernel_signing
            assess_network
            assess_security
            assess_persistence
            assess_applications
            assess_processes
            assess_browser_security
            ;;
        "full")
            assess_system_info
            assess_kernel_signing
            assess_network
            assess_security
            assess_persistence
            assess_applications
            assess_processes
            assess_browser_security
            assess_filesystem
            assess_logs
            ;;
    esac
    
    echo ""
    
    # Generate reports
    generate_report
    
    # Finalize hash file
    if [[ -f "$HASH_FILE.tmp" ]]; then
        echo "[" > "$HASH_FILE"
        sed '$!s/$/,/' "$HASH_FILE.tmp" >> "$HASH_FILE"
        echo "]" >> "$HASH_FILE"
        rm -f "$HASH_FILE.tmp"
    fi
    
    # Create archive
    log "INFO" "Creating assessment archive..."
    local archive_name="${OUTPUT_DIR}.tar.gz"
    
    if $ENCRYPT_OUTPUT; then
        tar -czf - -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" | \
            openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -out "${archive_name}.enc" -pass pass:"$ENCRYPTION_PASSWORD"
        
        if [[ $? -eq 0 ]]; then
            log "SUCCESS" "Encrypted archive created: ${archive_name}.enc"
            echo "To decrypt: openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in ${archive_name}.enc -out ${archive_name} -pass pass:PASSWORD" > "${OUTPUT_DIR}_decrypt_instructions.txt"
            
            read -p "Remove unencrypted assessment directory? (y/N): " remove_unencrypted
            if [[ "$remove_unencrypted" =~ ^[Yy]$ ]]; then
                rm -rf "$OUTPUT_DIR"
                log "INFO" "Unencrypted directory removed"
            fi
        else
            log "ERROR" "Encryption failed, creating unencrypted archive"
            tar -czf "$archive_name" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"
        fi
    else
        tar -czf "$archive_name" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"
        log "SUCCESS" "Archive created: $archive_name"
    fi
    
    # Final summary
    echo ""
    echo -e "${COLOR_GREEN}╔═══════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║          Assessment Complete                  ║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}╚═══════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    echo "Summary:"
    echo "  • Threat Score: $THREAT_SCORE"
    echo "  • Critical Findings: $CRITICAL_FINDINGS"
    echo "  • High Risk Findings: $HIGH_FINDINGS"
    echo "  • Medium Risk Findings: $MEDIUM_FINDINGS"
    echo "  • Low Risk Findings: $LOW_FINDINGS"
    echo ""
    echo "Reports:"
    echo "  • Detailed Report: $REPORT_FILE"
    $HTML_OUTPUT && echo "  • HTML Report: $HTML_REPORT_FILE"
    $JSON_OUTPUT && echo "  • JSON Data: $JSONL_REPORT_FILE"
    echo "  • Findings: $IOC_FILE"
    echo ""
    
    if [[ $THREAT_SCORE -gt 100 ]]; then
        echo -e "${COLOR_RED}⚠️  High risk detected! Review findings immediately.${COLOR_RESET}"
    elif [[ $THREAT_SCORE -gt 20 ]]; then
        echo -e "${COLOR_YELLOW}�� Medium risk detected. Review and remediate findings.${COLOR_RESET}"
    else
        echo -e "${COLOR_GREEN}✅ Low risk detected. Good security posture!${COLOR_RESET}"
    fi
    echo ""
}

# Cleanup function
cleanup() {
    log "INFO" "Running cleanup..."
    
    # Remove password file if it exists
    local pass_file="${OUTPUT_DIR}_password.txt"
    if [[ -f "$pass_file" ]]; then
        rm -f "$pass_file"
        log "INFO" "Temporary password file removed"
    fi
    
    # Remove decryption instructions if directory was deleted
    if [[ ! -d "$OUTPUT_DIR" ]] && [[ -f "${OUTPUT_DIR}_decrypt_instructions.txt" ]]; then
        rm -f "${OUTPUT_DIR}_decrypt_instructions.txt"
    fi
    
    log "INFO" "Assessment finished at $(date '+%Y-%m-%d %H:%M:%S')"
}

# Password generation
generate_password() {
    ENCRYPTION_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom | head -c 32)
}

display_password() {
    local pass_file="${OUTPUT_DIR}_password.txt"
    echo ""
    echo -e "${COLOR_YELLOW}═══════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}            ENCRYPTION PASSWORD                         ${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}═══════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_RED}IMPORTANT: Save this password securely!${COLOR_RESET}"
    echo -e "${COLOR_RED}You will need it to decrypt the assessment archive.${COLOR_RESET}"
    echo ""
    echo -e "Password: ${COLOR_GREEN}${ENCRYPTION_PASSWORD}${COLOR_RESET}"
    echo ""
    echo "$ENCRYPTION_PASSWORD" > "$pass_file"
    echo -e "${COLOR_YELLOW}Password temporarily saved to: ${pass_file}${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}This file will be automatically deleted when done.${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}═══════════════════════════════════════════════════════${COLOR_RESET}"
    echo ""
}

# Privilege check
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log "WARNING" "Not running as root - some checks will be limited"
        echo -e "${COLOR_YELLOW}TIP: For comprehensive assessment, run with sudo:${COLOR_RESET}"
        echo -e "${COLOR_CYAN}     sudo $0 $*${COLOR_RESET}"
        echo ""
        
        # Check if we can get sudo without password
        if ! sudo -n true 2>/dev/null; then
            log "INFO" "Some checks will prompt for password or be skipped"
        fi
    else
        log "SUCCESS" "Running with root privileges"
    fi
}

# File hashing
calculate_hash() {
    local file="$1"
    if [[ -f "$file" ]]; then
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}' || echo "hash_error"
    else
        echo "file_not_found"
    fi
}

# Entry point
main "$@"

# Exit with appropriate code
if (( CRITICAL_FINDINGS > 0 )); then
    exit 3  # Critical findings
elif (( HIGH_FINDINGS > 0 )) || (( THREAT_SCORE > 100 )); then
    exit 2  # High risk
elif (( MEDIUM_FINDINGS > 0 )) || (( THREAT_SCORE > 20 )); then
    exit 1  # Medium risk
else
    exit 0  # Low/no risk
fi

