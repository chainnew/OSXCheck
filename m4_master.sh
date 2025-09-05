#!/bin/bash
# Orchestrator: Apple Silicon M4 Forensic Framework (TT## modules)
# Discovers and runs scripts/TT[0-9][0-9]-*.sh in order, building evidence tree.
# Bash 3.2 compatible. No auto-sudo.
set -euo pipefail
IFS=$'\n\t'

# Configuration with defaults
: "${EVIDENCE_ROOT:=./evidence}"
: "${INVESTIGATOR:=unknown}"
: "${DEVICE_ID:=$(hostname)}"
: "${MEMORY_MODE:=lite}"
: "${CONCURRENCY:=1}"
: "${VERBOSE:=1}"
: "${MAX_MODULE_TIME:=3600}"  # 1 hour max per module

# Create run ID and directories
RUN_ID="${RUN_ID:-run-$(date -u +%Y-%m-%dT%H-%M-%SZ)}"
RUN_DIR="${EVIDENCE_ROOT}/${RUN_ID}"
REPORT_DIR="${RUN_DIR}/report"
MASTER_LOG="${RUN_DIR}/m4_master.log"
COC_FILE="${RUN_DIR}/CHAIN_OF_CUSTODY.jsonl"

# Create directories
mkdir -p "${RUN_DIR}" "${REPORT_DIR}"
touch "${COC_FILE}"

# Redirect output to log file
exec > >(tee -a "${MASTER_LOG}") 2>&1

# Logging functions
log_info() {
    echo "[*] $*"
}

log_warning() {
    echo "[!] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

# Main execution
log_info "m4_master start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log_info "Evidence Root: ${EVIDENCE_ROOT}"
log_info "Run ID: ${RUN_ID}"
log_info "Investigator: ${INVESTIGATOR} | Device: ${DEVICE_ID}"
log_info "MEMORY_MODE=${MEMORY_MODE} CONCURRENCY=${CONCURRENCY} VERBOSE=${VERBOSE}"

# Check for required tools
for tool in jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        log_error "Required tool '$tool' not found in PATH"
        exit 1
    fi
done

# Discover modules
MODULES=$(LC_ALL=C ls -1 scripts/TT[0-9][0-9]-*.sh 2>/dev/null | sort)
if [ -z "${MODULES}" ]; then
    log_error "No modules found under scripts/TT##-*.sh"
    exit 2
fi

# Function to create report outline
outline_header() {
    local f="$1"
    {
        echo "# M4 Forensic Report Outline"
        echo "Run: ${RUN_ID}"
        echo "Investigator: ${INVESTIGATOR}"
        echo "Device: ${DEVICE_ID}"
        echo "Evidence Root: ${EVIDENCE_ROOT}/${RUN_ID}"
        echo
    } > "$f"
}

# Function to append module info to outline
outline_append_module() {
    local mod_id="$1"
    local out_dir="${EVIDENCE_ROOT}/${RUN_ID}/${mod_id}"
    local meta="${out_dir}/meta.env"
    local summary="${out_dir}/summary.txt"
    local report_section="${mod_id}"
    local mitre=""
    
    if [ -f "$meta" ]; then
        # shellcheck disable=SC1090
        . "$meta" 2>/dev/null || true
        [ -n "${REPORT_SECTION:-}" ] && report_section="$REPORT_SECTION"
        [ -n "${MITRE_TECHNIQUES:-}" ] && mitre="$MITRE_TECHNIQUES"
    fi
    
    {
        echo "## ${mod_id}"
        echo "Section: ${report_section}"
        [ -n "$mitre" ] && echo "MITRE: ${mitre}"
        echo "Summary:"
        if [ -f "$summary" ]; then
            sed -n '1,20p' "$summary"
        else
            echo "(no summary.txt)"
        fi
        echo "Logs: ${out_dir}/full.log"
        echo "Manifest: ${out_dir}/manifest.json"
        echo
    } >> "${REPORT_DIR}/outline.md"
}

# Initialize outline
outline_header "${REPORT_DIR}/outline.md"

# Export environment variables for modules
export EVIDENCE_ROOT RUN_ID INVESTIGATOR DEVICE_ID MEMORY_MODE VERBOSE

# Function to run a module with timeout
run_module() {
    local module="$1"
    local mod_id=$(basename "$module" .sh)
    
    log_info "=== Running ${mod_id} ==="
    
    # Set up module-specific environment
    local module_dir="${EVIDENCE_ROOT}/${RUN_ID}/${mod_id}"
    mkdir -p "${module_dir}/artifacts"
    
    # Run module with timeout
    if timeout "$MAX_MODULE_TIME" bash "$module"; then
        log_info "=== Completed ${mod_id} ==="
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_error "Module ${mod_id} timed out after ${MAX_MODULE_TIME} seconds"
        else
            log_error "Module ${mod_id} failed with exit code $exit_code"
        fi
        return 1
    fi
}

# Run modules
for m in ${MODULES}; do
    mod_id=$(basename "$m" .sh)
    
    # Create chain of custody entry for module start
    echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"action\":\"start\",\"operator\":\"${INVESTIGATOR}\",\"evidence_id\":\"${mod_id}\",\"details\":\"Module execution started\"}" >> "${COC_FILE}"
    
    # Run the module
    if run_module "$m"; then
        # Create chain of custody entry for successful completion
        echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"action\":\"complete\",\"operator\":\"${INVESTIGATOR}\",\"evidence_id\":\"${mod_id}\",\"details\":\"Module execution completed successfully\"}" >> "${COC_FILE}"
    else
        # Create chain of custody entry for failed completion
        echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"action\":\"fail\",\"operator\":\"${INVESTIGATOR}\",\"evidence_id\":\"${mod_id}\",\"details\":\"Module execution failed\"}" >> "${COC_FILE}"
    fi
    
    # Add module to outline
    outline_append_module "$mod_id"
done

# Generate final report
{
    echo "# M4 Forensic Collection Report"
    echo
    echo "## Collection Summary"
    echo "- **Run ID**: ${RUN_ID}"
    echo "- **Investigator**: ${INVESTIGATOR}"
    echo "- **Device**: ${DEVICE_ID}"
    echo "- **Start Time**: $(head -1 "${MASTER_LOG}" | cut -d' ' -f4-)"
    echo "- **End Time**: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "- **Evidence Root**: ${EVIDENCE_ROOT}/${RUN_ID}"
    echo
    echo "## Modules Executed"
    echo "| Module | Status | Section | MITRE | Summary |"
    echo "|--------|--------|---------|-------|---------|"
    
    # Process each module
    for m in ${MODULES}; do
        mod_id=$(basename "$m" .sh)
        local out_dir="${EVIDENCE_ROOT}/${RUN_ID}/${mod_id}"
        local meta="${out_dir}/meta.env"
        local summary="${out_dir}/summary.txt"
        local report_section="${mod_id}"
        local mitre=""
        local status="✓"
        
        # Check if module completed successfully
        if [ ! -f "${out_dir}/full.log" ] || ! grep -q "=== Completed ${mod_id} ===" "${out_dir}/full.log"; then
            status="✗"
        fi
        
        # Load metadata
        if [ -f "$meta" ]; then
            # shellcheck disable=SC1090
            . "$meta" 2>/dev/null || true
            [ -n "${REPORT_SECTION:-}" ] && report_section="$REPORT_SECTION"
            [ -n "${MITRE_TECHNIQUES:-}" ] && mitre="$MITRE_TECHNIQUES"
        fi
        
        # Get first line of summary
        local summary_text="(no summary)"
        if [ -f "$summary" ]; then
            summary_text=$(head -1 "$summary" | sed 's/|/\\|/g')
        fi
        
        echo "| ${mod_id} | ${status} | ${report_section} | ${mitre} | ${summary_text} |"
    done
    
    echo
    echo "## Chain of Custody"
    echo "Total entries: $(wc -l < "${COC_FILE}")"
    echo
    echo "### First 3 entries:"
    head -3 "${COC_FILE}" | while IFS= read -r line; do
        echo "$line" | jq .
    done
    
    echo
    echo "### Last 3 entries:"
    tail -3 "${COC_FILE}" | while IFS= read -r line; do
        echo "$line" | jq .
    done
    
    echo
    echo "## Evidence Collection"
    echo "All collected evidence is stored in: ${EVIDENCE_ROOT}/${RUN_ID}"
    echo
    echo "### Directory Structure"
    find "${EVIDENCE_ROOT}/${RUN_ID}" -type d -maxdepth 2 | sort | sed 's/^/- /'
    
} > "${REPORT_DIR}/report.md"

log_info "m4_master end: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log_info "Report generated: ${REPORT_DIR}/report.md"