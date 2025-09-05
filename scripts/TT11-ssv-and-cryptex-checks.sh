#!/bin/bash
# Module: TT11-ssv-and-cryptex-checks
# Report: Section 4.2 – Sealed System Volume & Cryptex
# MITRE:  T1601.001
# Requires: may require root for some queries
set -euo pipefail
IFS=$'\n\t'

MODULE_ID="TT11-ssv-and-cryptex-checks"
REPORT_SECTION="Section 4.2 – Sealed System Volume & Cryptex"
MITRE_TECHNIQUES="T1601.001"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "${SCRIPT_DIR}/lib/common.sh"

init_module "$MODULE_ID"

echo "$ csrutil status > artifacts/csrutil_status.txt"
csrutil status > "${OUT_DIR}/artifacts/csrutil_status.txt" 2>&1 || true
add_artifact "${OUT_DIR}/artifacts/csrutil_status.txt"
log_coc "write" "${OUT_DIR}/artifacts/csrutil_status.txt" "SIP status" "csrutil" "macOS"

echo "$ diskutil apfs list > artifacts/apfs_list.txt"
diskutil apfs list > "${OUT_DIR}/artifacts/apfs_list.txt" 2>&1 || true
add_artifact "${OUT_DIR}/artifacts/apfs_list.txt"
log_coc "write" "${OUT_DIR}/artifacts/apfs_list.txt" "APFS volumes" "diskutil" "macOS"

echo "$ kmutil showloaded > artifacts/kmutil_showloaded.txt"
kmutil showloaded > "${OUT_DIR}/artifacts/kmutil_showloaded.txt" 2>&1 || true
add_artifact "${OUT_DIR}/artifacts/kmutil_showloaded.txt"
log_coc "write" "${OUT_DIR}/artifacts/kmutil_showloaded.txt" "Loaded kernel extensions" "kmutil" "macOS"

{
  echo "TT11 – SSV & Cryptex Checks"
  echo "Collected: SIP status, APFS list, loaded kexts."
  echo "Review for trustcache/SSV anomalies and unexpected kexts."
} | head -20 > "${OUT_DIR}/summary.txt"

write_manifest || true
finish_module
