#!/bin/bash
# Module: TT10-certificates-and-trust
# Report: Section 4.1 – Certificates & Trust Stores
# MITRE:  T1553.002
# Requires: root optional
set -euo pipefail
IFS=$'\n\t'

MODULE_ID="TT10-certificates-and-trust"
REPORT_SECTION="Section 4.1 – Certificates & Trust Stores"
MITRE_TECHNIQUES="T1553.002"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "${SCRIPT_DIR}/lib/common.sh"

init_module "$MODULE_ID"

# System root certificates
echo "$ security find-certificate -a -Z -p /System/Library/Keychains/SystemRootCertificates.keychain > artifacts/system_root_certs.pem"
security find-certificate -a -Z -p /System/Library/Keychains/SystemRootCertificates.keychain \
  > "${OUT_DIR}/artifacts/system_root_certs.pem" 2>&1 || true
add_artifact "${OUT_DIR}/artifacts/system_root_certs.pem"
log_coc "write" "${OUT_DIR}/artifacts/system_root_certs.pem" "System root CAs" "security" "macOS"

# User and system identities (codesigning)
echo "$ security find-identity -v -p codesigning > artifacts/codesign_identities.txt"
security find-identity -v -p codesigning \
  > "${OUT_DIR}/artifacts/codesign_identities.txt" 2>&1 || true
add_artifact "${OUT_DIR}/artifacts/codesign_identities.txt"
log_coc "write" "${OUT_DIR}/artifacts/codesign_identities.txt" "Codesign identities" "security" "macOS"

# Keychain list
echo "$ security list-keychains > artifacts/keychains_list.txt"
security list-keychains \
  > "${OUT_DIR}/artifacts/keychains_list.txt" 2>&1 || true
add_artifact "${OUT_DIR}/artifacts/keychains_list.txt"
log_coc "write" "${OUT_DIR}/artifacts/keychains_list.txt" "Keychains list" "security" "macOS"

{
  echo "TT10 – Certificates & Trust"
  echo "Collected: root CAs, codesign identities, keychain list."
  echo "Review for malicious CAs or anomalous identities."
} | head -20 > "${OUT_DIR}/summary.txt"

write_manifest || true
finish_module
