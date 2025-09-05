#!/usr/bin/env bash
# TT20 – Hardware Attestation: SEP, iBridge, IODeviceTree
# REPORT_SECTION="Hardware & Boot Attestation"
# MITRE_TECHNIQUES="T1542.001,T1553.002"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT20"
MODULE_NAME="hardware-attestation"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

# 1) SPHardwareDataType
system_profiler SPHardwareDataType -xml > "$ARTS/sphardware.xml" 2>/dev/null || true
add_artifact "$ARTS/sphardware.xml" "system_profiler SPHardwareDataType"

# 2) SPiBridgeDataType
system_profiler SPiBridgeDataType -xml > "$ARTS/spibridge.xml" 2>/dev/null || true
add_artifact "$ARTS/spibridge.xml" "system_profiler SPiBridgeDataType"

# 3) SEP / security status (if available)
system_profiler SPSecureElementDataType -xml > "$ARTS/spsecureelement.xml" 2>/dev/null || true
add_artifact "$ARTS/spsecureelement.xml" "system_profiler SPSecureElementDataType"

# 4) IODeviceTree snapshot
ioreg -l -p IODeviceTree > "$ARTS/ioreg_devicetree.txt" 2>/dev/null || true
add_artifact "$ARTS/ioreg_devicetree.txt" "IODeviceTree dump"

cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT20 Hardware Attestation
- SPHardware, SPiBridge, SPSecureElement (SEP) collected
- IODeviceTree dump captured
Notes:
- Provides baseline for hardware/boot trust verification
TXT

finish_module 

