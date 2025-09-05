#!/usr/bin/env bash
# TT19 – APFS & Disk Context
# REPORT_SECTION="Disk & File System Context"
# MITRE_TECHNIQUES="T1005,T1070.004"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT19"
MODULE_NAME="apfs-and-disk"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

# 1) diskutil list - plist + text
diskutil list -plist > "$ARTS/diskutil_list.plist" 2>/dev/null || true
add_artifact "$ARTS/diskutil_list.plist" "diskutil list (plist)"

diskutil list > "$ARTS/diskutil_list.txt" 2>/dev/null || true
add_artifact "$ARTS/diskutil_list.txt" "diskutil list (text)"

# 2) APFS details
diskutil apfs list -plist > "$ARTS/apfs_list.plist" 2>/dev/null || true
add_artifact "$ARTS/apfs_list.plist" "diskutil apfs list (plist)"

# 3) Asr info (lightweight header only)
asr info --plist / > "$ARTS/asr_info_root.plist" 2>/dev/null || true
add_artifact "$ARTS/asr_info_root.plist" "asr info (root, plist)"

# 4) Mounts & df snapshot
mount > "$ARTS/mounts.txt" 2>/dev/null || true
df -h > "$ARTS/df_h.txt" 2>/dev/null || true
add_artifact "$ARTS/mounts.txt" "Current mounts"
add_artifact "$ARTS/df_h.txt" "df -h"

cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT19 APFS & Disk Context
- diskutil list captured (plist + text)
- APFS list and asr info snapshot
- Current mounts and df -h for space context
Notes:
- Preserves APFS container metadata for imaging comparison
TXT

finish_module 

