#!/usr/bin/env bash
# TT16 – Time Machine & APFS Snapshots
# REPORT_SECTION="Backups & Snapshots"
# MITRE_TECHNIQUES="T1070.004,T1490,T1105"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT16"
MODULE_NAME="time-machine-and-snapshots"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

# 1) tmutil inventories (no modifications)
if command -v tmutil >/dev/null 2>&1; then
  tmutil destinationinfo 2>&1 | tee "$ARTS/tm_destinationinfo.txt" >/dev/null || true
  add_artifact "$ARTS/tm_destinationinfo.txt" "Time Machine destinationinfo"
  tmutil listbackups 2>&1 | tee "$ARTS/tm_listbackups.txt" >/dev/null || true
  add_artifact "$ARTS/tm_listbackups.txt" "Time Machine listbackups"
  tmutil listlocalsnapshots / 2>&1 | tee "$ARTS/tm_localsnapshots_root.txt" >/dev/null || true
  add_artifact "$ARTS/tm_localsnapshots_root.txt" "Time Machine local snapshots (/)"
fi

# 2) APFS snapshots via diskutil (read-only)
diskutil apfs listSnapshots / 2>&1 | tee "$ARTS/apfs_listSnapshots_root.txt" >/dev/null || true
add_artifact "$ARTS/apfs_listSnapshots_root.txt" "APFS listSnapshots (/)"

# 3) APFS container/volume context
diskutil apfs list -plist 2>/dev/null | sed -n '1,2000p' > "$ARTS/apfs_list_plist_head.xml" || true
add_artifact "$ARTS/apfs_list_plist_head.xml" "APFS list (plist head)"

# Summary (≤20 lines)
cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT16 Time Machine & APFS Snapshots
- Enumerated Time Machine configuration, backups, and local snapshots
- Captured APFS snapshots for root volume and APFS list (plist head)
Notes:
- Purely observational: no deletion or mount operations performed
- All artifacts hashed and logged to Chain of Custody
TXT

finish_module

