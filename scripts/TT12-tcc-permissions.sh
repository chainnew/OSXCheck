#!/usr/bin/env bash
# TT12 – TCC Permissions: System/User TCC.db snapshots & pivots
# REPORT_SECTION="Privacy & Permissions (TCC)"
# MITRE_TECHNIQUES="T1552,T1069,T1087,T1114"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT12"
MODULE_NAME="tcc-permissions"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

copy_tcc() {
  SRC="$1"; TAG="$2"
  if [ -f "$SRC" ]; then
    DST="$ARTS/TCC_${TAG}.db"
    cp -p "$SRC" "$DST" 2>/dev/null || true
    add_artifact "$DST" "TCC.db snapshot ($TAG)"
    if command -v sqlite3 >/dev/null 2>&1; then
      OUT="$ARTS/TCC_${TAG}_summary.txt"
      sqlite3 "$DST" <<'SQL' 2>/dev/null | tee "$OUT" >/dev/null
.headers on
.mode column
.width 32 56 8 20
SELECT
  service,
  client,
  auth_value,
  datetime(last_modified + 978307200, 'unixepoch') AS last_mod_utc
FROM access
ORDER BY service, last_modified DESC
LIMIT 300;
SQL
      add_artifact "$OUT" "TCC summary ($TAG, top 300)"
    fi
  fi
}

# System-level TCC
copy_tcc "/Library/Application Support/com.apple.TCC/TCC.db" "system"

# Per-user TCC
find /Users -mindepth 1 -maxdepth 1 -type d -prune 2>/dev/null | while read -r UHOME; do
  UBASE="$(basename "$UHOME")"
  UDB="$UHOME/Library/Application Support/com.apple.TCC/TCC.db"
  copy_tcc "$UDB" "user_${UBASE}"
done

# Quick integrity/context checks (presence of framework & tools)
ls -al "/System/Library/PrivateFrameworks/TCC.framework" 2>/dev/null \
  > "$ARTS/tcc_framework_ls.txt" || true
add_artifact "$ARTS/tcc_framework_ls.txt" "TCC.framework presence (ls -al head)"

# Summary (≤20 lines)
cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT12 TCC Permissions
- Snapshotted system TCC.db and per-user TCC.db (where present)
- Produced compact summaries (service, client, auth_value, last_modified)
- Captured TCC.framework presence for integrity context
Notes:
- Read-only copies; no resets or modifications performed
- All artifacts hashed and logged to Chain of Custody
TXT

finish_module

