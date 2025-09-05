#!/usr/bin/env bash
# TT13 – dyld & AMFI: dyld cache footprints, AMFI pivots
# REPORT_SECTION="Runtime & Loader Integrity"
# MITRE_TECHNIQUES="T1574.006,T1055,T1542.003"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT13"
MODULE_NAME="dyld-and-amfi"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

# 1) Enumerate dyld_shared_cache files
DYLD_LIST="$ARTS/dyld_shared_cache_paths.txt"
{ 
  find /System -type f -name "dyld_shared_cache*" -print 2>/dev/null
  find /System/Cryptexes -type f -name "dyld_shared_cache*" -print 2>/dev/null
} | sort -u | tee "$DYLD_LIST" >/dev/null
add_artifact "$DYLD_LIST" "dyld cache inventory"

# 2) Header info (file, size, codesign check) – head-only to stay light
while read -r F; do
  [ -f "$F" ] || continue
  INFO="$ARTS/$(basename "$F").info.txt"
  {
    echo "FILE: $F"
    stat -f "SIZE(bytes): %z  MTIME: %Sm" "$F" 2>/dev/null
    file "$F" 2>/dev/null
    codesign -dv "$F" 2>&1 | sed -n '1,80p' || true
  } > "$INFO"
  add_artifact "$INFO" "dyld cache info: $(basename "$F")"
done <"$DYLD_LIST"

# 3) AMFI / trustd pivots from AUL
if command -v log >/dev/null 2>&1; then
  log show --last 48h --predicate 'process == "amfid"' --style syslog 2>/dev/null \
    | sed -n '1,3000p' > "$ARTS/aul_amfid_48h.txt" || true
  add_artifact "$ARTS/aul_amfid_48h.txt" "Unified Log: amfid (48h head)"
  log show --last 48h --predicate 'process == "trustd"' --style syslog 2>/dev/null \
    | sed -n '1,3000p' > "$ARTS/aul_trustd_48h.txt" || true
  add_artifact "$ARTS/aul_trustd_48h.txt" "Unified Log: trustd (48h head)"
fi

# Summary (≤20 lines)
cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT13 dyld & AMFI
- Enumerated dyld_shared_cache files across System and Cryptex trees
- Collected file/type/codesign headers for each cache (head-only)
- Unified Log pivots for amfid and trustd (48h heads) captured
Notes:
- No extraction or modification of dyld caches performed
- All artifacts hashed and logged to Chain of Custody
TXT

finish_module

