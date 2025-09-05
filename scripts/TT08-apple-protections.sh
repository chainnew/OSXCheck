#!/usr/bin/env bash
# TT08 – Apple Protections: XProtect / MRT / Gatekeeper / SPCTL
# REPORT_SECTION="Platform Protections"
# MITRE_TECHNIQUES="T1204.002,T1553.001,T1553.002,T1036"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT08"
MODULE_NAME="apple-protections"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

# 1) Gatekeeper state + sample assessments (no execution)
spctl --status 2>&1 | tee "$ARTS/gatekeeper_status.txt" >/dev/null || true
add_artifact "$ARTS/gatekeeper_status.txt" "Gatekeeper status"

# Assess a few known binaries (read-only, metadata only)
for BIN in /usr/bin/osascript /usr/bin/python3 /usr/bin/codesign; do
  [ -x "$BIN" ] || continue
  spctl --assess --type execute -vv "$BIN" 2>&1 | sed -n '1,80p' > "$ARTS/spctl_$(basename "$BIN").txt" || true
  add_artifact "$ARTS/spctl_$(basename "$BIN").txt" "spctl assess $(basename "$BIN")"
done

# 2) XProtect definitions / Remediator footprints (paths vary by macOS)
# Inventory anything matching XProtect under Apple/System trees
XP_TREE="$ARTS/xprotect_tree.txt"
{ 
  find /Library/Apple/System -type d -name "*XProtect*" -print 2>/dev/null
  find /System/Library -type d -name "*XProtect*" -print 2>/dev/null
  find /Library -maxdepth 2 -type d -name "*XProtect*" -print 2>/dev/null
} | sort -u | tee "$XP_TREE" >/dev/null
add_artifact "$XP_TREE" "XProtect-related directories (inventory)"

# Grab small definition/property files for offline review
while read -r D; do
  [ -d "$D" ] || continue
  find "$D" -type f \( -name "*.plist" -o -name "*.json" -o -name "*.txt" \) -size -1M -print 2>/dev/null \
    | head -100 | while read -r F; do
      BAS="xprotect_$(echo "$F" | tr '/' '_' | cut -c1-160)"
      cp -p "$F" "$ARTS/$BAS" 2>/dev/null || true
      add_artifact "$ARTS/$BAS" "XProtect/MRT def or meta file"
    done
done <"$XP_TREE"

# 3) MRT / XProtectBehaviorService processes (presence only)
ps aux 2>/dev/null | grep -E "XProtect|Remediator|MRT|Behavior" | grep -v grep \
  | tee "$ARTS/xprotect_mrt_processes.txt" >/dev/null || true
add_artifact "$ARTS/xprotect_mrt_processes.txt" "Protection-related processes (snapshot)"

# 4) Syspolicyd/Gatekeeper recent events (best-effort AUL pivots)
if command -v log >/dev/null 2>&1; then
  log show --last 48h --predicate 'process == "syspolicyd"' --style syslog 2>/dev/null \
    | sed -n '1,2000p' > "$ARTS/aul_syspolicyd_48h.txt" || true
  add_artifact "$ARTS/aul_syspolicyd_48h.txt" "Unified Log: syspolicyd (48h head)"
fi

# Summary (≤20 lines)
cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT08 Platform Protections
- Gatekeeper status captured; spctl assessments of known binaries recorded
- XProtect/MRT/Remediator directories inventoried; small defs/plists collected
- Process snapshot for protection daemons (XProtect*, Remediator, MRT) obtained
- Unified Log pivot for syspolicyd (48h head) captured
Notes:
- Paths vary by macOS; this collects footprints non-destructively
- All artifacts hashed and logged to Chain of Custody
TXT

finish_module

