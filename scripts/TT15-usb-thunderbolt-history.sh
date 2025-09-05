#!/usr/bin/env bash
# TT15 – USB & Thunderbolt History
# REPORT_SECTION="External Device Connections"
# MITRE_TECHNIQUES="T1091,T1200,T1204.002"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT15"
MODULE_NAME="usb-thunderbolt-history"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

# 1) system_profiler dumps
system_profiler SPUSBDataType -xml > "$ARTS/spusb.xml" 2>/dev/null || true
add_artifact "$ARTS/spusb.xml" "system_profiler SPUSBDataType (XML)"

system_profiler SPThunderboltDataType -xml > "$ARTS/spthunderbolt.xml" 2>/dev/null || true
add_artifact "$ARTS/spthunderbolt.xml" "system_profiler SPThunderboltDataType (XML)"

# 2) AUL pivots for USBMSC (last 48h, head only)
if command -v log >/dev/null 2>&1; then
  log show --last 48h --predicate 'eventMessage CONTAINS "USBMSC"' --style syslog 2>/dev/null \
    | sed -n '1,3000p' > "$ARTS/aul_usbmsc.txt" || true
  add_artifact "$ARTS/aul_usbmsc.txt" "Unified Log: USBMSC device events (48h head)"
fi

# 3) Plist caches (sidebar / finder)
for P in /Users/*/Library/Preferences/com.apple.sidebarlists.plist /Users/*/Library/Preferences/com.apple.finder.plist; do
  [ -f "$P" ] || continue
  cp -p "$P" "$ARTS/$(basename "$P").copy" 2>/dev/null || true
  add_artifact "$ARTS/$(basename "$P").copy" "Finder/Sidebar plist copy: $(basename "$P")"
done

cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT15 USB & Thunderbolt History
- Captured SPUSB and SPThunderbolt full XML dumps
- Unified Log USBMSC device connection events (48h head)
- Finder/Sidebar plist caches for external volumes
Notes:
- Forensic value: maps device IDs, serials, mount history
TXT

finish_module

