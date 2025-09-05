#!/usr/bin/env bash
# TT09 – Unified Logs: logarchive + focused pivots
# REPORT_SECTION="System Activity: Apple Unified Log"
# MITRE_TECHNIQUES="T1005,T1059,T1070.004,T1204.002"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MODULE_ID="TT09"
MODULE_NAME="unified-logs"
init_module "$MODULE_ID" "$MODULE_NAME"

ARTS="$MODULE_OUT/artifacts"; mkdir -p "$ARTS"

# 1) Full logarchive (best-effort; may require root; bounded filename only)
if command -v log >/dev/null 2>&1; then
  ARCH="$ARTS/system.logarchive"
  log collect --output "$ARCH" --last 72h 2>>"$MODULE_OUT/full.log" || true
  [ -d "$ARCH" ] && add_artifact "$ARCH" "Unified Logs: 72h logarchive (best-effort)"
else
  echo "log(1) not available" > "$ARTS/aul_unavailable.txt"
  add_artifact "$ARTS/aul_unavailable.txt" "AUL unavailable"
fi

# 2) Focused pivots (heads only to keep light)
pivot() { PRED="$1"; OUT="$2"; log show --last 48h --predicate "$PRED" --style syslog 2>/dev/null | sed -n '1,3000p' > "$OUT" || true; add_artifact "$OUT" "AUL pivot: $PRED (48h head)"; }
if command -v log >/dev/null 2>&1; then
  pivot 'process == "sudo"'                          "$ARTS/aul_sudo.txt"
  pivot 'subsystem == "com.apple.mac.install"'       "$ARTS/aul_installer.txt"
  pivot 'eventMessage CONTAINS "USBMSC"'             "$ARTS/aul_usbmsc.txt"
  pivot 'process == "syspolicyd"'                    "$ARTS/aul_syspolicyd.txt"
  pivot 'process == "kextd" OR sender == "IOKit"'    "$ARTS/aul_kext.txt"
  pivot 'process == "amfid"'                         "$ARTS/aul_amfid.txt"
fi

# Summary (≤20 lines)
cat >"$MODULE_OUT/summary.txt" <<'TXT'
TT09 Unified Logs
- Collected a 72h logarchive (best-effort) for offline parsing
- Focused pivots captured (48h heads): sudo, installer, USBMSC, syspolicyd, kext, amfid
- Outputs are bounded to avoid massive logs during triage
Notes:
- logarchive size varies; ensure sufficient disk space
- All artifacts hashed and logged to Chain of Custody
TXT

finish_module

