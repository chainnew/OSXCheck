#!/usr/bin/env bash
# TT23-bounty-radar.sh — “one-shot” bounty-minded misconfig scanner
# Bash 3.2 compatible, no auto-sudo. Requires scripts/lib/common.sh

set -euo pipefail
MODULE_ID="TT23"
MODULE_NAME="bounty-radar"
REPORT_SECTION="Bounty Radar: High-Value Misconfigs"
MITRE_TECHNIQUES="T1547,T1553,T1552,T1053,T1037,T1068"

# --- bootstrap common helpers ------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=/dev/null
[ -f "$SCRIPT_DIR/lib/common.sh" ] && . "$SCRIPT_DIR/lib/common.sh"

# Fallbacks if common.sh not sourced (keeps the script runnable)
init_module() { 
  MODULE_DIR="${RUN_DIR:-"./evidence/$RUN_ID"}/${MODULE_ID}-${MODULE_NAME}"
  mkdir -p "$MODULE_DIR"/{artifacts,report}
  SUMMARY="$MODULE_DIR/summary.txt"; FULL="$MODULE_DIR/full.log"; MANIFEST="$MODULE_DIR/manifest.json"
  : >"$FULL"; : >"$SUMMARY"; : >"$MANIFEST"
}
finish_module() { true; }
log_coc() { :; }
add_artifact() { # path, label
  local p="$1" lbl="${2:-artifact}"
  [ -f "$p" ] && shasum -a 256 -- "$p" >>"$MANIFEST" 2>/dev/null || true
}

# --- env from orchestrator ---------------------------------------------------
EVIDENCE_ROOT="${EVIDENCE_ROOT:-./evidence}"
RUN_ID="${RUN_ID:-run-$(date -u +%Y-%m-%dT%H-%M-%SZ)}"
RUN_DIR="$EVIDENCE_ROOT/$RUN_ID"

init_module

# Paths
FINDINGS="$MODULE_DIR/artifacts/findings.jsonl"
: >"$FINDINGS"

say() { echo "$*" | tee -a "$FULL" >/dev/null; }
emit() { # severity, id, desc, path, extra
  printf '{"ts":"%s","severity":"%s","id":"%s","desc":"%s","path":"%s","extra":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$3" "$4" "${5//\"/\'}" >>"$FINDINGS"
}

# ------------------ checks ---------------------------------------------------

say "== LaunchAgents/Daemons world/group write =="
# World-writable or group-writable by staff/admin in persistence dirs
for d in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
  [ -d "$d" ] || continue
  # world-writable
  while IFS= read -r f; do
    emit "critical" "LAWW" "world-writable launch plist" "$f" "$(ls -lO "$f" 2>/dev/null)"
  done < <(find "$d" -type f -name '*.plist' -perm -002 2>/dev/null)
  # group-writable by admin/staff
  while IFS= read -r f; do
    emit "high" "LAGW" "group-writable launch plist" "$f" "$(ls -lO "$f" 2>/dev/null)"
  done < <(find "$d" -type f -name '*.plist' -perm -020 2>/dev/null)
done

say "== Login Items / BTM unsigned or missing parent entitlement =="
# Dump BTM database if present
BTM="/private/var/db/com.apple.backgroundtaskmanagement/BackgroundTaskManagement.plist"
if [ -r "$BTM" ]; then
  cp -p "$BTM" "$MODULE_DIR/artifacts/BTM.plist" && add_artifact "$MODULE_DIR/artifacts/BTM.plist" "BTM"
fi
# Heuristic: list LoginItems + codesign status
while IFS= read -r app; do
  cs=$(codesign -dv --verbose=2 "$app" 2>&1 || true)
  echo "$app | $cs" >>"$FULL"
  echo "$cs" | grep -q "Authority=" || emit "high" "LOGIN-UNSIGNED" "login item appears unsigned" "$app" ""
done < <(mdfind 'kMDItemKind == "Application" && kMDItemFSName == "*Login*"' 2>/dev/null | head -n 200)

say "== TCC Full Disk Access (FDA) for shells/automation =="
for db in "/Library/Application Support/com.apple.TCC/TCC.db" "$HOME/Library/Application Support/com.apple.TCC/TCC.db"; do
  [ -r "$db" ] || continue
  out="$MODULE_DIR/artifacts/$(basename "$db").FDA.txt"
  sqlite3 "$db" 'SELECT client,auth_value,auth_reason,last_modified FROM access WHERE service="kTCCServiceSystemPolicyAllFiles";' >"$out" 2>/dev/null || true
  add_artifact "$out" "TCC-FDA"
  # flag shells and common abuse
  while IFS='|' read -r client auth _ _; do
    case "$client" in
      *Terminal*|*/bash|*/zsh|*/python*|*/osascript|*/sh)
        [ "$auth" = "2" ] && emit "critical" "TCC-FDA" "Full Disk Access granted to shell/automation" "$client" "$db"
        ;;
    esac
  done < <(tr '|' '|' <"$out")
done

say "== Extra/Unexpected trust anchors (System keychain) =="
# List system keychain cert subjects and issuers; flag non-Apple anchors
secout="$MODULE_DIR/artifacts/system_certs.txt"
security find-certificate -a -p /Library/Keychains/System.keychain >"$secout" 2>/dev/null || true
add_artifact "$secout" "system-certs"
grep -q "." "$secout" || true
# naive heuristic: count non-Apple issuers
nonapple=$(grep -A1 "BEGIN CERTIFICATE" -n "$secout" | wc -l | tr -d ' ')
[ "${nonapple:-0}" -gt 0 ] && emit "info" "CERT-REVIEW" "review system trust anchors (non-Apple roots may exist)" "/Library/Keychains/System.keychain" "export in artifacts"

say "== AMFI/Gatekeeper anomalies (Unified Log pivots) =="
ulog="$MODULE_DIR/artifacts/amfi_gk.log"
log show --predicate '(process == "amfid" OR process == "syspolicyd") AND (eventMessage CONTAINS[c] "invalid signature" OR eventMessage CONTAINS[c] "Allowing")' --last 7d --info --debug >"$ulog" 2>/dev/null || true
add_artifact "$ulog" "amfi-gk"
grep -qi "invalid signature" "$ulog" && emit "high" "AMFI-INVALID" "AMFI allowed invalid signature events observed" "$ulog" "last 7d"

say "== Quarantine events for executables run recently =="
qout="$MODULE_DIR/artifacts/quarantine_events.tsv"
sqlite3 "$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
 'SELECT datetime(time_utc + 978307200,"unixepoch"), origin_url, agent_bundle, data_url FROM LSQuarantineEvent ORDER BY time_utc DESC LIMIT 200;' \
 >"$qout" 2>/dev/null || true
add_artifact "$qout" "quarantine"
grep -qiE "\.pkg|\.dmg|\.zip|\.app" "$qout" && emit "info" "QUAR-RECENT" "recent downloads of installers/apps" "$qout" "review for initial access"

say "== Cryptex permission oddities =="
crout="$MODULE_DIR/artifacts/cryptex_perm.txt"
find /System/Volumes/Preboot -maxdepth 4 -path '*/cryptex*/*' -type f -perm -002 -ls 2>/dev/null | tee "$crout" >/dev/null || true
add_artifact "$crout" "cryptex-perms"
[ -s "$crout" ] && emit "critical" "CRYPTEX-PERM" "world-writable file within cryptex trees" "/System/Volumes/Preboot" ""

say "== USB/Thunderbolt recent history pivots =="
usblog="$MODULE_DIR/artifacts/usb_recent.log"
log show --predicate 'subsystem CONTAINS "USB" OR eventMessage CONTAINS "USBMSC"' --last 14d --info --debug >"$usblog" 2>/dev/null || true
add_artifact "$usblog" "usb-aul"
[ -s "$usblog" ] && emit "info" "USB-RECENT" "recent USB/Thunderbolt activity present" "$usblog" ""

# ------------------ summarize (≤20 lines) ------------------------------------
CRIT=$(grep -c '"severity":"critical"' "$FINDINGS" 2>/dev/null || echo 0)
HIGH=$(grep -c '"severity":"high"' "$FINDINGS" 2>/dev/null || echo 0)
INFO=$(grep -c '"severity":"info"' "$FINDINGS" 2>/dev/null || echo 0)

{
  echo "Module: $MODULE_ID-$MODULE_NAME — $REPORT_SECTION"
  echo "MITRE: $MITRE_TECHNIQUES"
  echo "Critical: $CRIT  High: $HIGH  Info: $INFO"
  echo "- Launch plists w/ bad perms: $(grep -c '"id":"LAWW"\|"id":"LAGW"' "$FINDINGS" 2>/dev/null || echo 0)"
  echo "- TCC FDA to shells:         $(grep -c '"id":"TCC-FDA"' "$FINDINGS" 2>/dev/null || echo 0)"
  echo "- AMFI invalid sig events:   $(grep -c '"id":"AMFI-INVALID"' "$FINDINGS" 2>/dev/null || echo 0)"
  echo "- Cryptex world-writable:    $(grep -c '"id":"CRYPTEX-PERM"' "$FINDINGS" 2>/dev/null || echo 0)"
  echo "- Recent app downloads:      $(grep -c '"id":"QUAR-RECENT"' "$FINDINGS" 2>/dev/null || echo 0)"
  echo "- USB/Thunderbolt activity:  $(grep -c '"id":"USB-RECENT"' "$FINDINGS" 2>/dev/null || echo 0)"
  echo "Artifacts:"
  echo "  - $(basename "$FINDINGS") (JSONL findings)"
  echo "  - amfi_gk.log, quarantine_events.tsv, system_certs.txt"
  echo "  - usb_recent.log, cryptex_perm.txt, BTM.plist (if present)"
  echo "Next steps:"
  echo "  * Review CRITICAL/HIGH findings for bounty-grade misconfigs"
  echo "  * Cross-link with TT06 (persistence) & TT12 (TCC deep dive)"
  echo "  * Preserve evidence via CoC entry for any remediation actions"
} | tee "$SUMMARY" >/dev/null

# CoC entries
log_coc "$MODULE_ID" "write" "$FINDINGS" "JSONL misconfig findings"
for a in "$ulog" "$qout" "$secout" "$usblog" "$crout"; do
  [ -f "$a" ] && log_coc "$MODULE_ID" "write" "$a" "supporting artifact"
done

finish_module