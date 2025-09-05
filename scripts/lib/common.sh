#!/bin/bash
# Common helpers for TT modules (Bash 3.2 compatible)
set -euo pipefail
IFS=$'\n\t'

: "${EVIDENCE_ROOT:=./evidence}"
: "${INVESTIGATOR:=unknown}"
: "${DEVICE_ID:=$(hostname)}"
RUN_ID="${RUN_ID:-run-$(date -u +%Y-%m-%dT%H-%M-%SZ)}"

_start_ts=""
OUT_DIR=""
MODULE_ID="${MODULE_ID:-UNKNOWN}"
REPORT_SECTION="${REPORT_SECTION:-Unknown Section}"
MITRE_TECHNIQUES="${MITRE_TECHNIQUES:-}"

_escape_json() { # crude escape
  /usr/bin/python - "$@" <<'PY' 2>/dev/null || /usr/bin/printf '%s' "$*"
import sys, json
print(json.dumps(' '.join(sys.argv[1:])))
PY
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Root privileges required for ${MODULE_ID}. Run: sudo $0" >&2
    exit 3
  fi
}

init_module() {
  MODULE_ID="$1"
  OUT_DIR="${EVIDENCE_ROOT}/${RUN_ID}/${MODULE_ID}"
  mkdir -p "${OUT_DIR}/artifacts"
  # Persist module metadata for orchestrator/reporting
  {
    echo "MODULE_ID=${MODULE_ID}"
    echo "REPORT_SECTION=${REPORT_SECTION}"
    echo "MITRE_TECHNIQUES=${MITRE_TECHNIQUES}"
    echo "INVESTIGATOR=${INVESTIGATOR}"
    echo "DEVICE_ID=${DEVICE_ID}"
  } > "${OUT_DIR}/meta.env"
  # Start logging
  exec > >(tee "${OUT_DIR}/full.log") 2>&1
  _start_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[*] ${MODULE_ID} start: ${_start_ts}"
}

log_coc() {  # action, path, purpose, tool, version
  local action="$1"; shift
  local path="$1"; shift
  local purpose="$1"; shift
  local tool="$1"; shift
  local ver="$1"; shift
  local ts size sha
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  size="$(stat -f %z "${path}" 2>/dev/null || echo 0)"
  sha="$(shasum -a 256 -- "${path}" 2>/dev/null | awk '{print $1}')"
  printf '{"ts":"%s","investigator":"%s","device_id":"%s","module":"%s","action":"%s","artifact_path":"%s","sha256":"%s","size_bytes":%s,"purpose":"%s","tool":"%s","tool_version":"%s"}\n' \
    "$ts" "$INVESTIGATOR" "$DEVICE_ID" "$MODULE_ID" "$action" "$path" "$sha" "$size" \
    "$(_escape_json "$purpose")" "$(_escape_json "$tool")" "$(_escape_json "$ver")" \
    >> "${EVIDENCE_ROOT}/${RUN_ID}/CHAIN_OF_CUSTODY.jsonl"
}

_manifest_list() {
  echo "${OUT_DIR}/.manifest.list"
}

add_artifact() { # path
  local p="$1"
  echo "$p" >> "$(_manifest_list)"
}

write_manifest() {
  local tmp="${OUT_DIR}/.manifest.list"
  local out="${OUT_DIR}/manifest.json"
  if [ ! -s "$tmp" ]; then
    echo '{"artifacts":[]}' > "$out"
    return 0
  fi
  echo '{"artifacts":[' > "$out"
  local first=1
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    local size sha
    size="$(stat -f %z "$p" 2>/dev/null || echo 0)"
    sha="$(shasum -a 256 -- "$p" 2>/dev/null | awk '{print $1}')"
    if [ $first -eq 0 ]; then echo ',' >> "$out"; fi
    first=0
    printf '{"path":%s,"sha256":"%s","size_bytes":%s}' \
      "$(_escape_json "$p")" "$sha" "$size" >> "$out"
  done < "$tmp"
  echo ']}' >> "$out"
}

finish_module() {
  write_manifest || true
  local end_ts dur
  end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  dur=$(( $(date -u +%s) - $(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "${_start_ts}" +%s 2>/dev/null || echo 0 ) ))
  echo "[*] ${MODULE_ID} end: ${end_ts} (duration: ${dur}s)"
}

