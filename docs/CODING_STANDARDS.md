Bash Coding Standards

- Compatibility: Bash 3.2 (macOS default)
- Safety: set -euo pipefail; IFS=$'\n\t'
- No auto-sudo: fail with guidance if root is required
- Functions: provide require_root, log_coc, add_artifact helpers
- Logging: timestamp start/end, duration; log command lines (redact secrets)
- Output: write only under <EVIDENCE_ROOT>/<RUN_ID>/...
- Hashing: shasum -a 256 -- <file>
- JSON: avoid external deps; if jq present, ok as optional

