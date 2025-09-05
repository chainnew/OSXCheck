Evidence Structure

- Root: ./evidence/<RUN_ID>/
- RUN_ID: run-YYYY-MM-DDTHH-MM-SSZ (UTC)

Per Module
- <EVIDENCE_ROOT>/<RUN_ID>/<TT##-name>/
  - summary.txt         (≤20 lines, human summary)
  - full.log            (stdout/stderr, verbose)
  - manifest.json       (array of {path, sha256, size_bytes})
  - meta.env            (REPORT_SECTION, MITRE_TECHNIQUES, MODULE_ID)
  - artifacts/          (raw dumps, CSV/JSON, pcaps, etc.)

Chain of Custody
- Single JSONL per run: <EVIDENCE_ROOT>/<RUN_ID>/CHAIN_OF_CUSTODY.jsonl
- One line per artifact write with fields:
  - ts, investigator, device_id, module, action, artifact_path, sha256, size_bytes, purpose, tool, tool_version

