CODEX: Apple Silicon M4 Forensic Framework

Scope of Works – Version 1.1
Author: Matt Murphy
License: Open Source (MIT/GPL, TBD)

⸻

🔗 MITRE Mapping & Chain of Custody

All forensic modules must reference:
	•	MITRE ATT&CK Techniques (TT#) — each check is labeled with its ATT&CK ID.
	•	Chain of Custody (CoC) — every evidence file is hashed (SHA-256) and logged with:
	•	Investigator name / role
	•	Date & UTC timestamp
	•	Device ID (hostname, serial)
	•	Evidence path
	•	Purpose of transfer

Chain of Custody Reference:
	•	CNSSI 4009-2015
	•	NIST SP 800-72: Chain of Custody – “A process that tracks the movement of evidence through its collection, safeguarding, and analysis lifecycle by documenting each person who handled the evidence, the date/time it was collected or transferred, and the purpose for the transfer.”
	•	Source: https://csrc.nist.gov/glossary/term/chain_of_custody

⸻

Please read the Mac M4-Forensics-Data-Capture-Guide.md for a foundational overview of the vectors & areas within the M4 Architecture, m4_master.sh is a great start for this forensic script & that's the depth we need to maintain across the Apple OSX enviroment. 

🧩 Domains, Techniques, and Evidence Capture

1. Firmware & Boot Chain (TT#1542.001 – Pre-Boot: System Firmware)
	•	Scripts: boot-trust.sh, firmware-boot.sh, chain-boot.sh
	•	Evidence:
	•	DeviceTree anomalies (device_tree_full.txt)
	•	NVRAM/boot-args dump (nvram.log)
	•	iBoot hash verification (iboot_verification.txt)
	•	Output: ≤20-line summary + file refs

⸻

2. Certificates & Trust (TT#1553.002 – Subvert Trust Controls)
	•	Scripts: certificates.sh, gr0k-certs.sh
	•	Evidence:
	•	Extracted certs (system_certs.pem)
	•	Pinning plist diffs (CertificatePinning.plist.diff)
	•	Output: highlight malicious CAs, zero-GUID certs

⸻

3. Cryptex & Preboot (TT#1601.001 – Modify System Image)
	•	Scripts: gr0k-cryptex.sh
	•	Evidence:
	•	Cryptex structures (cryptex_audit.txt)
	•	Trustcache validation failures
	•	Output: note root hash mismatches, ownership anomalies

⸻

4. SIP & System Integrity (TT#1547.006 – Boot or Logon Autostart: Kernel Modules & Extensions)
	•	Scripts: gr0k-rootless.sh, gr0k-zero.sh
	•	Evidence:
	•	SIP status vs rootless.conf (sip_status.txt)
	•	Tamper tests (attempted file write in /System/)
	•	Output: note bypass success/failure

⸻

5. Kernel & Kext Sentinel (TT#1014 – Rootkit)
	•	Scripts: kext_sentinel_pro.sh, enhanced_forensic_scanner.sh
	•	Evidence:
	•	Loaded kexts (kext_audit.log)
	•	RWX memory mappings (vmmap_scan.log)
	•	Output: highlight unsigned or failed kexts

⸻

6. Network Stack (TT#1049 – System Network Connections Discovery)
	•	Scripts: gr0k-network.sh, network-test.sh
	•	Evidence:
	•	netstat_all.txt, pfctl_rules.log
	•	Hidden utun interfaces (ifconfig_hidden.log)
	•	Output: call out suspicious C2 or relay entries

⸻

7. Privacy Frameworks (TCC) (TT#1548.002 – Abuse Elevation Control Mechanism: TCC Bypass)
	•	Scripts: gr0k-private-relay.sh, gr0k-logs.sh
	•	Evidence:
	•	/Library/Application Support/com.apple.TCC/TCC.db dump
	•	Permissions table (tcc_query.log)
	•	Output: highlight abnormal FDA/Camera/Mic grants

⸻

8. User & Application Persistence (TT#1547.001 – Launch Agents/Daemons)
	•	Scripts: more-grok-scan.sh, more-more-gr0k-scan.sh
	•	Evidence:
	•	/Library/LaunchAgents/*.plist
	•	~/Library/LaunchAgents/*.plist
	•	Output: ≤20 lines mapping suspicious persistence vectors

⸻

9. Memory & Volatile Data (TT#1600.001 – Capture System State)
	•	Scripts: NUCLEAR_OPTIMIZED.sh, NUCLEAR_REPORT_BASED.sh
	•	Evidence:
	•	Memory dump (memory.aff4)
	•	Volatility reports (vol_pslist.txt, vol_netscan.txt)
	•	Output: suspicious processes, injected code

⸻

10. Chain of Custody Module (TT#None – Forensic Process Control)
	•	Auto-executes after each script run:
	•	Generates CoC.log entry
	•	SHA-256 hash of artifact
	•	Logs investigator, timestamp, evidence path, purpose

Format Example:

[2025-09-05T02:39Z]  
Investigator: Matt Murphy  
Device: MacMini-M4 (SN: W6PV2DWQY7)  
Evidence: /Evidence/20250905_0239/network/netstat_all.txt  
SHA256: 7f3a9c2d8e5b4a1f6c9d8e3b...  
Purpose: Network state snapshot during suspected APT activity  


⸻

📌 Deliverables
	•	m4_master.sh orchestrator (with TT#/CoC mapping)
	•	Modular grok/boot/network/certs scripts
	•	Evidence folder tree (logs/raw/hashes)
	•	SCOPE.md + Report-Template.md
	•	Chain of Custody log generator


 Script Naming Convention

 TT##-short-description.sh

 Where:
	•	TT## → the ATT&CK Technique ID reference in your mapping table.
	•	short-description → 2–4 words, lower-kebab-case, describing the script purpose.
	•	.sh → all scripts remain POSIX-compliant (bash 3.2 compatible).

OSXCHECK/
│
├── Mac-M4-Forensic-Data-Capture-Guide.md   # Playbook (main doc for DFIR teams)
├── SCOPE.md                                # Codex scope + ATT&CK mapping
├── README.md                               # Short intro, badges, quickstart
├── LICENSE                                 # Apache 2.0 (best for open collab)
│
├── scripts/                                # TT## forensic modules
│   ├── TT01-chain-of-custody.sh
│   ├── TT02-firmware-bootcheck.sh
│   ├── TT03-certificate-trust.sh
│   ├── TT04-cryptex-integrity.sh
│   ├── TT05-sip-rootless.sh
│   ├── TT06-kext-sentinel.sh
│   ├── TT07-network-state.sh
│   ├── TT08-tcc-bypass-check.sh
│   ├── TT09-launch-persistence.sh
│   ├── TT10-memory-capture.sh
│   └── m4_master.sh                        # orchestrator
│
├── evidence/                               # Default output dir
│   └── TT##/                               # One per technique
│
└── utils/                                  # Helper tools (parsers/reporting)
    └── parse_unified_logs.py

Benefits of This Scheme
	•	Direct ATT&CK mapping → anyone can cross-reference the script with the MITRE framework immediately.
	•	Court defensible → forensic reports can cite “Evidence captured by TT07-network-state.sh (MITRE T1049)”.
	•	Scalable → new vectors? Just increment TT11, TT12 … no clashes.
	•	Automation friendly → m4_master.sh can discover and execute all TT##-*.sh in order.


Reporting Alignment
	•	Each script outputs ≤20 lines summary + pointer to the full log in /evidence/TT##/.
	•	TT01-chain-of-custody.sh runs at the end of each script to append an entry to CoC.log with hash + metadata.
	•	Final report auto-pulls sections based on TT## order → perfectly mirrors your forensic report template.


Evidence is written under /evidence/TT##/ with SHA256 hash logs.

🧩 Modules
	•	TT01 Chain of Custody
	•	TT02 Firmware / Boot Integrity
	•	TT03 Certificates & Trust Stores
	•	TT04 Cryptex Analysis
	•	TT05 SIP & Rootless Checks
	•	TT06 Kext Sentinel
	•	TT07 Network State
	•	TT08 TCC Bypass Analysis
	•	TT09 Launch Daemons & Persistence
	•	TT10 Memory Capture

📚 Documentation

See Mac-M4-Forensic-Data-Capture-Guide.md

⚖️ License

Apache 2.0 — free for research, DFIR, and courtroom use.

