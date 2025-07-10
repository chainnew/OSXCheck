# OSXCheck

A comprehensive macOS security and forensics assessment script. The tool
collects system, network, persistence and application data to help identify
malicious activity. Output reports can be optionally encrypted for safe
transport.

The latest version includes deeper kernel extension checks that validate
signatures for both loaded and installed kernel extensions. Results are
stored under `kernel/` with per-kext details saved in `signatures/kexts`.

The script now verifies that required macOS utilities such as `sw_vers`
are available before running capability checks to prevent premature
termination when executed in minimal environments or via alternate
shells.
