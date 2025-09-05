#!/bin/bash

################################################################################
# TT03-network-state.sh - Production Network State Forensic Collection
# Version: 3.0.0-PRODUCTION
# Purpose: Comprehensive network state analysis including DNS, VPN, and routing
# Platform: macOS 10.12+ with bash 3.2 compatibility
# Classification: FORENSIC EVIDENCE COLLECTION - NETWORK STATE
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Script Constants
readonly SCRIPT_VERSION="3.0.0-PRODUCTION"
readonly SCRIPT_NAME="TT03-network-state.sh"
readonly SCRIPT_PURPOSE="Network State Forensic Collection"
readonly SCRIPT_HASH="$(shasum -a 256 "$0" | awk '{print $1}')"

# Validate execution parameters
if [ $# -lt 2 ]; then
    echo "ERROR: Insufficient parameters for forensic collection" >&2
    echo "Usage: $0 <case_id> <examiner> [evidence_path]" >&2
    echo "Example: $0 CASE-2025-001 'J.Smith' /Volumes/Evidence" >&2
    exit 1
fi

# Forensic Case Parameters
readonly CASE_ID="${1}"
readonly EXAMINER="${2}"
readonly EVIDENCE_PATH="${3:-/Volumes/Evidence}"
readonly ACQUISITION_ID="$(uuidgen)"
readonly ACQUISITION_START="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
readonly HOSTNAME="$(hostname)"
readonly OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo 'Unknown')"

# Validate evidence path
if [ ! -d "$EVIDENCE_PATH" ]; then
    echo "ERROR: Evidence path not accessible: $EVIDENCE_PATH" >&2
    echo "Mount an evidence drive or specify a valid path" >&2
    exit 1
fi

# Evidence Structure
readonly OUTPUT_ROOT="${EVIDENCE_PATH}/network_${CASE_ID}_${ACQUISITION_ID}"
readonly INTERFACE_DIR="${OUTPUT_ROOT}/01_interfaces"
readonly CONNECTION_DIR="${OUTPUT_ROOT}/02_connections"
readonly ROUTING_DIR="${OUTPUT_ROOT}/03_routing"
readonly DNS_DIR="${OUTPUT_ROOT}/04_dns"
readonly VPN_DIR="${OUTPUT_ROOT}/05_vpn"
readonly PRIVATERELAY_DIR="${OUTPUT_ROOT}/06_private_relay"
readonly THUNDERBOLT_DIR="${OUTPUT_ROOT}/07_thunderbolt"
readonly VIRTUAL_DIR="${OUTPUT_ROOT}/08_virtual_interfaces"
readonly DNSMONITOR_DIR="${OUTPUT_ROOT}/09_dns_monitor"
readonly METADATA_DIR="${OUTPUT_ROOT}/00_metadata"
readonly LOG_FILE="${METADATA_DIR}/acquisition.log"
readonly ERROR_LOG="${METADATA_DIR}/errors.log"
readonly MANIFEST_FILE="${METADATA_DIR}/evidence_manifest.sha256"
readonly CHAIN_FILE="${METADATA_DIR}/chain_of_custody.txt"
readonly FINDINGS_FILE="${METADATA_DIR}/findings_summary.txt"

# Initialize forensic environment
initialize_forensic_environment() {
    # Create evidence structure
    mkdir -p "$INTERFACE_DIR" "$CONNECTION_DIR" "$ROUTING_DIR" "$DNS_DIR" "$VPN_DIR"
    mkdir -p "$PRIVATERELAY_DIR" "$THUNDERBOLT_DIR" "$VIRTUAL_DIR" "$DNSMONITOR_DIR" "$METADATA_DIR"
    chmod 700 "$OUTPUT_ROOT"
    
    # Initialize chain of custody
    cat > "$CHAIN_FILE" <<-EOF
	NETWORK STATE FORENSIC COLLECTION - CHAIN OF CUSTODY
	=====================================================
	Case ID: $CASE_ID
	Acquisition ID: $ACQUISITION_ID
	Examiner: $EXAMINER
	Start Time: $ACQUISITION_START
	
	System Information:
	  Hostname: $HOSTNAME
	  OS Version: $OS_VERSION
	  Architecture: $(uname -m)
	  Kernel: $(uname -r)
	
	Script Information:
	  Version: $SCRIPT_VERSION
	  Hash: $SCRIPT_HASH
	
	Evidence Location: $OUTPUT_ROOT
	
	COLLECTION LOG:
	--------------
	EOF
    
    # Initialize findings summary
    echo "NETWORK STATE FINDINGS SUMMARY" > "$FINDINGS_FILE"
    echo "==============================" >> "$FINDINGS_FILE"
    echo "Generated: $ACQUISITION_START" >> "$FINDINGS_FILE"
    echo "Case ID: $CASE_ID" >> "$FINDINGS_FILE"
    echo "" >> "$FINDINGS_FILE"
    
    # Redirect output for logging
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG" >&2)
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Network forensics initialized"
}

# Secure evidence collection function
collect_evidence() {
    local description="$1"
    local output_dir="$2"
    local output_file="$3"
    local command="$4"
    local timeout_seconds="${5:-30}"
    
    local full_path="${output_dir}/${output_file}.txt"
    local temp_path="${full_path}.tmp"
    local start_time="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Collecting: $description"
    
    # Write metadata header
    {
        echo "Evidence Collection: $description"
        echo "Timestamp: $start_time"
        echo "Command: $command"
        echo "=========================================="
        echo ""
    } > "$temp_path"
    
    # Execute with timeout
    if timeout "$timeout_seconds" bash -c "$command" >> "$temp_path" 2>&1; then
        local exit_code=0
    else
        local exit_code=$?
        echo "Collection failed with exit code: $exit_code" >> "$temp_path"
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] WARNING: Failed to collect $description (exit: $exit_code)" >> "$ERROR_LOG"
    fi
    
    # Finalize and hash
    mv "$temp_path" "$full_path"
    local file_hash="$(shasum -a 256 "$full_path" | awk '{print $1}')"
    echo "${file_hash}  ${full_path#$OUTPUT_ROOT/}" >> "$MANIFEST_FILE"
    
    # Update chain of custody
    echo "[$start_time] Collected: $description (${file_hash:0:16}...)" >> "$CHAIN_FILE"
    
    return $exit_code
}

# Phase 1: Interface Configuration
collect_interface_configuration() {
    echo ""
    echo "=== PHASE 1: INTERFACE CONFIGURATION ==="
    
    collect_evidence \
        "Network interface configuration" \
        "$INTERFACE_DIR" \
        "ifconfig_all" \
        "ifconfig -a"
    
    collect_evidence \
        "Network hardware ports" \
        "$INTERFACE_DIR" \
        "hardware_ports" \
        "networksetup -listallhardwareports"
    
    collect_evidence \
        "Network service order" \
        "$INTERFACE_DIR" \
        "service_order" \
        "networksetup -listnetworkserviceorder"
    
    # Collect interface statistics
    for interface in $(ifconfig -l); do
        collect_evidence \
            "Interface statistics: $interface" \
            "$INTERFACE_DIR" \
            "stats_${interface}" \
            "netstat -i -I $interface"
    done
    
    # Document findings
    local interface_count="$(ifconfig -l | wc -w | tr -d ' ')"
    echo "Network Interfaces: $interface_count total" >> "$FINDINGS_FILE"
}

# Phase 2: Active Connections
collect_active_connections() {
    echo ""
    echo "=== PHASE 2: ACTIVE CONNECTIONS ==="
    
    collect_evidence \
        "All network connections" \
        "$CONNECTION_DIR" \
        "netstat_all" \
        "netstat -an"
    
    collect_evidence \
        "TCP connections" \
        "$CONNECTION_DIR" \
        "tcp_connections" \
        "netstat -an -p tcp"
    
    collect_evidence \
        "UDP connections" \
        "$CONNECTION_DIR" \
        "udp_connections" \
        "netstat -an -p udp"
    
    collect_evidence \
        "Process network connections" \
        "$CONNECTION_DIR" \
        "lsof_network" \
        "lsof -i -n -P"
    
    # Count established connections
    local established_count="$(netstat -an | grep -c ESTABLISHED || echo 0)"
    echo "Established Connections: $established_count" >> "$FINDINGS_FILE"
}

# Phase 3: Routing Configuration
collect_routing_configuration() {
    echo ""
    echo "=== PHASE 3: ROUTING CONFIGURATION ==="
    
    collect_evidence \
        "Routing table" \
        "$ROUTING_DIR" \
        "routing_table" \
        "netstat -rn"
    
    collect_evidence \
        "Default route" \
        "$ROUTING_DIR" \
        "default_route" \
        "route -n get default"
    
    collect_evidence \
        "ARP cache" \
        "$ROUTING_DIR" \
        "arp_cache" \
        "arp -an"
    
    collect_evidence \
        "Network state" \
        "$ROUTING_DIR" \
        "scutil_state" \
        "scutil --nwi"
}

# Phase 4: DNS Configuration and Monitoring
collect_dns_configuration() {
    echo ""
    echo "=== PHASE 4: DNS CONFIGURATION ==="
    
    collect_evidence \
        "DNS configuration" \
        "$DNS_DIR" \
        "dns_config" \
        "scutil --dns"
    
    collect_evidence \
        "DNS resolver configuration" \
        "$DNS_DIR" \
        "resolver_config" \
        "cat /etc/resolv.conf"
    
    collect_evidence \
        "mDNSResponder status" \
        "$DNS_DIR" \
        "mdns_status" \
        "dns-sd -V"
    
    # Check for DNS monitoring tools
    echo "DNS Monitoring Tools:" >> "$FINDINGS_FILE"
    
    if pgrep -f "DNSMonitor" > /dev/null 2>&1; then
        echo "  - DNSMonitor: ACTIVE" >> "$FINDINGS_FILE"
        
        collect_evidence \
            "DNSMonitor processes" \
            "$DNSMONITOR_DIR" \
            "dnsmonitor_processes" \
            "ps aux | grep -i dnsmonitor"
        
        collect_evidence \
            "DNSMonitor logs" \
            "$DNSMONITOR_DIR" \
            "dnsmonitor_logs" \
            "log show --predicate 'process == \"DNSMonitor\"' --last 1h --info --debug 2>/dev/null | head -1000"
        
        # Check for DNSMonitor configuration
        if [ -d "/Applications/DNSMonitor.app" ]; then
            collect_evidence \
                "DNSMonitor application info" \
                "$DNSMONITOR_DIR" \
                "app_info" \
                "ls -la /Applications/DNSMonitor.app/Contents/"
        fi
    else
        echo "  - DNSMonitor: NOT DETECTED" >> "$FINDINGS_FILE"
    fi
}

# Phase 5: VPN Detection
detect_vpn_connections() {
    echo ""
    echo "=== PHASE 5: VPN DETECTION ==="
    
    collect_evidence \
        "VPN configurations" \
        "$VPN_DIR" \
        "vpn_config" \
        "scutil --nc list"
    
    # Check for VPN interfaces
    local vpn_interfaces="$(ifconfig -l | tr ' ' '\n' | grep -E 'utun|ipsec|ppp|tap|tun' | tr '\n' ' ')"
    
    if [ -n "$vpn_interfaces" ]; then
        echo "VPN Interfaces Detected: $vpn_interfaces" >> "$FINDINGS_FILE"
        
        for interface in $vpn_interfaces; do
            collect_evidence \
                "VPN interface: $interface" \
                "$VPN_DIR" \
                "interface_${interface}" \
                "ifconfig $interface"
        done
    else
        echo "VPN Interfaces: NONE DETECTED" >> "$FINDINGS_FILE"
    fi
    
    # Check for VPN processes
    collect_evidence \
        "VPN process detection" \
        "$VPN_DIR" \
        "vpn_processes" \
        "ps aux | grep -E 'vpn|tunnel|cisco|openvpn|wireguard'"
}

# Phase 6: Private Relay Analysis
analyze_private_relay() {
    echo ""
    echo "=== PHASE 6: PRIVATE RELAY ANALYSIS ==="
    
    collect_evidence \
        "Proxy configuration" \
        "$PRIVATERELAY_DIR" \
        "proxy_config" \
        "scutil --proxy"
    
    # Check Private Relay status for each network service
    echo "Private Relay Status:" >> "$FINDINGS_FILE"
    
    for service in $(networksetup -listallnetworkservices | grep -v '*'); do
        local relay_status="$(networksetup -getprivaterelay "$service" 2>/dev/null || echo 'Not configured')"
        echo "  - $service: $relay_status" >> "$FINDINGS_FILE"
        
        echo "Service: $service" >> "${PRIVATERELAY_DIR}/relay_status.txt"
        echo "$relay_status" >> "${PRIVATERELAY_DIR}/relay_status.txt"
        echo "" >> "${PRIVATERELAY_DIR}/relay_status.txt"
    done
    
    # Check for Private Relay system extensions
    collect_evidence \
        "Private Relay extensions" \
        "$PRIVATERELAY_DIR" \
        "relay_extensions" \
        "systemextensionsctl list 2>/dev/null | grep -i relay || echo 'No relay extensions found'"
    
    # Check for Private Relay network connections
    collect_evidence \
        "Private Relay connections" \
        "$PRIVATERELAY_DIR" \
        "relay_connections" \
        "lsof -i -n -P | grep -E 'relay|icloud|mask'"
}

# Phase 7: Thunderbolt Analysis
analyze_thunderbolt() {
    echo ""
    echo "=== PHASE 7: THUNDERBOLT ANALYSIS ==="
    
    collect_evidence \
        "Thunderbolt devices" \
        "$THUNDERBOLT_DIR" \
        "thunderbolt_devices" \
        "system_profiler SPThunderboltDataType"
    
    collect_evidence \
        "Thunderbolt controller info" \
        "$THUNDERBOLT_DIR" \
        "controller_info" \
        "ioreg -l | grep -A 20 -i thunderbolt | head -500"
    
    # Check for Thunderbolt networking
    local thunderbolt_bridges="$(ifconfig -l | tr ' ' '\n' | grep bridge)"
    
    if [ -n "$thunderbolt_bridges" ]; then
        echo "Thunderbolt Bridges: $thunderbolt_bridges" >> "$FINDINGS_FILE"
        
        for bridge in $thunderbolt_bridges; do
            collect_evidence \
                "Bridge interface: $bridge" \
                "$THUNDERBOLT_DIR" \
                "bridge_${bridge}" \
                "ifconfig $bridge"
        done
    else
        echo "Thunderbolt Bridges: NONE DETECTED" >> "$FINDINGS_FILE"
    fi
}

# Phase 8: Virtual Interfaces
analyze_virtual_interfaces() {
    echo ""
    echo "=== PHASE 8: VIRTUAL INTERFACES ==="
    
    # Identify virtual interfaces
    local virtual_interfaces=""
    
    for interface in $(ifconfig -l); do
        case "$interface" in
            utun*|bridge*|tap*|tun*|gif*|stf*|vlan*|awdl*|llw*|lo*)
                virtual_interfaces="$virtual_interfaces $interface"
                ;;
        esac
    done
    
    if [ -n "$virtual_interfaces" ]; then
        echo "Virtual Interfaces:$virtual_interfaces" >> "$FINDINGS_FILE"
        
        for interface in $virtual_interfaces; do
            collect_evidence \
                "Virtual interface: $interface" \
                "$VIRTUAL_DIR" \
                "interface_${interface}" \
                "ifconfig $interface; echo '---'; netstat -i -I $interface"
        done
    else
        echo "Virtual Interfaces: NONE DETECTED" >> "$FINDINGS_FILE"
    fi
    
    # Check packet forwarding
    collect_evidence \
        "Packet forwarding status" \
        "$VIRTUAL_DIR" \
        "packet_forwarding" \
        "sysctl net.inet.ip.forwarding net.inet6.ip6.forwarding"
}

# Phase 9: Firewall and Security
collect_firewall_configuration() {
    echo ""
    echo "=== PHASE 9: FIREWALL CONFIGURATION ==="
    
    collect_evidence \
        "Application firewall status" \
        "$CONNECTION_DIR" \
        "app_firewall" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --listapps 2>/dev/null || echo 'Firewall not accessible'"
    
    collect_evidence \
        "Packet filter status" \
        "$CONNECTION_DIR" \
        "pf_status" \
        "pfctl -sa 2>/dev/null || echo 'Packet filter not accessible'"
    
    collect_evidence \
        "Packet filter rules" \
        "$CONNECTION_DIR" \
        "pf_rules" \
        "pfctl -sr 2>/dev/null || echo 'Cannot retrieve packet filter rules'"
}

# Phase 10: Network Extensions
analyze_network_extensions() {
    echo ""
    echo "=== PHASE 10: NETWORK EXTENSIONS ==="
    
    collect_evidence \
        "System extensions list" \
        "$CONNECTION_DIR" \
        "system_extensions" \
        "systemextensionsctl list 2>/dev/null || echo 'System extensions not accessible'"
    
    collect_evidence \
        "Network extension helpers" \
        "$CONNECTION_DIR" \
        "network_helpers" \
        "NEHelperCopyResponse 2>/dev/null || echo 'Network extension helpers not available'"
    
    # Count network-related extensions
    local extension_count="$(systemextensionsctl list 2>/dev/null | grep -c -i network || echo 0)"
    echo "Network Extensions: $extension_count detected" >> "$FINDINGS_FILE"
}

# Phase 11: WAN IP Detection
detect_wan_ip() {
    echo ""
    echo "=== PHASE 11: WAN IP DETECTION ==="
    
    echo "WAN IP Addresses:" >> "$FINDINGS_FILE"
    
    # Multiple methods to detect external IP
    local wan_ips=""
    
    # Method 1: Using curl to external services
    for service in "ifconfig.me" "ipinfo.io/ip" "checkip.amazonaws.com"; do
        local ip="$(curl -s --max-time 5 "https://$service" 2>/dev/null || echo '')"
        if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            wan_ips="$wan_ips $ip"
            echo "  - Detected via $service: $ip" >> "${CONNECTION_DIR}/wan_ip.txt"
        fi
    done
    
    # Method 2: Using dig
    local dig_ip="$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null || echo '')"
    if [ -n "$dig_ip" ]; then
        wan_ips="$wan_ips $dig_ip"
        echo "  - Detected via DNS: $dig_ip" >> "${CONNECTION_DIR}/wan_ip.txt"
    fi
    
    # Deduplicate and report
    if [ -n "$wan_ips" ]; then
        local unique_ips="$(echo $wan_ips | tr ' ' '\n' | sort -u | tr '\n' ' ')"
        echo "  - WAN IPs: $unique_ips" >> "$FINDINGS_FILE"
    else
        echo "  - WAN IP: Unable to determine" >> "$FINDINGS_FILE"
    fi
}

# Phase 12: SkyWalk Framework Analysis
analyze_skywalk() {
    echo ""
    echo "=== PHASE 12: SKYWALK FRAMEWORK ==="
    
    if command -v skywalkctl &> /dev/null; then
        collect_evidence \
            "SkyWalk overview" \
            "$CONNECTION_DIR" \
            "skywalk_show" \
            "skywalkctl show"
        
        collect_evidence \
            "SkyWalk statistics" \
            "$CONNECTION_DIR" \
            "skywalk_stats" \
            "skywalkctl stats"
        
        echo "SkyWalk Framework: ACTIVE" >> "$FINDINGS_FILE"
    else
        echo "SkyWalk Framework: NOT AVAILABLE" >> "$FINDINGS_FILE"
    fi
}

# Generate forensic report
generate_forensic_report() {
    echo ""
    echo "=== GENERATING FORENSIC REPORT ==="
    
    local report_file="${OUTPUT_ROOT}/NETWORK_FORENSICS_REPORT.md"
    local acquisition_end="$(date -u +"%Y-%m-%dT%H:%M:%S%z")"
    
    cat > "$report_file" <<-EOF
	# NETWORK STATE FORENSIC REPORT
	
	## Executive Summary
	
	This report documents a comprehensive network state forensic collection performed on a macOS system. The analysis encompasses interface configuration, active connections, routing tables, DNS configuration, VPN detection, Private Relay status, Thunderbolt networking, and virtual interface analysis.
	
	## Case Information
	
	- **Case ID**: $CASE_ID
	- **Examiner**: $EXAMINER
	- **Acquisition ID**: $ACQUISITION_ID
	- **Analysis Period**: $ACQUISITION_START to $acquisition_end
	
	## System Information
	
	- **Hostname**: $HOSTNAME
	- **OS Version**: $OS_VERSION
	- **Architecture**: $(uname -m)
	- **Kernel Version**: $(uname -r)
	
	## Key Findings
	
	$(cat "$FINDINGS_FILE")
	
	## Network Configuration Analysis
	
	### Interface Configuration
	
	The system has $(ifconfig -l | wc -w | tr -d ' ') network interfaces configured. Physical and virtual interfaces have been documented with their current configuration and statistics.
	
	### Active Connections
	
	Analysis revealed $(netstat -an | grep -c ESTABLISHED || echo 0) established connections at the time of collection. All connection states have been preserved for analysis.
	
	### DNS Configuration
	
	The DNS configuration has been captured including resolver settings, mDNSResponder status, and any DNS monitoring tools detected on the system.
	
	### VPN and Tunneling
	
	$(if [ -n "$(ifconfig -l | tr ' ' '\n' | grep -E 'utun|ipsec|ppp')" ]; then
	    echo "VPN interfaces were detected and analyzed. Details are preserved in the VPN analysis section."
	else
	    echo "No active VPN interfaces were detected at the time of collection."
	fi)
	
	### Private Relay Status
	
	iCloud Private Relay configuration has been assessed for all network services. The current state and any active relay connections have been documented.
	
	### Thunderbolt Networking
	
	Thunderbolt controller configuration and any associated networking components have been analyzed using both system_profiler and ioreg data.
	
	## Evidence Integrity
	
	All collected evidence has been hashed and recorded in the manifest file. To verify integrity:
	
	\`\`\`
	shasum -c "$MANIFEST_FILE"
	\`\`\`
	
	## Collection Methodology
	
	The network forensic collection followed a structured 12-phase approach:
	
	1. Interface Configuration
	2. Active Connections
	3. Routing Configuration
	4. DNS Configuration and Monitoring
	5. VPN Detection
	6. Private Relay Analysis
	7. Thunderbolt Analysis
	8. Virtual Interfaces
	9. Firewall Configuration
	10. Network Extensions
	11. WAN IP Detection
	12. SkyWalk Framework Analysis
	
	Each phase was executed with timeout controls and error handling to ensure collection completion even when individual operations failed.
	
	## Recommendations
	
	### Immediate Analysis
	
	1. Review established connections for suspicious endpoints
	2. Analyze DNS queries if monitoring tools were active
	3. Verify VPN and tunnel configurations against policy
	4. Examine virtual interfaces for unauthorized bridges or redirects
	
	### Further Investigation
	
	1. Correlate network connections with process activity
	2. Analyze routing tables for suspicious routes
	3. Review firewall rules for unauthorized modifications
	4. Compare network configuration against baseline
	
	## Conclusion
	
	This network state forensic collection provides a comprehensive snapshot of the system's network configuration and active connections. All evidence has been collected following forensic best practices with proper chain of custody documentation.
	
	---
	
	*Generated by TT03 Network Forensics v${SCRIPT_VERSION}*  
	*Report created: $(date)*
	EOF
    
    # Update chain of custody
    cat >> "$CHAIN_FILE" <<-EOF
	
	COLLECTION COMPLETED
	-------------------
	End Time: $acquisition_end
	Total Files: $(find "$OUTPUT_ROOT" -type f | wc -l)
	Evidence Size: $(du -sh "$OUTPUT_ROOT" | awk '{print $1}')
	
	Verification:
	  Manifest: $MANIFEST_FILE
	  Manifest Hash: $(shasum -a 256 "$MANIFEST_FILE" | awk '{print $1}')
	
	Examiner Certification:
	  I certify this network forensic collection was conducted
	  in accordance with established forensic procedures.
	  
	  Signature: _______________________
	  
	  Date: ____________________________
	EOF
    
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Forensic report generated: $report_file"
}

# Finalize evidence package
finalize_evidence() {
    echo ""
    echo "=== FINALIZING EVIDENCE PACKAGE ==="
    
    # Create evidence archive
    local archive_name="${CASE_ID}_network_${ACQUISITION_ID}.tar.gz"
    cd "$(dirname "$OUTPUT_ROOT")" || exit 1
    tar -czf "$archive_name" "$(basename "$OUTPUT_ROOT")"
    cd - > /dev/null || exit 1
    
    local archive_hash="$(shasum -a 256 "$(dirname "$OUTPUT_ROOT")/$archive_name" | awk '{print $1}')"
    
    # Display summary
    echo ""
    echo "=========================================="
    echo "NETWORK FORENSICS COLLECTION COMPLETE"
    echo "=========================================="
    echo "Case ID: $CASE_ID"
    echo "Evidence Location: $OUTPUT_ROOT"
    echo "Archive: $(dirname "$OUTPUT_ROOT")/$archive_name"
    echo "Archive SHA256: $archive_hash"
    echo ""
    echo "Key Findings:"
    grep -E "Interfaces:|Connections:|VPN|Private Relay|DNS Monitoring" "$FINDINGS_FILE" | head -10
    echo ""
    echo "To verify evidence integrity:"
    echo "  shasum -c '$MANIFEST_FILE'"
}

# Main execution
main() {
    echo "================================================"
    echo "NETWORK STATE FORENSICS v${SCRIPT_VERSION}"
    echo "================================================"
    echo "Case ID: $CASE_ID"
    echo "Examiner: $EXAMINER"
    echo ""
    
    # Check for recommended privileges
    if [ "$EUID" -ne 0 ]; then
        echo "WARNING: Running without root privileges"
        echo "Some network analysis capabilities will be limited"
        echo ""
    fi
    
    # Initialize environment
    initialize_forensic_environment
    
    # Execute collection phases
    collect_interface_configuration
    collect_active_connections
    collect_routing_configuration
    collect_dns_configuration
    detect_vpn_connections
    analyze_private_relay
    analyze_thunderbolt
    analyze_virtual_interfaces
    collect_firewall_configuration
    analyze_network_extensions
    detect_wan_ip
    analyze_skywalk
    
    # Generate reports and finalize
    generate_forensic_report
    finalize_evidence
}

# Signal handling for clean termination
trap 'echo "[$(date -u +"%Y-%m-%dT%H:%M:%S%z")] Collection interrupted"; exit 130' INT TERM

# Execute main function
main "$@"

exit 0