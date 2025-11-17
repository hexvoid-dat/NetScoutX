# NetScoutX

[![Go Reference](https://pkg.go.dev/github.com/hexe/net-scout?tab=doc)](https://pkg.go.dev/github.com/hexe/net-scout)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/hexe/net-scout/actions/workflows/go.yml/badge.svg)](https://github.com/hexe/net-scout/actions/workflows/go.yml)


<p align="center">
  <img src="assets/netscoutxbanner.jpeg" alt="NetScoutX banner" width="480" />
</p>

```
  _   _      _   ____                  _   __  __
 | \ | | ___| |_/ ___|  ___ ___  _   _| |_ \ \/ /
 |  \| |/ _ \ __\___ \ / __/ _ \| | | | __| \  / 
 | |\  |  __/ |_ ___) | (_| (_) | |_| | |_ /  \ 
 |_| \_|\___|\__|____/ \___\___/ \__,_|\__/_/\_\
```

## 🚀 Project Overview

NetScoutX is a powerful, professional-grade hybrid network reconnaissance tool designed for cybersecurity engineers and network administrators. It combines active scanning techniques with a sophisticated passive analysis engine to provide a comprehensive and deep understanding of network topology, device behavior, and potential security risks.

Developed by Hexe (Synth1ca Cybersec), NetScoutX embodies principles of directness, technical clarity, and security-oriented engineering, focusing on practical results for real-world network diagnostics.

## Quickstart

```bash
# Interactive mode (recommended)
sudo netscoutx

# Quick active scan of a home network
sudo net-scout -subnet 192.168.0.0/24 -output scan.json

# Active scan + short passive capture
sudo net-scout -subnet 192.168.0.0/24 -passive-duration 20s -output baseline.json
```

## ✨ Features

NetScoutX offers a rich set of capabilities, meticulously crafted to deliver senior-grade network intelligence:

### 🔵 Active Engine

*   **Host Discovery:** Lightweight TCP-based host discovery across specified subnets, probing common ports (80, 22, 21, 443).
*   **Port Scanning:** Concurrent TCP port scanning for a comprehensive list of common ports (20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080).
*   **UDP Scanning:** Targeted UDP scanning for well-known services: DNS (53), NTP (123), SNMP (161), SSDP (1900), mDNS (5353), with automatic service name identification.
*   **Service Fingerprinting:** Active probing to identify service versions for SSH, HTTP (Server banner), and FTP.
*   **OS Guessing:** Best-effort OS fingerprinting using TTL analysis (requires root/capabilities) and service banner heuristics.
*   **Vulnerability Lookup:** Basic in-memory database for flagging known vulnerabilities based on service banners.

### 🔵 Passive Engine (using `gopacket`/`libpcap`)

*   **Multi-Interface Capture:** Capable of sniffing traffic on multiple network interfaces simultaneously.
*   **ARP Passive Discovery:** Continuously monitors ARP traffic to discover hosts, map IPs to MACs, and identify MAC vendors via OUI lookup.
*   **DHCP Packet Parsing:** Decodes DHCP traffic to extract IP assignments, hostnames, and vendor class. Tracks DHCP servers and flags potential rogue DHCP activity.
*   **mDNS Service Discovery:** Parses mDNS traffic to discover hostnames and advertised services (e.g., `_http._tcp.local`), useful for identifying IoT devices and their capabilities. Flags sensitive mDNS leaks.
*   **DNS Query Parsing:** Monitors DNS queries to extract requested domains. Heuristics are applied to detect high-entropy domains (potential DGA) and queries to unusual TLDs.
*   **TLS JA3 Fingerprinting:** Extracts TLS ClientHello messages to compute JA3 fingerprints, enabling identification of client applications (browsers, malware, etc.). *Note: This feature is currently under development and may not be fully functional.*
*   **Passive Scoring Contribution:** Data from the passive engine directly contributes to the overall host risk score.

### 🔵 ARP Analysis

*   **Structured Anomalies:** Advanced detection of ARP anomalies, categorizing them into `ip_conflict` (IP claimed by multiple MACs) and `greedy_mac` (MAC claiming multiple IPs).
*   **Severity Classification:** Anomalies are classified by severity (High, Medium, Low), with intelligent recognition of "likely gateway" scenarios to reduce false positives.
*   **Risk Score Contribution:** ARP anomalies directly impact the host's risk score, highlighting suspicious network behavior.

### 🔵 Command-Line Interfaces (CLIs)

NetScoutX provides two distinct CLI experiences:

1.  **`net-scout` (Flag-based CLI):** A traditional, non-interactive tool for scripting and automated scans, configurable via command-line flags.
2.  **`net-scout-cli` (Interactive TUI-like CLI):** An interactive menu-driven interface offering:
    *   **Quick Scan:** Auto-detects subnet and performs a combined active + passive scan.
    *   **Custom Scan:** Allows manual CIDR input for active + passive scanning.
    *   **Passive-Only Mode:** Dedicated mode for continuous, stealthy passive network monitoring without sending any active probes.
    *   **Merged Overview:** Comprehensive host overview table displaying merged active and passive data (IP, MAC, Vendor, Risk, JA3 count, Open Ports).
    *   **Passive Summary:** Dedicated summary block for passive discovery statistics.
    *   **Settings:** Configuration for TTL fingerprinting and UDP scanning.
    *   **JSON Export:** Detailed scan results can be exported to JSON.
    *   **Result Diffing:** Compare current scan results against a baseline JSON report.

<p align="center">
  <img src="assets/sscli.png" alt="NetScoutX CLI screenshot" width="700" />
</p>

## Why NetScoutX vs Nmap?

NetScoutX is not a replacement for Nmap. Instead, it is a hybrid situational-awareness tool designed to complement traditional scanners. The project combines active scanning techniques (TCP/UDP, banner grabbing, risk scoring) with passive observation (ARP, DHCP, mDNS, DNS, TLS JA3) to provide longer-term context and anomaly detection that a single active scan cannot deliver.

- **Active + Passive:** NetScoutX runs active probes while simultaneously collecting passive signals to enrich host context.
- **Built-in risk scoring:** Automatic heuristic scoring highlights hosts that merit immediate attention.
- **Anomaly detection:** Structured ARP, DHCP, and DNS heuristics detect IP conflicts, rogue DHCP servers, suspicious domains, and IoT leaks.
- **Baseline diffing:** Compare scan results over time to detect configuration drift or newly introduced services/vulnerabilities.

Use NetScoutX alongside Nmap and other tools—each tool brings different strengths to network security and diagnostics.

## 🏗️ Architecture Overview

NetScoutX employs a hybrid architecture, seamlessly integrating active probing with a high-performance passive analysis pipeline.

```
+-------------------+       +-------------------+
|   Active Engine   |       |   Passive Engine  |
|-------------------|       |-------------------|
| - Host Discovery  |       | - Packet Capture  |
| - Port Scanning   |       |   (libpcap/gopacket)|
| - UDP Scanning    |       | - ARP Parser      |
| - Service Finger. |       | - DHCP Parser     |
| - OS Guessing     |       | - mDNS Parser     |
+-------------------+       | - DNS Parser      |
          |                 | - TLS JA3 Parser  |
          |                 +-------------------+
          |                           |
          |                           |
          v                           v
+-------------------------------------------------+
|             Merge & Analysis Pipeline           |
|-------------------------------------------------|
| 1. Active TCP Discovery                         |
| 2. ARP Enrichment (active ARP requests)         |
| 3. Passive Collection (ARP/DHCP/mDNS/DNS/JA3)   |
| 4. ARP Anomaly Analysis (structured)            |
| 5. Port Scan (TCP/UDP)                          |
| 6. Service Fingerprinting                       |
| 7. OS Guessing                                  |
| 8. Merge Passive & Active Results               |
| 9. Risk Evaluation (incorporating passive data) |
+-------------------------------------------------+
          |
          v
+-------------------+
|    CLI & Reports  |
|-------------------|
| - Interactive TUI |
| - Flag-based CLI  |
| - JSON Export     |
| - Console Output  |
| - Baseline Diff   |
+-------------------+
```

### Key Components:

*   **`internal/scanner`**: Houses the active scanning logic, including host discovery, port scanning, OS fingerprinting, and risk evaluation.
*   **`internal/passive`**: Contains the passive analysis engine, responsible for packet capture, protocol parsing (ARP, DHCP, mDNS, DNS, TLS), and initial data aggregation.
*   **`internal/merge`**: Provides the intelligence to combine the disparate data streams from the active and passive engines into a unified host view.
*   **`internal/report`**: Handles the generation of human-readable console output and machine-readable JSON reports.
*   **`cmd/net-scout` & `cmd/net-scout-cli`**: The entry points for the two distinct command-line interfaces.

## ⚡ Installation

NetScoutX requires Go 1.22+ and `libpcap` for packet capture capabilities.

### Prerequisites:

*   **Go 1.22+**: Ensure Go is installed and configured.
*   **`libpcap` development libraries**:
    *   **Ubuntu/Debian:** `sudo apt-get update && sudo apt-get install libpcap-dev`
    *   **CentOS/RHEL:** `sudo yum install libpcap-devel`
    *   **macOS:** `brew install libpcap`

### Official Installation (Recommended for system-wide access):

1.  **Build the interactive CLI application:**
    ```bash
    go build -o netscoutx ./cmd/net-scout-cli
    ```
2.  **Move the executable to a system PATH directory:**
    ```bash
    sudo mv netscoutx /usr/local/bin/
    ```
    *Note: Running `netscoutx` (especially in passive mode or with TTL fingerprinting) may require elevated privileges (`sudo`) or appropriate capabilities (`setcap cap_net_raw,cap_net_admin+ep /path/to/netscoutx`) to access raw network sockets.*

### Building the Flag-based CLI:

```bash
go build -o net-scout ./cmd/net-scout
```

## 🚀 Usage Examples

### Interactive CLI (`netscoutx`)

Simply run the executable (with `sudo` if needed for full functionality):

```bash
sudo netscoutx
```

You will be presented with a main menu:

```text
MAIN MENU
  1) Quick scan (auto-detect subnet, includes passive analysis)
  2) Custom scan (enter CIDR, includes passive analysis)
  3) Run tests (Docker required)
  4) Help
  5) About
  6) Exit
  7) Settings (TTL / OS fingerprint / UDP)
  8) Passive scan (listen only, no packets sent)
```

#### Example: Quick Scan (Active + Passive)

Choosing option `1` will initiate a quick scan on your detected local subnet, running both active probes and the passive analysis engine in parallel.

```text
$ sudo netscoutx
  _   _      _   ____                  _   __  __
 | \ | | ___| |_/ ___|  ___ ___  _   _| |_ \ \/ /
 |  \| |/ _ \ __\___ \ / __/ _ \| | | | __| \  / 
 | |\  |  __/ |_ ___) | (_| (_) | |_| | |_ /  \ 
 |_| \_|\___|\__|____/ \___\___/ \__,_|\__/_/\_\
Welcome to NetScoutX!
   Scan your network, enumerate hosts, and highlight security risks.
   Choose an option from the menu below:

MAIN MENU
  1) Quick scan (auto-detect subnet, includes passive analysis)
  2) Custom scan (enter CIDR, includes passive analysis)
  3) Run tests (Docker required)
  4) Help
  5) About
  6) Exit
  7) Settings (TTL / OS fingerprint / UDP)
  8) Passive scan (listen only, no packets sent)
Choose an option (1-8): 1

QUICK SCAN
Attempting to detect your local subnet...
Using detected subnet: 192.168.1.0/24
Results will be saved to quick_scan_20251117_123456.json
Compare with previous JSON report? (y/N): n

Starting scan for subnet: 192.168.1.0/24
Passive analysis will run in parallel for 10 seconds...
Step 1/5: Discovering active hosts...
Step 1.5/5: ARP Enrichment...
Found 3 total hosts after ARP enrichment
Step 2/5: ARP Anomaly Analysis...
Step 3/5: Port & Service Scanning...
... fingerprinting services...
Active scan completed.
Step 4/5: Merging passive and active results...
Step 5/5: Final analysis...

============================================================
SCAN RESULTS
============================================================

GENERAL WARNINGS:
   - ARP anomaly: MAC 00:11:22:33:44:55 is associated with multiple IP addresses: [192.168.1.1, 192.168.1.100]
   - ARP anomaly: MAC 00:11:22:33:44:55 acts as a gateway/proxy for 2 IPs (e.g., 192.168.1.1)

ACTIVE SCAN SUMMARY:
   - Actively probed hosts: 2
   - Scan duration: 12.543s

PASSIVE DISCOVERY SUMMARY:
   - Passively discovered hosts: 3
   - DHCP servers observed: 1

HOST OVERVIEW:
IP             MAC                VENDOR          HOSTNAME        RISK           JA3s   OPEN PORTS
192.168.1.1    00:11:22:33:44:55  Cisco           router.local    medium (45)    0      80/tcp, 443/tcp, 53/udp
192.168.1.100  00:22:33:44:55:66  Intel           my-pc           medium (30)    1      22/tcp, 8080/tcp
192.168.1.101  00:aa:bb:cc:dd:ee  Raspberry Pi F. raspberrypi     low (10)       0      -

--- Scan Results for subnet 192.168.1.0/24 ---
Scan finished in 12.543s. Found 3 host(s).

--- Detailed Host Report ---
--------------------------------------------------
HOST: 192.168.1.1 (00:11:22:33:44:55)
  OS (guess): Network device (Cisco)
  Risk: Medium (45/100)
  Open ports:
    PORT  PROTO  SERVICE  DETAILS
    80    tcp    HTTP     Server: Apache/2.4.29
    443   tcp    HTTPS    Server: nginx/1.18.0
    53    udp    DNS      
--------------------------------------------------
HOST: 192.168.1.100 (00:22:33:44:55:66)
  OS (guess): Linux (OpenSSH)
  Risk: Medium (30/100)
  Open ports:
    PORT  PROTO  SERVICE  DETAILS
    22    tcp    SSH      SSH-2.0-OpenSSH_8.2p1
    8080  tcp    HTTP     Server: Caddy/2.4.5
--------------------------------------------------
HOST: 192.168.1.101 (00:aa:bb:cc:dd:ee)
  OS (guess): Unknown
  Risk: Low (10/100)
  Open ports: none detected
--------------------------------------------------

=== Security summary ===
  Hosts scanned: 3
  High risk:   0
  Medium risk: 2
  Low risk:    1
```

#### Example: Passive Scan Only

Choosing option `8` will start the passive engine, listening for traffic without sending any active probes.

```text
$ sudo netscoutx
... 
MAIN MENU
... 
  8) Passive scan (listen only, no packets sent)
Choose an option (1-8): 8

PASSIVE SCAN
Starting passive network analysis. This will run until you stop it (Ctrl+C).
Listening for ARP, DHCP, mDNS, DNS, and TLS fingerprints...
Capture started. Press Ctrl+C to stop and see results.
^C
Passive: stopping capture...
Passive: capture stopped.

============================================================
PASSIVE SCAN RESULTS
============================================================

PASSIVE DISCOVERY SUMMARY:
   - Passively discovered hosts: 2
   - DHCP servers observed: 1

HOST OVERVIEW:
IP             MAC                VENDOR          HOSTNAME        RISK           JA3s   OPEN PORTS
192.168.1.100  00:22:33:44:55:66  Intel           my-pc           low (5)        1      -
192.168.1.102  00:ff:ee:dd:cc:bb  Samsung         smart-tv        low (8)        0      -
```

### Flag-based CLI (`net-scout`)

```bash
# Basic active scan
sudo ./net-scout -subnet 192.168.1.0/24 -output scan_report.json

# Active scan with UDP and passive collection for 30 seconds
sudo ./net-scout -subnet 192.168.1.0/24 -enable-udp -passive-duration 30s -output scan_report_full.json
```

## 📊 Risk Scoring Explanation

NetScoutX employs a heuristic risk scoring system (0-100) to highlight potential security concerns on discovered hosts. The score is derived from a combination of factors:

*   **Open Ports:** Each open port contributes a base score.
*   **Vulnerabilities:** Detected vulnerabilities (from banner analysis) add significant points based on their severity (CRITICAL, HIGH, MEDIUM).
*   **Specific Services:** Certain services (e.g., Telnet, SMB, RDP) inherently increase risk.
*   **Unencrypted HTTP:** Presence of HTTP on port 80 without HTTPS on 443 adds risk.
*   **ARP Anomalies:** High-severity ARP conflicts (IP claimed by multiple MACs) add substantial risk. Medium-severity greedy MACs also contribute.
*   **Passive Discovery Signals:**
    *   **Passively Discovered Hosts:** Hosts only seen passively (not responding to active probes) incur a slight risk.
    *   **JA3 Fingerprints:** The presence of JA3 fingerprints adds a base risk. More advanced analysis (not fully implemented) would flag rare or suspicious JA3s for higher risk.
    *   **DNS Queries:** The presence of DNS queries adds a base risk. More advanced analysis (not fully implemented) would flag suspicious domains (high entropy, unusual TLDs) for higher risk.
    *   **mDNS Leaks:** Sensitive mDNS service advertisements (e.g., file sharing, remote access protocols) contribute to risk.
    *   **Rogue DHCP:** Detection of potential rogue DHCP servers adds significant risk.

## 🚨 Anomaly Detection

NetScoutX actively identifies and reports various network anomalies:

*   **ARP Anomalies:**
    *   **IP Conflict (`ip_conflict`):** An IP address being claimed by more than one MAC address. This is a high-severity indicator of potential ARP spoofing or misconfiguration.
    *   **Greedy MAC (`greedy_mac`):** A single MAC address being associated with multiple IP addresses. This can indicate a legitimate gateway/router or a suspicious proxy ARP setup. NetScoutX intelligently attempts to classify these as "likely gateway" if common infrastructure services are detected, reducing false positives.
*   **DHCP Anomalies:**
    *   **Rogue DHCP Server:** Detection of DHCP servers that are not expected or exhibit suspicious behavior (e.g., unknown vendor, multiple servers on the segment).
*   **DNS Anomalies:**
    *   **High-Entropy Domains:** DNS queries for domains with unusually high entropy in their labels, often indicative of Domain Generation Algorithms (DGAs) used by malware.
    *   **Unusual TLDs:** Queries to Top-Level Domains (TLDs) that are uncommon or associated with malicious activity.
*   **mDNS Leaks:** Identification of sensitive mDNS service advertisements (e.g., file sharing, remote access protocols) that might expose internal network details.
*   **Rare JA3 Fingerprints:** (Planned) Identification of JA3 fingerprints that are uncommon in typical network traffic, potentially indicating custom tools or malware.

## 📄 JSON Report Structure Description

NetScoutX can export detailed scan results in JSON format. The `ScanResult` structure provides a comprehensive overview:

```json
{
  "timestamp": "2025-11-17T12:34:56.789Z",
  "subnet": "192.168.1.0/24",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "hostname": "router.local",
      "os_guess": "Network device (Cisco)",
      "os_confidence": "medium",
      "open_ports": [
        {
          "number": 53,
          "protocol": "udp",
          "state": "open",
          "service": "DNS"
        },
        {
          "number": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTP",
          "version": "Apache/2.4.29",
          "banner": "Server: Apache/2.4.29",
          "vulnerabilities": [
            {
              "cve_id": "CVE-2018-1312",
              "description": "Path traversal in Apache HTTPD 2.4.29 allowing exposure of arbitrary files.",
              "severity": "HIGH"
            }
          ]
        },
        {
          "number": 443,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTPS",
          "version": "nginx/1.18.0",
          "banner": "Server: nginx/1.18.0"
        }
      ],
      "risk_score": 45,
      "risk_level": "medium",
      "arp_flags": [
        "greedy_mac"
      ],
      "ja3_fingerprints": [],
      "dns_queries": [],
      "passively_discovered": false
    },
    {
      "ip": "192.168.1.100",
      "mac": "00:22:33:44:55:66",
      "hostname": "my-pc",
      "os_guess": "Linux (OpenSSH)",
      "os_confidence": "medium",
      "open_ports": [
        {
          "number": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "SSH",
          "version": "SSH-2.0-OpenSSH_8.2p1",
          "banner": "SSH-2.0-OpenSSH_8.2p1"
        },
        {
          "number": 8080,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTP",
          "version": "Caddy/2.4.5",
          "banner": "Server: Caddy/2.4.5"
        }
      ],
      "risk_score": 30,
      "risk_level": "medium",
      "arp_flags": [],
      "ja3_fingerprints": [
        "e7d705a3286e19ea42f587b344ee6865"
      ],
      "dns_queries": [
        "www.google.com",
        "update.microsoft.com"
      ],
      "passively_discovered": false
    },
    {
      "ip": "192.168.1.101",
      "mac": "00:aa:bb:cc:dd:ee",
      "hostname": "raspberrypi",
      "os_guess": "Unknown",
      "os_confidence": "low",
      "open_ports": [],
      "risk_score": 10,
      "risk_level": "low",
      "arp_flags": [],
      "ja3_fingerprints": [],
      "dns_queries": [],
      "passively_discovered": true
    }
  ],
  "scan_duration": "12.543s",
  "security_warnings": [
    "ARP anomaly: MAC 00:11:22:33:44:55 is associated with multiple IP addresses: [192.168.1.1, 192.168.1.100]",
    "ARP anomaly: MAC 00:11:22:33:44:55 acts as a gateway/proxy for 2 IPs (e.g., 192.168.1.1)"
  ]
}
```

## 🤝 Contributing

We welcome contributions to NetScoutX! Please refer to `CONTRIBUTING.md` for guidelines on how to get involved.

## 📜 License

NetScoutX is open-source software licensed under the MIT License. See the `LICENSE` file for details.

## 🗺️ Roadmap

NetScoutX is continuously evolving. Our planned phases of development include:

### Phase 1 — OSS Release (Current State)

*   Hybrid active + passive network reconnaissance.
*   Comprehensive host discovery, port scanning (TCP/UDP), service fingerprinting.
*   Advanced ARP anomaly detection and risk scoring.
*   Passive collection for ARP, DHCP, mDNS, DNS, TLS JA3.
*   Interactive and flag-based CLI.
*   JSON reporting and baseline diffing.

### Phase 2 — Enhancements

*   **Passive TLS JA3S:** Server-side JA3 fingerprinting for deeper TLS analysis.
*   **IoT Fingerprinting:** Enhanced classification of IoT devices based on mDNS/SSDP patterns and OUI.
*   **Behavior Graphs:** Visualization of host communication patterns ("talking hosts graph").
*   **Threat Intel Integration:** Integration with external threat intelligence feeds for enriched anomaly detection.
*   **Mini Web UI:** A lightweight web interface for easier monitoring and interaction.
*   **Plugin System:** A modular architecture to allow community-driven extensions and custom parsers.

### Phase 3 — Heavyweight Fingerprinting

*   **SMB, RDP, SSH Deep Parse:** In-depth protocol parsing for these critical services to extract more detailed information and identify specific vulnerabilities.
*   **TLS Full Parser:** Comprehensive parsing of TLS handshakes beyond JA3 for deeper security analysis.
*   **Protocol Decoders:** Development of decoders for additional application-layer protocols.

### Phase 4 — Enterprise Mode

*   **Alerting:** Real-time notification system for detected anomalies and high-risk events.
*   **SQLite / BadgerDB Storage:** Persistent storage options for historical scan data and passive observations.
*   **Live Dashboard:** A dynamic, real-time dashboard for continuous network visibility.
*   **Remote Agents:** Support for deploying agents across distributed networks for centralized monitoring.
*   **Distributed Scanning:** Orchestration of scans across multiple nodes for large-scale environments.

## 🧑‍💻 Maintainer Info

**Hexe**
*   Founder of Synth1ca Cybersec
*   Full-stack Developer
*   Cybersecurity Engineer
*   Tattoo Artist ("13ttt")

## 🙏 Credits

*   **`gopacket`**: For powerful packet capture and decoding capabilities.
*   **`golang.org/x/net/icmp`**: For ICMP-based TTL measurements.
*   **Community:** To all contributors and users who help make NetScoutX better.

---
