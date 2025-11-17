# NetScoutX Architecture Overview

This document provides a detailed overview of the NetScoutX architecture, describing its core components, data flow, and key design principles. NetScoutX is built as a hybrid network reconnaissance tool, integrating both active probing and passive traffic analysis.

## 1. High-Level Architecture

NetScoutX's architecture is modular, separating concerns into distinct packages for active scanning, passive analysis, data merging, and reporting.

```
+-------------------+       +-------------------+
|   Active Engine   |       |   Passive Engine  |
|-------------------|       |-------------------|
| - Host Discovery  |       | - Packet Capture  |
| - Port Scanning   |       |   (libpcap/gopacket)|
| - UDP Scanning    |       | - ARP Parser      |
| - Service Finger. |       | - DHCP Parser     |
| - OS Guessing     |       | - mDNS Parser     |
| - Vuln Lookup     |       | - DNS Parser      |
+-------------------+       | - TLS JA3 Parser  |
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

## 2. Core Data Models

The project revolves around two primary host representations and a unified scan result:

### `internal/scanner/models.go`

*   **`Host`**: Represents a device discovered on the network. This is the central entity for reporting and risk evaluation.
    *   `IP`, `MAC`, `Hostname`, `OSGuess`, `OSConfidence`
    *   `OpenPorts []Port`
    *   `RiskScore`, `RiskLevel`
    *   `Anomalies []ARPAnomaly` (internal for risk scoring)
    *   `ARPFlags []string` (for JSON export)
    *   **Passive Data Fields**: `JA3Fingerprints`, `RareJA3Fingerprints`, `DNSQueries`, `SuspiciousDNSQueries`, `LeakedMDNSServices`, `PotentialRogueDHCP`, `PassivelyDiscovered`.
*   **`Port`**: Details about an open port.
    *   `Number`, `Protocol`, `State`, `Service`, `Version`, `Banner`, `Vulnerabilities []Vulnerability`.
*   **`ARPAnomaly`**: Structured representation of ARP-related anomalies.
    *   `Kind` (`ARPConflictIP`, `ARPGreedyMAC`), `IP`, `MAC`, `Involved`, `Severity`, `Message`.
*   **`ScanResult`**: Aggregates all scan data for reporting.
    *   `Timestamp`, `Subnet`, `Hosts []Host`, `ScanDuration`, `SecurityWarnings []string`.

### `internal/passive/model.go`

*   **`Host` (aliased as `passive.Host`)**: Represents a device observed *passively*. Designed to be merged into `scanner.Host`.
    *   `IPs map[string]time.Time`, `MAC`, `Hostname`, `Vendor`, `Services map[string]struct{}` (mDNS), `FirstSeen`, `LastSeen`.
    *   `DHCPHostname`, `DHCPVendorCode`.
    *   `DNSQueries`, `SuspiciousDNSQueries`.
    *   `JA3Fingerprints`, `RareJA3Fingerprints`.
    *   `LeakedMDNSServices`, `PotentialRogueDHCP`.
*   **`AnalysisResult`**: Stores the complete state of the passive analysis.
    *   `Hosts map[string]*Host` (keyed by MAC), `DHCPServers map[string]*DHCPServer`, `JA3Observatory map[string]*JA3Observation`.
*   **`DHCPServer`**: Metadata about observed DHCP servers.
*   **`JA3Observation`**: Tracks JA3 fingerprint frequency for rarity detection.

## 3. Active Engine (`internal/scanner`)

This package is responsible for actively probing the network.

*   **`discover.go`**:
    *   `DiscoverHosts(subnet string)`: Performs TCP-based host discovery by probing common ports (80, 22, 21, 443).
    *   `GetIPsInSubnet(subnetStr string)`: Utility to generate all IP addresses within a CIDR block.
*   **`arp.go`**:
    *   `CollectARP(ips []net.IP, subnet string)`: Sends active ARP requests using `gopacket/pcap` and listens for replies to build IP-to-MAC mappings. Handles interface selection and permissions.
    *   `EnrichHostsWithARP(hosts []Host, subnet string)`: Merges active ARP results into `scanner.Host` list, updating MACs and adding ARP-only discovered hosts.
*   **`scan.go`**:
    *   `PortScanner(hosts []Host)`: Performs concurrent TCP port scanning on a predefined list of common ports.
    *   Includes basic banner grabbing and calls `CheckBannerForVulnerabilities`.
*   **`udp_scan.go`**:
    *   `UdpScanner(hosts []Host)`: Performs lightweight UDP probes on a curated set of ports (53, 123, 161, 1900, 5353).
    *   Maps port numbers to well-known service names (e.g., 53 -> "DNS").
*   **`service_fingerprint.go`**:
    *   `FingerprintServices(hosts []Host)`: Actively probes open TCP ports (21, 22, 80, 443, 8080) to identify service versions (e.g., SSH banner, HTTP Server header, FTP banner).
*   **`fingerprint.go`**:
    *   `GuessOS(host *Host)`: Attempts to guess the OS using TTL values from ICMP probes (requires raw socket access) and heuristics based on service banners.
    *   `ConfigureFingerprint`, `GetFingerprintOptions`: Manages TTL fingerprinting settings.
*   **`security.go`**:
    *   `AnalyzeARP(hosts []Host)`: Detects and classifies ARP anomalies (`ARPConflictIP`, `ARPGreedyMAC`) with severity levels (High, Medium, Low). Includes logic to identify "likely gateway" MACs based on associated IPs and open ports.
*   **`risk.go`**:
    *   `EvaluateRisk(host *Host)`: Calculates a heuristic risk score (0-100) and `RiskLevel` for each host. Integrates factors from open ports, vulnerabilities, ARP anomalies, and passive signals.
*   **`vulndb.go`**:
    *   `CheckBannerForVulnerabilities(banner string)`: A small, in-memory database for demo purposes to flag known vulnerabilities based on service banners.
*   **`network.go`**:
    *   `DetectLocalSubnet()`: Auto-detects a usable IPv4 subnet on the host machine, ignoring virtual/loopback interfaces.

## 4. Passive Engine (`internal/passive`)

This package is responsible for passively observing network traffic using `gopacket/pcap`.

*   **`engine.go`**:
    *   `Engine` struct: Manages interfaces, `AnalysisResult`, context for graceful shutdown.
    *   `NewEngine(interfaces ...string)`: Creates an engine, auto-detects interfaces if none specified.
    *   `Start()`, `Stop()`: Controls packet capture.
    *   `sniffInterface(ifaceName string)`: Opens a `pcap` handle, sets a BPF filter (`arp or udp port 67/68/53/5353 or tcp port 443`), and processes packets.
    *   `dispatchPacket(packet gopacket.Packet)`: Inspects packet layers and dispatches them to appropriate parsers (ARP, DHCP, mDNS, DNS, JA3).
*   **`helpers.go`**:
    *   `ensureHostLocked(mac string)`: Thread-safe helper to retrieve or create `passive.Host` entries.
    *   `normalizeMAC(mac string)`: Standardizes MAC address format.
*   **`heuristics.go`**:
    *   Contains constants and functions for passive anomaly detection: `infraVendorKeywords`, `commonTLDs`, `sensitiveMDNSServices`, `wellKnownJA3Fingerprints`.
    *   `isLikelyInfrastructureVendor(vendor string)`: Checks if a vendor string matches known infrastructure providers.
    *   `isSensitiveMDNSService(service string)`: Flags mDNS services that might indicate sensitive information leakage.
    *   `classifyDNSQuery(query string)`: Analyzes DNS queries for high entropy (DGA) and unusual TLDs.
    *   `shannonEntropy(label string)`: Calculates Shannon entropy for a string.
    *   `isCommonJA3(hash string)`: Checks if a JA3 hash is a well-known fingerprint.
*   **`oui.go`**:
    *   `ouiMap`: A curated, embedded map of OUI prefixes to vendor names.
    *   `GetVendorFromMAC(mac string)`: Performs OUI lookup.
*   **`parser_arp.go`**:
    *   `parseARP(arp *layers.ARP)`: Processes passive ARP packets, updates `passive.Host` with IP/MAC/Vendor.
*   **`parser_dhcp.go`**:
    *   `parseDHCP(packet gopacket.Packet)`: Decodes DHCPv4 packets, extracts lease info, updates `passive.Host` with hostname, tracks `DHCPServer`s, and flags `PotentialRogueDHCP` based on heuristics.
*   **`parser_dns.go`**:
    *   `parseDNS(packet gopacket.Packet)`: Processes DNS queries, extracts queried domains, and flags `SuspiciousDNSQueries` using heuristics from `heuristics.go`.
*   **`parser_ja3.go`**:
    *   `parseJA3(packet gopacket.Packet)`: **(Currently non-functional due to compilation errors)** Intended to extract TLS ClientHello messages, compute JA3 fingerprints, and update `passive.Host` with `JA3Fingerprints` and `RareJA3Fingerprints` based on `JA3Observation` from `JA3Observatory`.
    *   `extractJA3String(payload []byte)`: Manually parses TLS handshake records to build the JA3 string components.
    *   `recordJA3Observation(hash, source string)`: Tracks JA3 fingerprint frequency.
*   **`passive_test.go`**: Unit tests for passive parsers, loading `.pcap` fixtures.
*   **`testdata/generate/main.go`**: Script to generate `.pcap` test data.

## 5. Merge Pipeline (`internal/merge`)

This package is responsible for combining the results from the active and passive engines.

*   **`merge.go`**:
    *   `MergeResults(activeHosts []scanner.Host, passiveResult *passive.AnalysisResult)`:
        *   Takes a list of actively discovered hosts and the full passive analysis result.
        *   Enriches existing `scanner.Host` entries with passive data (MAC, Hostname, JA3s, DNS queries).
        *   Creates new `scanner.Host` entries for devices discovered *only* passively, marking them with `PassivelyDiscovered: true`.

## 6. Reporting (`internal/report`)

This package handles the output formatting.

*   **`report.go`**:
    *   `RenderConsole(result scanner.ScanResult)`: Formats scan results for console output, including structured open port tables.
    *   `SaveJSON(result scanner.ScanResult, filePath string)`: Exports `ScanResult` to a JSON file.
    *   `LoadJSON(result scanner.ScanResult, filePath string)`: Loads a `ScanResult` from a JSON file.
*   **`diff.go`**:
    *   `ComputeScanDiff(oldRes, newRes scanner.ScanResult)`: Compares two scan results to identify new/missing hosts and port changes.
    *   `RenderDiff(diff ScanDiff)`: Formats and prints the scan differences.

## 7. Command-Line Interfaces (`cmd`)

### `cmd/net-scout/main.go` (Flag-based CLI)

*   Parses command-line flags (`-subnet`, `-output`, `-disable-ttl`, `-ttl-only-with-sudo`, `-baseline`, `-enable-udp`, `-passive-duration`).
*   Executes the full scan pipeline: Host Discovery -> ARP Enrichment -> ARP Analysis -> Port Scan -> UDP Scan -> Service Fingerprinting -> OS Fingerprinting -> **Passive Collection (if enabled)** -> **Merge Results** -> Risk Evaluation -> Reporting.
*   Logs progress to `log.Println`.

### `cmd/net-scout-cli/main.go` (Interactive CLI)

*   Provides a menu-driven interface.
*   **`runActiveScan(isQuick bool)`**: Orchestrates the combined active and passive scan pipeline.
    *   Starts `passive.Engine` in parallel.
    *   Runs active discovery, ARP enrichment, port/service scanning, OS fingerprinting.
    *   Waits for a fixed `passiveCollectionDuration` (10s) or active scan completion.
    *   Stops `passive.Engine`.
    *   Calls `merge.MergeResults`.
    *   Performs final ARP analysis and risk evaluation on merged hosts.
    *   Presents `ACTIVE SCAN SUMMARY`, `PASSIVE DISCOVERY SUMMARY`, and `HOST OVERVIEW` table.
*   **`runPassiveScan()`**: Dedicated mode for passive-only collection.
    *   Starts `passive.Engine`.
    *   Listens until Ctrl+C.
    *   Stops `passive.Engine`.
    *   Presents `PASSIVE DISCOVERY SUMMARY` and `HOST OVERVIEW` table (using `passiveEngine.Result.HostsAsSlice()`).
*   **`showSettings()`**: Allows toggling TTL fingerprinting, "TTL only with sudo", and UDP scanning.
*   **`printHostOverviewTable(hosts []scanner.Host)`**: Displays a formatted table with IP, MAC, Vendor, Hostname, Risk, JA3s count, and Open Ports.
*   **`printPassiveSummary(result *passive.AnalysisResult)`**: Displays a summary of passive findings (hosts, DHCP servers).

## 8. File Tree

```
.
├── cmd/
│   ├── net-scout/
│   │   └── main.go             # Flag-based CLI entry point
│   └── net-scout-cli/
│       └── main.go             # Interactive CLI entry point
├── docker-compose.yml          # (Not analyzed, assumed for E2E tests)
├── go.mod                      # Go module definition
├── go.sum                      # Go module checksums
├── howtouse.md                 # (Not analyzed, assumed user guide)
├── INSTALL.md                  # Installation instructions
├── internal/
│   ├── merge/
│   │   └── merge.go            # Logic for merging active and passive results
│   ├── passive/
│   │   ├── engine.go           # Core passive sniffing engine
│   │   ├── helpers.go          # Passive engine helper functions
│   │   ├── heuristics.go       # Passive anomaly detection heuristics
│   │   ├── model.go            # Passive data models
│   │   ├── oui.go              # OUI (MAC vendor) lookup database
│   │   ├── parser_arp.go       # Passive ARP parser
│   │   ├── parser_dhcp.go      # Passive DHCP parser
│   │   ├── parser_dns.go       # Passive DNS query parser
│   │   ├── parser_ja3.go       # Passive TLS JA3 fingerprint parser (currently non-functional)
│   │   ├── parser_mdns.go      # Passive mDNS parser
│   │   └── passive_test.go     # Unit tests for passive parsers
│   │   └── testdata/           # Directory for .pcap test fixtures
│   │       └── generate/
│   │           └── main.go     # Script to generate .pcap test data
│   ├── report/
│   │   ├── diff.go             # Scan result diffing logic
│   │   └── report.go           # Console and JSON reporting
│   └── scanner/
│       ├── arp.go              # Active ARP collection and host enrichment
│       ├── discover.go         # Active TCP host discovery
│       ├── fingerprint.go      # OS guessing (TTL + banners)
│       ├── models.go           # Core data models (Host, Port, ARPAnomaly, ScanResult)
│       ├── network.go          # Local subnet detection
│       ├── risk.go             # Risk scoring engine
│       ├── scan.go             # Active TCP port scanning
│       ├── security.go         # ARP anomaly analysis (AnalyzeARP)
│       ├── security_test.go    # Unit tests for ARP anomaly analysis
│       ├── service_fingerprint.go # Active service version fingerprinting
│       ├── udp_scan.go         # Active UDP port scanning
│       └── vulndb.go           # Simple in-memory vulnerability database
├── net-scout                   # (Built executable for flag-based CLI)
├── net-scout-cli               # (Built executable for interactive CLI)
├── netscoutx                   # (Built executable for interactive CLI, renamed)
└── run_e2e_tests.sh            # (Not analyzed, assumed E2E test script)
```

---
