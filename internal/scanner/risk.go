package scanner

import "strings"

// EvaluateRisk computes a heuristic risk score and level for the host.
func EvaluateRisk(host *Host) {
	score := 0

	// Base risk for having open ports
	score += len(host.OpenPorts) * 2

	// Risk from ARP anomalies
	for _, anomaly := range host.Anomalies {
		switch anomaly.Severity {
		case RiskHigh:
			score += 25 // High-severity anomaly like IP conflict
		case RiskMedium:
			score += 10 // Medium-severity anomaly
		}
	}

	// Risk from passive signals
	if host.PassivelyDiscovered {
		score += 5 // Slightly higher risk for hosts only seen passively
	}
	if len(host.RareJA3Fingerprints) > 0 {
		score += 12 + minInt((len(host.RareJA3Fingerprints)-1)*3, 8)
	} else if len(host.JA3Fingerprints) > 0 {
		score += 3
	}
	if len(host.SuspiciousDNSQueries) > 0 {
		score += 10 + minInt((len(host.SuspiciousDNSQueries)-1)*2, 10)
	} else if len(host.DNSQueries) > 0 {
		score += 3
	}
	if len(host.LeakedMDNSServices) > 0 {
		score += 8 + minInt((len(host.LeakedMDNSServices)-1)*2, 10)
	}
	if host.PotentialRogueDHCP {
		score += 20
	}

	hasHTTP80 := false
	hasHTTPS443 := false

	for _, port := range host.OpenPorts {
		// Risk from vulnerabilities
		for _, vuln := range port.Vulnerabilities {
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				score += 25
			case "HIGH":
				score += 15
			case "MEDIUM":
				score += 8
			default:
				score += 5
			}
		}

		// Risk from specific services
		proto := strings.ToLower(port.Protocol)
		if proto == "" {
			proto = "tcp"
		}

		if proto == "tcp" {
			switch port.Number {
			case 21: // FTP
				score += 8
			case 22: // SSH
				score += 5
			case 23: // Telnet - high risk
				score += 20
			case 445, 139: // SMB
				score += 15
			case 3389: // RDP
				score += 15
			case 80:
				hasHTTP80 = true
			case 443:
				hasHTTPS443 = true
			}
		}

		if proto == "udp" {
			switch port.Number {
			case 161: // SNMP
				score += 10
			case 1900: // SSDP
				score += 8
			}
		}

		// Extra risk if we identified a specific version
		if port.Version != "" {
			score += 2
		}
	}

	if hasHTTP80 && !hasHTTPS443 {
		score += 10 // Unencrypted HTTP is a risk
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	host.RiskScore = score
	host.RiskLevel = classifyRisk(score)
}

func classifyRisk(score int) RiskLevel {
	switch {
	case score >= 70:
		return RiskHigh
	case score >= 30:
		return RiskMedium
	default:
		return RiskLow
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
