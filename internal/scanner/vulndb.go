package scanner

import "strings"

// vulnerabilityDatabase represents a small built-in lookup table for demo purposes.
var vulnerabilityDatabase = []struct {
	SoftwareName string
	CheckFunc    func(banner string) bool
	VulnInfo     Vulnerability
}{
	{
		SoftwareName: "OpenSSH",
		CheckFunc: func(banner string) bool {
			return strings.Contains(banner, "OpenSSH") && (strings.Contains(banner, "7.6") || strings.Contains(banner, "7.5") || strings.Contains(banner, "7.2"))
		},
		VulnInfo: Vulnerability{
			CVE_ID:      "CVE-2018-15473",
			Description: "Username enumeration vulnerability allowing remote attackers to confirm valid logins.",
			Severity:    "MEDIUM",
		},
	},
	{
		SoftwareName: "Apache",
		CheckFunc: func(banner string) bool {
			return strings.Contains(banner, "Server: Apache/2.4.29")
		},
		VulnInfo: Vulnerability{
			CVE_ID:      "CVE-2018-1312",
			Description: "Path traversal in Apache HTTPD 2.4.29 allowing exposure of arbitrary files.",
			Severity:    "HIGH",
		},
	},
	{
		SoftwareName: "vsftpd",
		CheckFunc: func(banner string) bool {
			return (strings.Contains(banner, "vsftpd") || strings.Contains(banner, "vsFTPd")) && (strings.Contains(banner, "2.3.4") || strings.Contains(banner, "3.0.2"))
		},
		VulnInfo: Vulnerability{
			CVE_ID:      "CVE-2011-2523",
			Description: "Backdoor command execution risk in the trojanized vsftpd 2.3.4 build.",
			Severity:    "CRITICAL",
		},
	},
	{
		SoftwareName: "ProFTPD",
		CheckFunc: func(banner string) bool {
			return strings.Contains(banner, "ProFTPD 1.3.3c")
		},
		VulnInfo: Vulnerability{
			CVE_ID:      "CVE-2010-4221",
			Description: "Remote code execution issue impacting ProFTPD 1.3.3c.",
			Severity:    "CRITICAL",
		},
	},
	{
		SoftwareName: "Samba",
		CheckFunc: func(banner string) bool {
			return strings.Contains(banner, "Samba 3.0.20")
		},
		VulnInfo: Vulnerability{
			CVE_ID:      "CVE-2007-2446",
			Description: "Samba trans2 stack overflow enabling remote code execution.",
			Severity:    "CRITICAL",
		},
	},
	{
		SoftwareName: "MySQL",
		CheckFunc: func(banner string) bool {
			return strings.Contains(banner, "mysql_native_password") && strings.Contains(banner, "5.0.51a")
		},
		VulnInfo: Vulnerability{
			CVE_ID:      "CVE-2008-0226",
			Description: "Authentication bypass affecting MySQL 5.0.51a.",
			Severity:    "HIGH",
		},
	},
}

// CheckBannerForVulnerabilities compares the supplied banner against the local database.
func CheckBannerForVulnerabilities(banner string) []Vulnerability {
	var foundVulns []Vulnerability
	if banner == "" {
		return foundVulns
	}

	for _, entry := range vulnerabilityDatabase {
		if entry.CheckFunc(banner) {
			foundVulns = append(foundVulns, entry.VulnInfo)
		}
	}
	return foundVulns
}
