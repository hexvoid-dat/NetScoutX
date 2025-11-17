package scanner

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpTimeout = 2 * time.Second
)

type osHint struct {
	family string
	detail string
}

type FingerprintOptions struct {
	DisableTTL      bool
	TTLOnlyWithSudo bool
}

var fingerprintOptions = FingerprintOptions{}
var ttlPermissionWarningOnce sync.Once
var ttlSudoInfoOnce sync.Once

func ConfigureFingerprint(opts FingerprintOptions) {
	fingerprintOptions = opts
}

func GetFingerprintOptions() FingerprintOptions {
	return fingerprintOptions
}

// GuessOS combines TTL probes and captured service banners to build a best-effort OS guess.
// The heuristic is intentionally lightweight and only offers broad families (Linux, Windows, network device).
func GuessOS(host *Host) {
	opts := fingerprintOptions
	var ttlHint osHint
	hasTTLEvidence := false

	if !opts.DisableTTL {
		if opts.TTLOnlyWithSudo && !isRoot() {
			ttlSudoInfoOnce.Do(func() {
				log.Println("TTL probe disabled: --ttl-only-with-sudo set and process is not running as root.")
			})
		} else {
			ttl, ttlErr := measureTTL(host.IP)
			var ok bool
			if ttlErr == nil {
				ttlHint, ok = hintFromTTL(ttl)
				hasTTLEvidence = ok
			} else if ttlErr != errNoTTLData {
				log.Printf("TTL probe for %s failed: %v", host.IP, ttlErr)
			}
		}
	}

	bannerHint, hasBannerEvidence := hintFromBanners(host.OpenPorts)

	host.OSGuess, host.OSConfidence = combineHints(ttlHint, hasTTLEvidence, bannerHint, hasBannerEvidence)
}

var errNoTTLData = fmt.Errorf("no ttl response")

func measureTTL(ip string) (byte, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if isPermissionError(err) {
			ttlPermissionWarningOnce.Do(func() {
				log.Println("TTL probe skipped (raw sockets unavailable). Run as root or grant cap_net_raw to enable TTL-based OS fingerprinting.")
			})
			return 0, errNoTTLData
		}
		return 0, err
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  1,
			Data: []byte("net-scout-ttl"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	if _, err := conn.WriteTo(msgBytes, destAddr); err != nil {
		return 0, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(icmpTimeout)); err != nil {
		return 0, err
	}

	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return 0, errNoTTLData
	}
	if n > 8 && peer.String() == ip {
		return reply[8], nil
	}
	return 0, errNoTTLData
}

func isPermissionError(err error) bool {
	if os.IsPermission(err) {
		return true
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "operation not permitted") || strings.Contains(errMsg, "permission denied")
}

func isRoot() bool {
	return os.Geteuid() == 0
}

func hintFromTTL(ttl byte) (osHint, bool) {
	switch {
	case ttl > 0 && ttl <= 65:
		return osHint{family: "Linux"}, true
	case ttl > 65 && ttl <= 130:
		return osHint{family: "Windows"}, true
	case ttl > 130:
		return osHint{family: "Network device"}, true
	default:
		return osHint{}, false
	}
}

func hintFromBanners(ports []Port) (osHint, bool) {
	for _, port := range ports {
		hint, ok := classifyBanner(port.Banner)
		if ok {
			return hint, true
		}
	}
	return osHint{}, false
}

func classifyBanner(banner string) (osHint, bool) {
	if banner == "" {
		return osHint{}, false
	}
	lower := strings.ToLower(banner)

	switch {
	case strings.Contains(lower, "openssh"):
		return osHint{family: "Linux", detail: "OpenSSH"}, true
	case strings.Contains(lower, "dropbear"):
		return osHint{family: "Network device", detail: "Dropbear"}, true
	case strings.Contains(lower, "ssh"):
		return osHint{family: "Linux", detail: "SSH"}, true
	case strings.Contains(lower, "server: nginx"):
		return osHint{family: "Linux", detail: "nginx"}, true
	case strings.Contains(lower, "server: apache"):
		return osHint{family: "Linux", detail: "Apache"}, true
	case strings.Contains(lower, "server: caddy"):
		return osHint{family: "Linux", detail: "Caddy"}, true
	case strings.Contains(lower, "server: litespeed"):
		return osHint{family: "Linux", detail: "LiteSpeed"}, true
	case strings.Contains(lower, "microsoft-iis") || strings.Contains(lower, "asp.net"):
		return osHint{family: "Windows", detail: "IIS"}, true
	default:
		return osHint{}, false
	}
}

func combineHints(ttlHint osHint, hasTTL bool, bannerHint osHint, hasBanner bool) (string, OSConfidence) {
	switch {
	case hasTTL && hasBanner:
		if ttlHint.family == bannerHint.family || ttlHint.family == "" {
			return formatOSGuess(bannerHint), ConfidenceHigh
		}
		guess := formatOSGuess(ttlHint)
		if guess == "" {
			guess = formatOSGuess(bannerHint)
		}
		if guess == "" {
			guess = "Unknown"
		}
		return guess, ConfidenceLow
	case hasBanner:
		return formatOSGuess(bannerHint), ConfidenceMedium
	case hasTTL:
		return formatOSGuess(ttlHint), ConfidenceMedium
	default:
		return "Unknown", ConfidenceLow
	}
}

func formatOSGuess(h osHint) string {
	if h.family == "" {
		return ""
	}
	if h.detail == "" {
		return h.family
	}
	return fmt.Sprintf("%s (%s)", h.family, h.detail)
}
