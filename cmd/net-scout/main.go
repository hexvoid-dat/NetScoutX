package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/hexe/net-scout/internal/merge"
	"github.com/hexe/net-scout/internal/passive"
	"github.com/hexe/net-scout/internal/report"
	"github.com/hexe/net-scout/internal/scanner"
)

func main() {
	subnet := flag.String("subnet", "", "Subnet to scan in CIDR notation (e.g. 192.168.1.0/24)")
	outputFile := flag.String("output", "", "Optional path to a JSON report file")
	disableTTL := flag.Bool("disable-ttl", false, "Disable TTL-based OS fingerprinting")
	ttlOnlyWithSudo := flag.Bool("ttl-only-with-sudo", false, "Only run TTL-based OS fingerprinting when running as root")
	baselineFile := flag.String("baseline", "", "Optional path to a previous JSON report to diff against")
	enableUDP := flag.Bool("enable-udp", false, "Enable UDP scanning on a small set of common ports (53, 123, 5353, 1900)")
	passiveDuration := flag.Duration("passive-duration", 0, "Duration for passive collection (e.g., 30s, 1m). Set to 0 to disable.")
	flag.Parse()

	scanner.ConfigureFingerprint(scanner.FingerprintOptions{
		DisableTTL:      *disableTTL,
		TTLOnlyWithSudo: *ttlOnlyWithSudo,
	})

	if *subnet == "" {
		fmt.Println("Error: the -subnet flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	startTime := time.Now()
	log.Println("Starting scan...")

	var passiveEngine *passive.Engine
	if *passiveDuration > 0 {
		log.Printf("Starting passive collection for %s...", *passiveDuration)
		passiveEngine = passive.NewEngine()
		passiveEngine.Start()
		defer passiveEngine.Stop() // Ensure passive engine is stopped
	}

	// Krok 1: Odkrywanie hostów
	log.Printf("Step 1/5: Discovering hosts in subnet %s...", *subnet)
	activeHosts, err := scanner.DiscoverHosts(*subnet)
	if err != nil {
		log.Fatalf("Critical error during host discovery: %v", err)
	}

	if len(activeHosts) == 0 {
		log.Println("No active hosts found. Aborting.")
		// If passive was running, let it finish its duration before reporting.
		if passiveEngine != nil {
			time.Sleep(*passiveDuration)
		}
		return
	}

	// Optional: ARP enrichment
	log.Println("Step 1.5/5: Enriching hosts with ARP data...")
	arpEnrichedHosts, _, arpActive := scanner.EnrichHostsWithARP(activeHosts, *subnet)
	if arpActive {
		activeHosts = arpEnrichedHosts
		log.Printf("ARP enrichment complete. Total hosts to scan: %d", len(activeHosts))
	}

	// Step 2: Run security heuristics.
	log.Printf("Step 2/5: Security analysis for %d host(s)...", len(activeHosts))
	anomalies := scanner.AnalyzeARP(activeHosts)
	hostMap := make(map[string]*scanner.Host)
	for i := range activeHosts {
		hostMap[activeHosts[i].IP] = &activeHosts[i]
	}
	var warnings []string
	for _, anomaly := range anomalies {
		warnings = append(warnings, anomaly.Message)
		// Associate anomaly with the host for risk scoring
		if anomaly.IP != "" {
			if host, ok := hostMap[anomaly.IP]; ok {
				host.Anomalies = append(host.Anomalies, anomaly)
				host.ARPFlags = append(host.ARPFlags, string(anomaly.Kind))
			}
		}
	}

	// Step 3: Scan ports and services.
	log.Printf("Step 3/5: Scanning ports on %d host(s)...", len(activeHosts))
	scanner.PortScanner(activeHosts)
	runOSFingerprinting(activeHosts)

	if *enableUDP {
		log.Println("Running UDP scan...")
		scanner.UdpScanner(activeHosts)
	}

	log.Println("Fingerprinting services...")
	scanner.FingerprintServices(activeHosts)

	// If passive was running, wait for its duration to complete before merging
	if passiveEngine != nil {
		remainingPassiveTime := *passiveDuration - time.Since(startTime)
		if remainingPassiveTime > 0 {
			log.Printf("Waiting for passive collection to complete (%s remaining)...", remainingPassiveTime)
			time.Sleep(remainingPassiveTime)
		}
		log.Println("Step 4/5: Merging passive and active results...")
		activeHosts = merge.MergeResults(activeHosts, passiveEngine.Result)
	}

	// Step 5: Evaluate risk on merged data
	log.Println("Step 5/5: Evaluating risk...")
	for i := range activeHosts {
		scanner.EvaluateRisk(&activeHosts[i])
	}

	scanDuration := time.Since(startTime)

	finalResult := scanner.ScanResult{
		Timestamp:        startTime,
		Subnet:           *subnet,
		Hosts:            activeHosts, // Now contains merged hosts
		ScanDuration:     scanDuration,
		SecurityWarnings: warnings,
	}

	if *outputFile != "" {
		report.SaveJSON(finalResult, *outputFile)
	} else {
		report.RenderConsole(finalResult)
	}

	if *baselineFile != "" {
		baseline, err := report.LoadJSON(*baselineFile)
		if err != nil {
			log.Printf("Warning: could not load baseline report %s: %v", *baselineFile, err)
		} else {
			diff := report.ComputeScanDiff(baseline, finalResult)
			report.RenderDiff(diff)
		}
	}

	log.Println("Scan finished.")
}

func runOSFingerprinting(hosts []scanner.Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(host *scanner.Host) {
			defer wg.Done()
			scanner.GuessOS(host)
		}(&hosts[i])
	}
	wg.Wait()
}
