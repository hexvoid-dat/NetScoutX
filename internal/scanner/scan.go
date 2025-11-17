package scanner

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// Liczba workerów do skanowania portów
	numWorkers = 100
	// Timeout dla połączenia z portem
	connectTimeout = 1 * time.Second
)

// Skanowany port i host
type scanTask struct {
	host *Host
	port int
}

// Wynik skanowania portu
type scanResult struct {
	port Port
	host *Host
}

// PortScanner skanuje zdefiniowaną listę portów na podanych hostach.
func PortScanner(hosts []Host) {
	tasks := make(chan scanTask, numWorkers)
	results := make(chan scanResult)
	var wg sync.WaitGroup

	// Uruchomienie workerów
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, results)
	}

	// Zasilenie kolejki zadań
	go func() {
		for i := range hosts {
			for _, port := range commonPorts() {
				tasks <- scanTask{host: &hosts[i], port: port}
			}
		}
		close(tasks)
	}()

	// Czekanie na zakończenie wszystkich workerów i zamknięcie kanału wyników
	go func() {
		wg.Wait()
		close(results)
	}()

	// Zbieranie wyników
	for result := range results {
		if result.port.State == StateOpen {
			result.host.OpenPorts = append(result.host.OpenPorts, result.port)
		}
	}

	// Sortowanie otwartych portów dla każdego hosta
	for i := range hosts {
		sort.Slice(hosts[i].OpenPorts, func(j, k int) bool {
			return hosts[i].OpenPorts[j].Number < hosts[i].OpenPorts[k].Number
		})
	}
}

func worker(wg *sync.WaitGroup, tasks <-chan scanTask, results chan<- scanResult) {
	defer wg.Done()
	for task := range tasks {
		address := fmt.Sprintf("%s:%d", task.host.IP, task.port)
		conn, err := net.DialTimeout("tcp", address, connectTimeout)

		portResult := Port{
			Number:   task.port,
			Protocol: "tcp",
		}

		if err != nil {
			portResult.State = StateClosed
		} else {
			conn.Close()
			portResult.State = StateOpen
			// Prosty banner grabbing
			portResult.Banner = grabBanner(address)

			// Analiza podatności na podstawie baneru
			portResult.Vulnerabilities = CheckBannerForVulnerabilities(portResult.Banner)
		}
		results <- scanResult{port: portResult, host: task.host}
	}
}

func grabBanner(address string) string {
	conn, err := net.DialTimeout("tcp", address, connectTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	// Ustawienie deadline'u na odczyt
	_ = conn.SetReadDeadline(time.Now().Add(connectTimeout))
	
	// Dla portu 80 (HTTP), wyślij żądanie HEAD
	if strings.Contains(address, ":80") {
		_, err = conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: " + strings.Split(address, ":")[0] + "\r\n\r\n"))
		if err != nil {
			return ""
		}
	}
	
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}

// commonPorts zwraca listę najczęściej skanowanych portów.
func commonPorts() []int {
	// W wersji produkcyjnej można to wczytywać z pliku konfiguracyjnego.
	return []int{
		20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
		993, 995, 1723, 3306, 3389, 5900, 8080,
	}
}
