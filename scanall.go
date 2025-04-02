package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pingTimeout     = 500 * time.Millisecond
	portScanTimeout = 1 * time.Second
	scanTimeout     = 2 * time.Second
	workersCount    = 50
	topPortsCount   = 20
)

var topTCPPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
}

type ScanResult struct {
	IP       string
	Hostname string
	Ports    []int
	Mac      string
}

func main() {
	showBanner()
	ipNet := selectNetwork()
	if ipNet == nil {
		return
	}

	results := scanNetwork(ipNet)
	if len(results) == 0 {
		fmt.Println("No active hosts found")
		return
	}

	printResults(results)
	saveToFile(results)
	showMenu(results, ipNet)
}

func showBanner() {
	fmt.Println("====================================")
	fmt.Println("      ADVANCED NETWORK SCANNER      ")
	fmt.Println("====================================")
	fmt.Println()
}

func selectNetwork() *net.IPNet {
	_, currentNet, err := getLocalNetwork()
	if err != nil {
		fmt.Printf("Error getting local network: %v\n", err)
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Current network: %s\n", currentNet)
	fmt.Print("Enter network to scan (e.g. 192.168.1.0/24) or press Enter to use current: ")
	networkInput, _ := reader.ReadString('\n')
	networkInput = strings.TrimSpace(networkInput)

	if networkInput == "" {
		_, ipNet, err := getLocalNetwork()
		if err != nil {
			fmt.Printf("Error getting local network: %v\n", err)
			return nil
		}
		return ipNet
	}

	_, ipNet, err := net.ParseCIDR(networkInput)
	if err != nil {
		fmt.Printf("Invalid network format: %v\n", err)
		return nil
	}
	return ipNet
}

func scanNetwork(ipNet *net.IPNet) []ScanResult {
	fmt.Printf("\nScanning network %s...\n", ipNet)

	var wg sync.WaitGroup
	var mutex sync.Mutex
	results := make([]ScanResult, 0)
	jobs := make(chan string)

	// Progress tracking
	done := make(chan bool)
	go showProgress(done, ipNet)

	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go worker(jobs, &wg, &mutex, &results)
	}

	for ip := range generateIPs(ipNet) {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	done <- true

	return results
}

func worker(jobs <-chan string, wg *sync.WaitGroup, mutex *sync.Mutex, results *[]ScanResult) {
	defer wg.Done()
	for ip := range jobs {
		if isHostActive(ip) {
			result := ScanResult{
				IP:       ip,
				Hostname: resolveHostname(ip),
				Ports:    scanPorts(ip),
				Mac:      getMacAddress(ip),
			}

			mutex.Lock()
			*results = append(*results, result)
			mutex.Unlock()
		}
	}
}

func showProgress(done chan bool, ipNet *net.IPNet) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	total := calculateIPCount(ipNet)
	processed := 0

	for {
		select {
		case <-done:
			fmt.Printf("\rScanning complete! %d/%d IPs processed\n", processed, total)
			return
		case <-ticker.C:
			fmt.Printf("\rScanning in progress... %d/%d IPs processed", processed, total)
			processed += workersCount
		}
	}
}

func calculateIPCount(ipNet *net.IPNet) int {
	ones, bits := ipNet.Mask.Size()
	return 1 << (bits - ones)
}

func isHostActive(ip string) bool {
	return isPingable(ip) || hasOpenPorts(ip)
}

func hasOpenPorts(ip string) bool {
	for _, port := range topTCPPorts[:5] {
		if isPortOpen(ip, port) {
			return true
		}
	}
	return false
}

func scanPorts(ip string) []int {
	var openPorts []int
	var wg sync.WaitGroup
	var mutex sync.Mutex
	portJobs := make(chan int)

	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portJobs {
				if isPortOpen(ip, port) {
					mutex.Lock()
					openPorts = append(openPorts, port)
					mutex.Unlock()
				}
			}
		}()
	}

	for _, port := range topTCPPorts {
		portJobs <- port
	}
	close(portJobs)
	wg.Wait()

	sort.Ints(openPorts)
	return openPorts
}

func isPortOpen(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, portScanTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func getMacAddress(ip string) string {
	switch runtime.GOOS {
	case "linux":
		return getMacAddressLinux(ip)
	case "windows":
		return getMacAddressWindows(ip)
	default:
		return ""
	}
}

func getMacAddressLinux(ip string) string {
	cmd := exec.Command("arp", "-n", ip)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	parts := strings.Fields(string(output))
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func getMacAddressWindows(ip string) string {
	cmd := exec.Command("arp", "-a", ip)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

func printResults(results []ScanResult) {
	fmt.Println("\nScan Results:")
	fmt.Println("IP Address\tMAC Address\tHostname\tOpen Ports")
	fmt.Println("------------------------------------------------")

	for _, res := range results {
		ports := formatPorts(res.Ports)
		fmt.Printf("%-15s\t%-17s\t%-15s\t%s\n", res.IP, res.Mac, res.Hostname, ports)
	}
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return "None"
	}
	if len(ports) > 5 {
		return fmt.Sprintf("%v... (%d total)", ports[:5], len(ports))
	}
	return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
}

func saveToFile(results []ScanResult) {
	file, err := os.Create("network_scan.txt")
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	fmt.Fprintln(file, "Network Scan Results")
	fmt.Fprintln(file, "IP Address\tMAC Address\tHostname\tOpen Ports")
	fmt.Fprintln(file, "------------------------------------------------")

	for _, res := range results {
		ports := formatPorts(res.Ports)
		fmt.Fprintf(file, "%-15s\t%-17s\t%-15s\t%s\n", res.IP, res.Mac, res.Hostname, ports)
	}

	fmt.Println("\nResults saved to network_scan.txt")
}

func showMenu(results []ScanResult, ipNet *net.IPNet) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("\nMenu:\n1. Ping specific host\n2. Scan specific host in detail\n3. Rescan network\n4. Change network\n5. Export results\n6. Exit\nChoose option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			pingOption(reader, results)
		case "2":
			scanOption(reader, results)
		case "3":
			results = scanNetwork(ipNet)
			printResults(results)
			saveToFile(results)
		case "4":
			main()
			return
		case "5":
			exportResults(reader, results)
		case "6":
			os.Exit(0)
		default:
			fmt.Println("Invalid option")
		}
	}
}

func pingOption(reader *bufio.Reader, results []ScanResult) {
	fmt.Print("Enter IP to ping: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)
	if !isValidIP(ip) {
		fmt.Println("Invalid IP address")
		return
	}
	pingHost(ip)
}

func scanOption(reader *bufio.Reader, results []ScanResult) {
	fmt.Print("Enter IP to scan: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)
	if !isValidIP(ip) {
		fmt.Println("Invalid IP address")
		return
	}
	scanSingleHost(ip)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func exportResults(reader *bufio.Reader, results []ScanResult) {
	fmt.Print("Enter filename to export (default: scan_results.csv): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	if filename == "" {
		filename = "scan_results.csv"
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	// CSV header
	fmt.Fprintln(file, "IP Address,MAC Address,Hostname,Open Ports")

	for _, res := range results {
		ports := formatPorts(res.Ports)
		fmt.Fprintf(file, "%s,%s,%s,%s\n", res.IP, res.Mac, res.Hostname, ports)
	}

	fmt.Printf("Results exported to %s\n", filename)
}

func pingHost(ip string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "4", ip)
	case "linux", "darwin":
		cmd = exec.Command("ping", "-c", "4", ip)
	default:
		fmt.Println("Unsupported OS")
		return
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("\nPinging %s...\n", ip)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Ping error: %v\n", err)
	}
}

func scanSingleHost(ip string) {
	fmt.Printf("\nScanning host %s in detail...\n", ip)

	result := ScanResult{
		IP:       ip,
		Hostname: resolveHostname(ip),
		Ports:    scanAllPorts(ip),
		Mac:      getMacAddress(ip),
	}

	fmt.Println("\nDetailed Scan Results:")
	fmt.Println("IP Address:", result.IP)
	fmt.Println("Hostname:", result.Hostname)
	fmt.Println("MAC Address:", result.Mac)
	fmt.Println("Open Ports:", result.Ports)
}

func scanAllPorts(ip string) []int {
	fmt.Println("Scanning all ports (this will take time)...")

	var openPorts []int
	var wg sync.WaitGroup
	var mutex sync.Mutex
	portJobs := make(chan int, 100)

	// Limit workers for full port scan
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portJobs {
				if isPortOpen(ip, port) {
					mutex.Lock()
					openPorts = append(openPorts, port)
					mutex.Unlock()
				}
			}
		}()
	}

	// Send ports to scan
	go func() {
		for port := 1; port <= 65535; port++ {
			portJobs <- port
		}
		close(portJobs)
	}()

	wg.Wait()
	sort.Ints(openPorts)
	return openPorts
}

func generateIPs(ipNet *net.IPNet) <-chan string {
	out := make(chan string)

	go func() {
		defer close(out)
		ip := ipNet.IP.Mask(ipNet.Mask)
		for {
			next := nextIP(ip)
			if !ipNet.Contains(next) {
				break
			}
			ip = next
			out <- ip.String()
		}
	}()

	return out
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}

	return next
}

func isPingable(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(int(pingTimeout.Milliseconds())), ip)
	case "linux", "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(int(pingTimeout.Seconds())), ip)
	default:
		return false
	}

	err := cmd.Run()
	return err == nil
}

func getLocalNetwork() (string, *net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String(), ipNet, nil
			}
		}
	}

	return "", nil, fmt.Errorf("no IPv4 network found")
}