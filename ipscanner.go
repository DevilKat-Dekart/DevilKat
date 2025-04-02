package main

import (
	"bufio"
	"bytes"
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
	pingTimeout  = 500 * time.Millisecond
	scanTimeout  = 2 * time.Second
	workersCount = 100
)

func main() {
	fmt.Println("IP Scanner with Ping Utility")
	fmt.Println("----------------------------")

	// Получаем локальный IP и маску подсети
	ip, ipNet, err := getLocalNetwork()
	if err != nil {
		fmt.Printf("Error getting local network: %v\n", err)
		return
	}

	fmt.Printf("Local IP: %s\n", ip)
	fmt.Printf("Network: %s\n", ipNet)

	// Сканируем сеть
	activeIPs := scanNetwork(ipNet)

	if len(activeIPs) == 0 {
		fmt.Println("No active IP addresses found")
		return
	}

	// Сортируем IP адреса
	sort.Slice(activeIPs, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(activeIPs[i]).To4(), net.ParseIP(activeIPs[j]).To4()) < 0
	})

	fmt.Println("\nActive IP addresses:")
	for i, ip := range activeIPs {
		fmt.Printf("%3d: %s\n", i+1, ip)
	}

	// Предлагаем выполнить ping
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nEnter IP address to ping (or 'q' to quit): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "q" || input == "" {
		return
	}

	// Проверяем, что введенный IP есть в списке
	found := false
	for _, ip := range activeIPs {
		if ip == input {
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("IP %s not found in active list\n", input)
		return
	}

	fmt.Printf("Pinging %s...\n", input)
	pingIP(input)
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

func scanNetwork(ipNet *net.IPNet) []string {
	fmt.Printf("\nScanning network %s...\n", ipNet)

	var wg sync.WaitGroup
	var mutex sync.Mutex
	activeIPs := make([]string, 0)

	// Создаем канал для задач
	jobs := make(chan string)

	// Запускаем workers
	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if isIPActive(ip) {
					mutex.Lock()
					activeIPs = append(activeIPs, ip)
					mutex.Unlock()
				}
			}
		}()
	}

	// Отправляем задачи в канал
	for ip := range generateIPs(ipNet) {
		jobs <- ip
	}
	close(jobs)

	wg.Wait()

	return activeIPs
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

func isIPActive(ip string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), scanTimeout)
	if err == nil {
		conn.Close()
		return true
	}

	// Если порт 80 закрыт, пробуем ping
	if isPingable(ip) {
		return true
	}

	return false
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

func pingIP(ip string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-t", ip)
	case "linux", "darwin":
		cmd = exec.Command("ping", ip)
	default:
		fmt.Println("Unsupported OS")
		return
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Ping error: %v\n", err)
	}
}