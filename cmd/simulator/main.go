package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	attackType := flag.String("attack", "imds-ssrf", "Attack type to simulate: imds-ssrf, s3-exfiltration, rate-burst")
	targetIP := flag.String("target", "169.254.169.254", "Target destination IP")
	burstCount := flag.Int("count", 15, "Connection count")
	flag.Parse()

	log.Printf("Starting attack simulation: %s (Target: %s, Count: %d)", *attackType, *targetIP, *burstCount)

	switch *attackType {
	case "imds-ssrf":
		simulateIMDS(*targetIP, *burstCount)
	case "s3-exfiltration":
		simulateS3Exfiltration("54.239.28.85", *burstCount)
	case "rate-burst":
		simulateRateBurst(*targetIP, *burstCount)
	default:
		log.Fatalf("Unknown attack scenario: %s", *attackType)
	}

	log.Printf("Attack simulation %s finished.", *attackType)
}

func simulateIMDS(ip string, count int) {
	fmt.Printf("[SIMULATOR] Launching simulated AWS IMDSv2 metadata query to %s:80...\n", ip)
	for i := 1; i <= count; i++ {
		fmt.Printf("  -> [%d/%d] Attempting socket connect to %s:80 (IMDS Token Scrape)\n", i, count, ip)
		// Non-blocking connect probe
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), 100*time.Millisecond)
		if err == nil && conn != nil {
			_ = conn.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func simulateS3Exfiltration(ip string, count int) {
	fmt.Printf("[SIMULATOR] Launching anomalous public S3 burst to %s:443...\n", ip)
	for i := 1; i <= count; i++ {
		fmt.Printf("  -> [%d/%d] Emitting data chunk to AWS S3 storage range\n", i, count)
		time.Sleep(30 * time.Millisecond)
	}
}

func simulateRateBurst(ip string, count int) {
	fmt.Printf("[SIMULATOR] Launching high-frequency egress connection burst to %s...\n", ip)
	for i := 1; i <= count; i++ {
		time.Sleep(10 * time.Millisecond)
	}
}
