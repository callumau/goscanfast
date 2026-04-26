package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func BenchmarkSyntheticScan16(b *testing.B) {
	ports := []int{21, 22, 23, 25, 80, 135, 139, 161, 389, 443, 445, 636, 3389, 5985, 5986, 8080}
	timeout := 10 * time.Microsecond
	for i := 0; i < b.N; i++ {
		ips, err := GenerateIPs("10.0.0.0/16", nil)
		if err != nil {
			b.Fatal(err)
		}
		ctx := context.Background()
		for ip := range ips {
			_ = syntheticScan(ctx, ip, ports, timeout)
		}
	}
}

func BenchmarkRealisticScan24(b *testing.B) {
	listeners, openPorts := startTestListeners(b, 2)
	defer closeListeners(listeners)

	ports := append([]int{}, openPorts...)
	ports = append(ports, 40001, 40003, 40005, 40007, 40009, 40011, 40013, 40015)
	if len(ports) < 10 {
		b.Fatal("expected at least 10 ports")
	}

	timeout := 2 * time.Millisecond
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ips, err := GenerateIPs("10.0.0.0/24", nil)
		if err != nil {
			b.Fatal(err)
		}
		for range ips {
			_ = scanPorts(ctx, "127.0.0.1", ports, timeout, 1, nil)
		}
	}
	b.StopTimer()
	if b.N > 0 {
		secondsPerRun := b.Elapsed().Seconds() / float64(b.N)
		estimate := secondsPerRun * 65536
		b.ReportMetric(estimate, "sec_per_/8")
	}
}

func syntheticScan(ctx context.Context, ip net.IP, ports []int, timeout time.Duration) []int {
	open := make([]int, 0)
	for _, port := range ports {
		portCtx, cancel := context.WithTimeout(ctx, timeout)
		_ = portCtx
		cancel()
		if port%2 == 0 {
			open = append(open, port)
		}
	}
	return open
}

func startTestListeners(b *testing.B, count int) ([]net.Listener, []int) {
	listeners := make([]net.Listener, 0, count)
	ports := make([]int, 0, count)
	for i := 0; i < count; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			closeListeners(listeners)
			b.Fatalf("listener error: %v", err)
		}
		listeners = append(listeners, ln)
		addr := ln.Addr().(*net.TCPAddr)
		ports = append(ports, addr.Port)
	}
	return listeners, ports
}

func closeListeners(listeners []net.Listener) {
	for _, ln := range listeners {
		_ = ln.Close()
	}
}
