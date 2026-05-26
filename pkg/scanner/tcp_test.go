package scanner

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanPort_Open(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()

	if !ScanPort(ctx, "127.0.0.1", port, 500*time.Millisecond, 0, nil, nil) {
		t.Fatal("expected open port to be detected")
	}
}

func TestScanPort_Closed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	ctx := context.Background()
	if ScanPort(ctx, "127.0.0.1", port, 500*time.Millisecond, 0, nil, nil) {
		t.Fatal("expected closed port to fail")
	}
}

func TestScanPort_Timeout(t *testing.T) {
	ctx := context.Background()
	var sent atomic.Uint64
	if ScanPort(ctx, "192.0.2.1", 12345, 50*time.Millisecond, 2, nil, &sent) {
		t.Fatal("expected timeout on unroutable address")
	}
	if sent.Load() != 3 {
		t.Fatalf("expected 3 packets sent (1 + 2 retries), got %d", sent.Load())
	}
}

func TestScanPort_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if ScanPort(ctx, "127.0.0.1", 12345, 1*time.Second, 2, nil, nil) {
		t.Fatal("expected false when context cancelled")
	}
}

func TestScanPort_RateLimited(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ticketCh := make(chan struct{}, 1)
	ticketCh <- struct{}{}

	ctx := context.Background()
	start := time.Now()
	if !ScanPort(ctx, "127.0.0.1", port, 500*time.Millisecond, 0, ticketCh, nil) {
		t.Fatal("expected open port")
	}
	// Should be near-instant since token is pre-buffered
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("rate-limited scan took too long")
	}
}

func TestScanPort_NoRetries(t *testing.T) {
	ctx := context.Background()
	if ScanPort(ctx, "192.0.2.1", 1, 10*time.Millisecond, 0, nil, nil) {
		t.Fatal("expected false with retries=0 on dead address")
	}
}

func TestScanPort_NegativeRetries(t *testing.T) {
	ctx := context.Background()
	_ = ScanPort(ctx, "192.0.2.1", 1, 10*time.Millisecond, -5, nil, nil)
}

func TestScanPorts_Sequential(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ports := []int{port, 19999}
	ctx := context.Background()

	open := scanPorts(ctx, "127.0.0.1", ports, 500*time.Millisecond, 0, 1, nil, nil)
	if len(open) != 1 {
		t.Fatalf("expected 1 open port, got %d: %v", len(open), open)
	}
	if open[0] != port {
		t.Fatalf("expected port %d open, got %d", port, open[0])
	}
}

func TestScanPorts_Concurrent(t *testing.T) {
	listeners := make([]net.Listener, 3)
	openPorts := make([]int, 3)
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = ln
		openPorts[i] = ln.Addr().(*net.TCPAddr).Port
		go func(l net.Listener) {
			conn, _ := l.Accept()
			if conn != nil {
				conn.Close()
			}
		}(ln)
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	ports := append([]int{}, openPorts...)
	ports = append(ports, 20001, 20002, 20003)

	ctx := context.Background()
	open := scanPorts(ctx, "127.0.0.1", ports, 500*time.Millisecond, 0, 4, nil, nil)
	if len(open) != 3 {
		t.Fatalf("expected 3 open ports, got %d: %v", len(open), open)
	}
}

func TestScanPorts_Empty(t *testing.T) {
	ctx := context.Background()
	open := scanPorts(ctx, "127.0.0.1", nil, 500*time.Millisecond, 0, 1, nil, nil)
	if open != nil {
		t.Fatal("expected nil for empty ports")
	}
}

func TestScanPorts_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	open := scanPorts(ctx, "127.0.0.1", []int{80, 443}, 1*time.Second, 0, 1, nil, nil)
	if len(open) != 0 {
		t.Fatal("expected no open ports when context cancelled")
	}
}

func TestIsRetryable(t *testing.T) {
	if !isRetryable(&fakeTimeoutError{}) {
		t.Fatal("expected timeout error to be retryable")
	}
}

type fakeTimeoutError struct{}

func (e *fakeTimeoutError) Error() string   { return "timeout" }
func (e *fakeTimeoutError) Timeout() bool   { return true }
func (e *fakeTimeoutError) Temporary() bool { return true }
