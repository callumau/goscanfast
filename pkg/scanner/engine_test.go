package scanner

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"goscanfast/pkg/models"
)

type mockWriter struct {
	results []models.Result
}

func (w *mockWriter) Write(r models.Result) error {
	w.results = append(w.results, r)
	return nil
}

func (w *mockWriter) Close() error { return nil }

// mockReporter counters are atomic: the engine calls Reporter methods
// concurrently from all worker goroutines.
type mockReporter struct {
	startCalls     atomic.Int64
	hostEnqueued   atomic.Int64
	hostStartCalls atomic.Int64
	hostDoneCalls  atomic.Int64
	portOpenCalls  atomic.Int64
	resultCalls    atomic.Int64
	doneCalls      atomic.Int64
}

func (r *mockReporter) OnStart(total uint64)        { r.startCalls.Add(1) }
func (r *mockReporter) OnHostEnqueued()             { r.hostEnqueued.Add(1) }
func (r *mockReporter) OnHostStart(ip string)       { r.hostStartCalls.Add(1) }
func (r *mockReporter) OnHostDone()                 { r.hostDoneCalls.Add(1) }
func (r *mockReporter) OnPortOpen(ip string, p int) { r.portOpenCalls.Add(1) }
func (r *mockReporter) OnResult(res models.Result)  { r.resultCalls.Add(1) }
func (r *mockReporter) OnDone()                     { r.doneCalls.Add(1) }

func TestEngine_Run_SmallRange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	writer := &mockWriter{}
	reporter := &mockReporter{}

	engine := &Engine{
		CIDRs:       []string{"127.0.0.1/32"},
		Ports:       []int{port},
		Concurrency: 4,
		Timeout:     500 * time.Millisecond,
		Writer:      writer,
		Reporter:    reporter,
	}

	ctx := context.Background()
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(writer.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(writer.results))
	}
	if writer.results[0].IP != "127.0.0.1" {
		t.Fatalf("expected IP 127.0.0.1, got %s", writer.results[0].IP)
	}
	if len(writer.results[0].Ports) != 1 || writer.results[0].Ports[0] != port {
		t.Fatalf("expected port %d, got %v", port, writer.results[0].Ports)
	}

	if reporter.startCalls.Load() != 1 {
		t.Fatalf("expected 1 OnStart call, got %d", reporter.startCalls.Load())
	}
	if reporter.doneCalls.Load() != 1 {
		t.Fatalf("expected 1 OnDone call, got %d", reporter.doneCalls.Load())
	}
}

func TestEngine_Run_ContextCancel(t *testing.T) {
	writer := &mockWriter{}
	reporter := &mockReporter{}

	engine := &Engine{
		CIDRs:       []string{"10.0.0.0/16"},
		Ports:       []int{80, 443},
		Concurrency: 4,
		Timeout:     10 * time.Millisecond,
		Writer:      writer,
		Reporter:    reporter,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := engine.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if reporter.doneCalls.Load() != 1 {
		t.Fatalf("expected 1 OnDone call, got %d", reporter.doneCalls.Load())
	}
}

func TestEngine_Run_ZeroConcurrency(t *testing.T) {
	engine := &Engine{
		CIDRs:       []string{"127.0.0.1/32"},
		Concurrency: 0,
		Writer:      &mockWriter{},
	}
	if err := engine.Run(context.Background()); err == nil {
		t.Fatal("expected error for zero concurrency")
	}
}

func TestEngine_Run_NilWriter(t *testing.T) {
	engine := &Engine{
		CIDRs:       []string{"127.0.0.1/32"},
		Concurrency: 4,
	}
	if err := engine.Run(context.Background()); err == nil {
		t.Fatal("expected error for nil writer")
	}
}

func TestEngine_Run_TooLarge(t *testing.T) {
	engine := &Engine{
		CIDRs:       []string{"0.0.0.0/0"},
		Concurrency: 4,
		Writer:      &mockWriter{},
	}
	if err := engine.Run(context.Background()); err == nil {
		t.Fatal("expected error for too-large range")
	}
}

func TestEngine_Run_RateLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	writer := &mockWriter{}
	var sent atomic.Uint64

	engine := &Engine{
		CIDRs:       []string{"127.0.0.1/32"},
		Ports:       []int{port},
		Concurrency: 4,
		Timeout:     500 * time.Millisecond,
		Writer:      writer,
		PPS:         100,
		PacketsSent: &sent,
	}

	ctx := context.Background()
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(writer.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(writer.results))
	}
}

func TestEngine_Run_Exclude(t *testing.T) {
	writer := &mockWriter{}

	engine := &Engine{
		CIDRs:       []string{"127.0.0.0/30"},
		Exclude:     []string{"127.0.0.0/31"},
		Ports:       []int{80},
		Concurrency: 4,
		Timeout:     50 * time.Millisecond,
		Writer:      writer,
	}

	ctx := context.Background()
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range writer.results {
		if r.IP == "127.0.0.0" || r.IP == "127.0.0.1" {
			t.Fatalf("excluded IP %s was scanned", r.IP)
		}
	}
}
