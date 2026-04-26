package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"goscanfast/pkg/models"
)

type testWriter struct {
	mu      sync.Mutex
	results []models.Result
}

func (w *testWriter) Write(r models.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, r)
	return nil
}

func (w *testWriter) Close() error { return nil }

func (w *testWriter) sorted() []models.Result {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]models.Result, len(w.results))
	copy(out, w.results)
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		if len(out[i].Ports) != len(out[j].Ports) {
			return len(out[i].Ports) < len(out[j].Ports)
		}
		for k := range out[i].Ports {
			if out[i].Ports[k] != out[j].Ports[k] {
				return out[i].Ports[k] < out[j].Ports[k]
			}
		}
		return false
	})
	return out
}

func TestConsistencyHighConcurrency(t *testing.T) {
	openCount := 8
	listeners := make([]net.Listener, 0, openCount)
	openPorts := make([]int, 0, openCount)
	for i := 0; i < openCount; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			t.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)
		openPorts = append(openPorts, ln.Addr().(*net.TCPAddr).Port)
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}(ln)
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	ports := append([]int{}, openPorts...)
	ports = append(ports, 40001, 40003, 40005, 40007, 40009, 40011, 40013, 40015, 40017, 40019, 40021, 40023)

	cidr := "127.0.0.0/24"

	var runs [][]models.Result
	for i := 0; i < 5; i++ {
		writer := &testWriter{}
		engine := Engine{
			CIDRs:           []string{cidr},
			Ports:           ports,
			Concurrency:     1024,
			PortConcurrency: 0,
			Timeout:         5 * time.Second,
			Writer:          writer,
			Reporter:        nil,
		}
		if err := engine.Run(); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		runs = append(runs, writer.sorted())
	}

	for i := 1; i < len(runs); i++ {
		if len(runs[i]) != len(runs[0]) {
			t.Fatalf("run %d result count %d != run 0 count %d", i, len(runs[i]), len(runs[0]))
		}
		for j := range runs[0] {
			if runs[i][j].IP != runs[0][j].IP {
				t.Fatalf("run %d result %d IP mismatch: %s vs %s", i, j, runs[i][j].IP, runs[0][j].IP)
			}
			if len(runs[i][j].Ports) != len(runs[0][j].Ports) {
				t.Fatalf("run %d result %d port count mismatch: %v vs %v", i, j, runs[i][j].Ports, runs[0][j].Ports)
			}
			for k := range runs[0][j].Ports {
				if runs[i][j].Ports[k] != runs[0][j].Ports[k] {
					t.Fatalf("run %d result %d port mismatch: %v vs %v", i, j, runs[i][j].Ports, runs[0][j].Ports)
				}
			}
		}
	}
}

type mockNetError struct {
	msg     string
	timeout bool
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return true }

type fakeConn struct{}

func (c *fakeConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c *fakeConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestConsistencyWithMockTimeouts(t *testing.T) {
	oldDial := dialContext
	defer func() { dialContext = oldDial }()

	openPorts := map[int]bool{22: true, 80: true, 443: true, 8080: true}
	attempts := make(map[string]int)
	var mu sync.Mutex

	dialContext = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, _ := strconv.Atoi(portStr)

		if !openPorts[port] {
			return nil, &mockNetError{msg: "connection refused", timeout: false}
		}

		key := fmt.Sprintf("%s:%d", host, port)
		mu.Lock()
		count := attempts[key]
		attempts[key] = count + 1
		mu.Unlock()

		if count == 0 {
			return nil, &mockNetError{msg: "i/o timeout", timeout: true}
		}
		return &fakeConn{}, nil
	}

	cidr := "127.0.0.0/26"
	ports := []int{21, 22, 23, 25, 80, 135, 139, 443, 445, 8080}

	var runs [][]models.Result
	for i := 0; i < 5; i++ {
		mu.Lock()
		attempts = make(map[string]int)
		mu.Unlock()

		writer := &testWriter{}
		engine := Engine{
			CIDRs:           []string{cidr},
			Ports:           ports,
			Concurrency:     1024,
			PortConcurrency: 0,
			Timeout:         5 * time.Second,
			Writer:          writer,
			Reporter:        nil,
		}
		if err := engine.Run(); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		runs = append(runs, writer.sorted())
	}

	expectedHosts := 64
	expectedPorts := 4

	for i, run := range runs {
		if len(run) != expectedHosts {
			t.Fatalf("run %d: expected %d hosts, got %d", i, expectedHosts, len(run))
		}
		for _, r := range run {
			if len(r.Ports) != expectedPorts {
				t.Fatalf("run %d host %s: expected %d ports, got %v", i, r.IP, expectedPorts, r.Ports)
			}
		}
	}

	for i := 1; i < len(runs); i++ {
		if len(runs[i]) != len(runs[0]) {
			t.Fatalf("run %d result count %d != run 0 count %d", i, len(runs[i]), len(runs[0]))
		}
		for j := range runs[0] {
			if runs[i][j].IP != runs[0][j].IP {
				t.Fatalf("run %d result %d IP mismatch: %s vs %s", i, j, runs[i][j].IP, runs[0][j].IP)
			}
			if len(runs[i][j].Ports) != len(runs[0][j].Ports) {
				t.Fatalf("run %d result %d port count mismatch: %v vs %v", i, j, runs[i][j].Ports, runs[0][j].Ports)
			}
			for k := range runs[0][j].Ports {
				if runs[i][j].Ports[k] != runs[0][j].Ports[k] {
					t.Fatalf("run %d result %d port mismatch: %v vs %v", i, j, runs[i][j].Ports, runs[0][j].Ports)
				}
			}
		}
	}
}
