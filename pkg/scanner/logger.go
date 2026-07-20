package scanner

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"goscanfast/pkg/models"
)

// ActivityLogger implements Reporter to write timestamped progress and
// summary information to a log file.
type ActivityLogger struct {
	filePath    string
	file        *os.File
	mu          sync.Mutex
	startTime   time.Time
	total       uint64
	completed   uint64
	found       uint64
	alive       uint64
	cidrs       []string
	lastLogTime time.Time
}

// NewActivityLogger creates an ActivityLogger that appends to path.
func NewActivityLogger(path string, cidrs []string) (*ActivityLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &ActivityLogger{
		filePath:    path,
		file:        f,
		cidrs:       cidrs,
		lastLogTime: time.Time{}, // Initialize to zero time so first check passes
	}, nil
}

func (l *ActivityLogger) log(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(l.file, "[%s] %s\n", timestamp, msg)
}

func (l *ActivityLogger) OnStart(total uint64) {
	l.mu.Lock()
	l.startTime = time.Now()
	l.mu.Unlock()
	atomic.StoreUint64(&l.total, total)
	l.log(fmt.Sprintf("Scan started for range(s): %v. Total targets: %d", l.cidrs, total))
}

func (l *ActivityLogger) OnHostEnqueued() {}

func (l *ActivityLogger) OnHostStart(ip string) {}

func (l *ActivityLogger) OnHostDone() {
	newVal := atomic.AddUint64(&l.completed, 1)

	if newVal%100 == 0 {
		l.mu.Lock()
		shouldLog := time.Since(l.lastLogTime) >= 30*time.Second
		if shouldLog {
			l.lastLogTime = time.Now()
		}
		l.mu.Unlock()

		if shouldLog {
			l.reportProgress(newVal)
		}
	}
}

func (l *ActivityLogger) reportProgress(completed uint64) {
	l.mu.Lock()
	elapsed := time.Since(l.startTime)
	l.mu.Unlock()
	total := atomic.LoadUint64(&l.total)
	rate := float64(completed) / elapsed.Seconds()

	var eta string
	if total > completed && rate > 0 {
		remaining := float64(total - completed)
		seconds := remaining / rate
		eta = time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
	} else {
		eta = "N/A"
	}

	percent := 0.0
	if total > 0 {
		percent = (float64(completed) / float64(total)) * 100
	}

	l.log(fmt.Sprintf("Progress: %d/%d (%.2f%%) | Rate: %.1f hosts/s | ETA: %s",
		completed, total, percent, rate, eta))
}

func (l *ActivityLogger) OnPortOpen(ip string, port int) {
	atomic.AddUint64(&l.found, 1)
}

func (l *ActivityLogger) OnResult(result models.Result) {
	atomic.AddUint64(&l.alive, 1)
}

func (l *ActivityLogger) OnDone() {
	elapsed := time.Since(l.startTime)
	completed := atomic.LoadUint64(&l.completed)
	alive := atomic.LoadUint64(&l.alive)
	found := atomic.LoadUint64(&l.found)

	l.log("Scan finished.")
	l.log(fmt.Sprintf("Summary: Duration: %s | Total: %d | Alive: %d | Ports Found: %d",
		elapsed.Round(time.Second), completed, alive, found))
}

func (l *ActivityLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
