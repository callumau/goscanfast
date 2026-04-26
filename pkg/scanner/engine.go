package scanner

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goscanfast/pkg/export"
	"goscanfast/pkg/models"
)

type Engine struct {
	CIDRs       []string
	Exclude     []string
	Ports       []int
	Concurrency int
	PortConcurrency int
	Timeout     time.Duration
	Writer      export.Writer
	SMBWriter   export.SMBWriter
	Reporter    Reporter
	RateLimit   int
	adaptivePC  atomic.Int32
}

type Reporter interface {
	OnStart(total uint64)
	OnHostEnqueued()
	OnHostStart(ip string)
	OnHostDone()
	OnPortOpen(ip string, port int)
	OnResult(result models.Result)
	OnDone()
}

type MultiReporter []Reporter

func (m MultiReporter) OnStart(total uint64) {
	for _, r := range m {
		if r != nil {
			r.OnStart(total)
		}
	}
}

func (m MultiReporter) OnHostEnqueued() {
	for _, r := range m {
		if r != nil {
			r.OnHostEnqueued()
		}
	}
}

func (m MultiReporter) OnHostStart(ip string) {
	for _, r := range m {
		if r != nil {
			r.OnHostStart(ip)
		}
	}
}

func (m MultiReporter) OnHostDone() {
	for _, r := range m {
		if r != nil {
			r.OnHostDone()
		}
	}
}

func (m MultiReporter) OnPortOpen(ip string, port int) {
	for _, r := range m {
		if r != nil {
			r.OnPortOpen(ip, port)
		}
	}
}

func (m MultiReporter) OnResult(result models.Result) {
	for _, r := range m {
		if r != nil {
			r.OnResult(result)
		}
	}
}

func (m MultiReporter) OnDone() {
	for _, r := range m {
		if r != nil {
			r.OnDone()
		}
	}
}

func (e *Engine) Run() error {
	if e.Concurrency <= 0 {
		return errors.New("concurrency must be > 0")
	}
	if e.Writer == nil {
		return errors.New("writer is required")
	}

	ips, err := GenerateIPsMulti(e.CIDRs, e.Exclude)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	maxPC := resolvedPortConcurrency(e.PortConcurrency, len(e.Ports))
	e.adaptivePC.Store(int32(maxPC))

	var totalDials atomic.Uint64
	var timeoutDials atomic.Uint64
	go e.adapt(ctx, maxPC, &totalDials, &timeoutDials)

	if e.Reporter != nil {
		e.Reporter.OnStart(TotalCIDRSize(e.CIDRs))
	}

	jobs := make(chan net.IP, e.Concurrency)
	resultsWriter := make(chan models.Result, e.Concurrency)
	var limiter <-chan time.Time
	var ticker *time.Ticker
	if e.RateLimit > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(e.RateLimit))
		limiter = ticker.C
		defer ticker.Stop()
	}

	// Pre-spawn workers
	var wg sync.WaitGroup
	var smbWG sync.WaitGroup
	var dnsWG sync.WaitGroup

	dnsJobs := make(chan models.Result, e.Concurrency)

	// DNS Workers
	for i := 0; i < e.Concurrency/2+1; i++ {
		dnsWG.Add(1)
		go func() {
			defer dnsWG.Done()
			for res := range dnsJobs {
				res.Hostname = lookupHostname(res.IP)
				if e.Reporter != nil {
					e.Reporter.OnResult(res)
				}
				resultsWriter <- res
				if e.Reporter != nil {
					e.Reporter.OnHostDone()
				}
			}
		}()
	}

	for i := 0; i < e.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for ip := range jobs {
				if limiter != nil {
					<-limiter
				}
				if e.Reporter != nil {
					e.Reporter.OnHostStart(ip.String())
				}
				openPorts := scanPorts(ctx, ip.String(), e.Ports, e.Timeout, int(e.adaptivePC.Load()), &totalDials, &timeoutDials)
				if len(openPorts) == 0 {
					if e.Reporter != nil {
						e.Reporter.OnHostDone()
					}
					continue
				}

				for _, port := range openPorts {
					if e.Reporter != nil {
						e.Reporter.OnPortOpen(ip.String(), port)
					}
				}

				// Check for SMB port 445
				if e.SMBWriter != nil {
					for _, p := range openPorts {
						if p == 445 {
							smbWG.Add(1)
							go func(targetIP string) {
								defer smbWG.Done()
								EnumSMB(ctx, targetIP, "", e.SMBWriter, e.Timeout)
							}(ip.String())
							break
						}
					}
				}

				dnsJobs <- models.Result{
					IP:    ip.String(),
					Ports: openPorts,
				}
			}
		}(i)
	}

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for result := range resultsWriter {
			_ = e.Writer.Write(result)
		}
	}()

	// Feeder
	for ip := range ips {
		jobs <- ip
		if e.Reporter != nil {
			e.Reporter.OnHostEnqueued()
		}
	}
	close(jobs)
	wg.Wait()
	close(dnsJobs)
	dnsWG.Wait()
	close(resultsWriter)
	writerWG.Wait()

	// Wait for SMB tasks to finish
	smbWG.Wait()

	if e.Reporter != nil {
		e.Reporter.OnDone()
	}
	return nil
}

func scanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, portConcurrency int, totalDials, timeoutDials *atomic.Uint64) []int {
	if len(ports) == 0 {
		return nil
	}
	if portConcurrency <= 0 || portConcurrency == 1 {
		open := make([]int, 0)
		for _, port := range ports {
			ok, to := ScanPort(ctx, ip, port, timeout)
			if totalDials != nil {
				totalDials.Add(1)
			}
			if to && timeoutDials != nil {
				timeoutDials.Add(1)
			}
			if ok {
				open = append(open, port)
			}
		}
		sort.Ints(open)
		return open
	}

	if portConcurrency > len(ports) {
		portConcurrency = len(ports)
	}

	open := make([]int, 0, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, portConcurrency)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			ok, to := ScanPort(ctx, ip, p, timeout)
			if totalDials != nil {
				totalDials.Add(1)
			}
			if to && timeoutDials != nil {
				timeoutDials.Add(1)
			}
			if ok {
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Ints(open)
	return open
}

func (e *Engine) adapt(ctx context.Context, maxPC int, totalDials, timeoutDials *atomic.Uint64) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			total := totalDials.Swap(0)
			timeouts := timeoutDials.Swap(0)
			if total < 10 {
				continue
			}
			rate := float64(timeouts) / float64(total)
			current := int(e.adaptivePC.Load())
			if rate > 0.30 {
				newPC := current / 2
				if newPC < 1 {
					newPC = 1
				}
				e.adaptivePC.Store(int32(newPC))
			} else if rate < 0.05 && current < maxPC {
				newPC := current + 1
				if newPC > maxPC {
					newPC = maxPC
				}
				e.adaptivePC.Store(int32(newPC))
			}
		}
	}
}

func lookupHostname(ip string) string {
	addrs, err := net.LookupAddr(ip)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return strings.TrimSuffix(addrs[0], ".")
}

func resolvedPortConcurrency(requested int, portsCount int) int {
	if portsCount <= 0 {
		return 0
	}
	if requested > 0 {
		if requested > portsCount {
			return portsCount
		}
		return requested
	}

	cpu := runtime.GOMAXPROCS(0)
	if cpu <= 0 {
		cpu = 1
	}
	maxByCPU := cpu * 4
	if maxByCPU > 64 {
		maxByCPU = 64
	}
	maxByPorts := portsCount
	if maxByCPU < 1 {
		maxByCPU = 1
	}
	if maxByPorts < 1 {
		maxByPorts = 1
	}
	if maxByCPU > maxByPorts {
		return maxByPorts
	}
	return maxByCPU
}
