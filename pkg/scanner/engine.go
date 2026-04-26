package scanner

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
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
	Retries     int
	ResolveDNS  bool
	AdminConcurrency int
	SMBConcurrency   int
	Writer      export.Writer
	SMBWriter   export.SMBWriter
	Reporter    Reporter
	RateLimit   int
	PortRateLimit int
	PortInflightLimit int
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

	if e.Reporter != nil {
		e.Reporter.OnStart(TotalCIDRSize(e.CIDRs))
	}

	jobs := make(chan net.IP, e.Concurrency)
	resultsWriter := make(chan models.Result, e.Concurrency)
	adminQueueSize := e.Concurrency * 4
	if adminQueueSize < e.Concurrency {
		adminQueueSize = e.Concurrency
	}
	adminJobs := make(chan models.Result, adminQueueSize)
	var limiter <-chan time.Time
	var ticker *time.Ticker
	if e.RateLimit > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(e.RateLimit))
		limiter = ticker.C
		defer ticker.Stop()
	}
	var portLimiter <-chan time.Time
	var portTicker *time.Ticker
	if e.PortRateLimit > 0 {
		portTicker = time.NewTicker(time.Second / time.Duration(e.PortRateLimit))
		portLimiter = portTicker.C
		defer portTicker.Stop()
	}
	var portInflight chan struct{}
	if e.PortInflightLimit > 0 {
		portInflight = make(chan struct{}, e.PortInflightLimit)
	}

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for result := range resultsWriter {
			_ = e.Writer.Write(result)
		}
	}()

	var smbWG sync.WaitGroup
	var smbJobs chan string
	if e.SMBWriter != nil {
		smbJobs = make(chan string, adminQueueSize)
		smbConcurrency := resolvedSMBConcurrency(e.SMBConcurrency, resolvedAdminConcurrency(e.AdminConcurrency, e.Concurrency))
		for i := 0; i < smbConcurrency; i++ {
			smbWG.Add(1)
			go func() {
				defer smbWG.Done()
				for targetIP := range smbJobs {
					EnumSMB(ctx, targetIP, "", e.SMBWriter, e.Timeout)
				}
			}()
		}
	}

	var adminWG sync.WaitGroup
	adminConcurrency := resolvedAdminConcurrency(e.AdminConcurrency, e.Concurrency)
	for i := 0; i < adminConcurrency; i++ {
		adminWG.Add(1)
		go func() {
			defer adminWG.Done()
			for res := range adminJobs {
				if e.ResolveDNS {
					res.Hostname = lookupHostname(res.IP)
				}
				if smbJobs != nil && hasPort(res.Ports, 445) {
					smbJobs <- res.IP
				}
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

	var wg sync.WaitGroup
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
				openPorts := scanPorts(ctx, ip.String(), e.Ports, e.Timeout, e.Retries, resolvedPortConcurrency(e.PortConcurrency, len(e.Ports)), portLimiter, portInflight)
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

				adminJobs <- models.Result{
					IP:    ip.String(),
					Ports: openPorts,
				}
			}
		}(i)
	}

	for ip := range ips {
		jobs <- ip
		if e.Reporter != nil {
			e.Reporter.OnHostEnqueued()
		}
	}
	close(jobs)
	wg.Wait()
	close(adminJobs)
	adminWG.Wait()
	if smbJobs != nil {
		close(smbJobs)
		smbWG.Wait()
	}
	close(resultsWriter)
	writerWG.Wait()

	if e.Reporter != nil {
		e.Reporter.OnDone()
	}
	return nil
}

func scanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, retries int, portConcurrency int, limiter <-chan time.Time, inflight chan struct{}) []int {
	if len(ports) == 0 {
		return nil
	}
	if portConcurrency <= 0 || portConcurrency == 1 {
		open := make([]int, 0)
		for _, port := range ports {
			if limiter != nil {
				<-limiter
			}
			if inflight != nil {
				inflight <- struct{}{}
			}
			if ScanPort(ctx, ip, port, timeout, retries) {
				open = append(open, port)
			}
			if inflight != nil {
				<-inflight
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
			if limiter != nil {
				<-limiter
			}
			if inflight != nil {
				inflight <- struct{}{}
				defer func() { <-inflight }()
			}

			if ScanPort(ctx, ip, p, timeout, retries) {
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

func resolvedAdminConcurrency(requested int, scanConcurrency int) int {
	if requested > 0 {
		return requested
	}
	if scanConcurrency < 2 {
		return 1
	}
	return scanConcurrency/2 + 1
}

func resolvedSMBConcurrency(requested int, adminConcurrency int) int {
	if requested > 0 {
		return requested
	}
	if adminConcurrency < 1 {
		return 1
	}
	if adminConcurrency > 8 {
		return 8
	}
	return adminConcurrency
}

func hasPort(ports []int, target int) bool {
	for _, p := range ports {
		if p == target {
			return true
		}
	}
	return false
}
