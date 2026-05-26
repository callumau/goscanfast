package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goscanfast/pkg/export"
	"goscanfast/pkg/models"
)

// Engine orchestrates the full scan pipeline: IP generation, port scanning,
// DNS resolution, result writing, SMB enumeration, and progress reporting.
type Engine struct {
	CIDRs           []string
	Exclude         []string
	Ports           []int
	Concurrency     int
	PortConcurrency int
	Timeout         time.Duration
	Retries         int
	Writer          export.Writer
	SMBWriter       export.SMBWriter
	Reporter        Reporter
	PPS             int
	PacketsSent     *atomic.Uint64
}

// Reporter receives lifecycle events from the scan engine for progress
// reporting, logging, and UI updates.
type Reporter interface {
	OnStart(total uint64)
	OnHostEnqueued()
	OnHostStart(ip string)
	OnHostDone()
	OnPortOpen(ip string, port int)
	OnResult(result models.Result)
	OnDone()
}

// MultiReporter fans out Reporter calls to multiple implementations.
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

// Run executes the scan pipeline. ctx controls the lifetime of all
// scanning, DNS, SMB, and rate-limiting goroutines.
func (e *Engine) Run(ctx context.Context) error {
	if e.Concurrency <= 0 {
		return errors.New("concurrency must be > 0")
	}
	if e.Writer == nil {
		return errors.New("writer is required")
	}

	totalSize := TotalCIDRSize(e.CIDRs)
	if totalSize > 1<<24 {
		return fmt.Errorf("target range too large (%d hosts, max %d); split into smaller ranges", totalSize, 1<<24)
	}

	ips, err := GenerateIPsMulti(e.CIDRs, e.Exclude)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if e.Reporter != nil {
		e.Reporter.OnStart(TotalCIDRSize(e.CIDRs))
	}

	jobs := make(chan net.IP, e.Concurrency)
	resultsWriter := make(chan models.Result, e.Concurrency)
	var ppsTicket <-chan struct{}
	if e.PPS > 0 {
		tickCh := make(chan struct{}, e.PPS)
		const maxDeficitFactor = 10
		go func() {
			start := time.Now()
			var issued int64
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					elapsed := time.Since(start)
					target := int64(elapsed.Seconds() * float64(e.PPS))
					deficit := target - issued
					maxDeficit := int64(e.PPS * maxDeficitFactor)
					if deficit > maxDeficit {
						deficit = maxDeficit
						issued = target - maxDeficit
					}
					for i := int64(0); i < deficit; i++ {
						select {
						case tickCh <- struct{}{}:
							issued++
						default:
							issued++
						}
					}
				}
			}
		}()
		ppsTicket = tickCh
	}

	var wg sync.WaitGroup
	var smbWG sync.WaitGroup
	var dnsWG sync.WaitGroup

	dnsJobs := make(chan models.Result, e.Concurrency*2)

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
				if e.Reporter != nil {
					e.Reporter.OnHostStart(ip.String())
				}
				openPorts := scanPorts(ctx, ip.String(), e.Ports, e.Timeout, e.Retries, resolvedPortConcurrency(e.PortConcurrency, len(e.Ports)), ppsTicket, e.PacketsSent)
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
			if err := e.Writer.Write(result); err != nil {
				log.Printf("write error for %s: %v", result.IP, err)
			}
		}
	}()

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

	smbWG.Wait()

	if e.Reporter != nil {
		e.Reporter.OnDone()
	}
	return nil
}

func scanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, retries int, portConcurrency int, ppsTicket <-chan struct{}, packetsSent *atomic.Uint64) []int {
	if len(ports) == 0 {
		return nil
	}
	if portConcurrency <= 0 || portConcurrency == 1 {
		open := make([]int, 0)
		for _, port := range ports {
			if ScanPort(ctx, ip, port, timeout, retries, ppsTicket, packetsSent) {
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

			if ScanPort(ctx, ip, p, timeout, retries, ppsTicket, packetsSent) {
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
	const defaultMax = 64
	if portsCount <= 0 {
		return 0
	}
	if requested > 0 {
		if requested > portsCount {
			return portsCount
		}
		return requested
	}
	if portsCount > defaultMax {
		return defaultMax
	}
	return portsCount
}
