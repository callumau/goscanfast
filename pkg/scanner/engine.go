package scanner

import (
	"context"
	"errors"
	"net"
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
	Timeout     time.Duration
	Writer      export.Writer
	Reporter    Reporter
	RateLimit   int
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
	results := make(chan models.Result, e.Concurrency)
	var limiter <-chan time.Time
	var ticker *time.Ticker
	if e.RateLimit > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(e.RateLimit))
		limiter = ticker.C
		defer ticker.Stop()
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
				openPorts := scanPorts(ctx, ip.String(), e.Ports, e.Timeout)
				if len(openPorts) == 0 {
					if e.Reporter != nil {
						e.Reporter.OnHostDone()
					}
					continue
				}
				hostname := lookupHostname(ip.String())
				result := models.Result{
					IP:       ip.String(),
					Hostname: hostname,
					Ports:    openPorts,
				}
				if e.Reporter != nil {
					e.Reporter.OnResult(result)
				}
				for _, port := range openPorts {
					if e.Reporter != nil {
						e.Reporter.OnPortOpen(result.IP, port)
					}
				}
				results <- result
				if e.Reporter != nil {
					e.Reporter.OnHostDone()
				}
			}
		}(i)
	}

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for result := range results {
			_ = e.Writer.Write(result)
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
	close(results)
	writerWG.Wait()
	if e.Reporter != nil {
		e.Reporter.OnDone()
	}
	return nil
}

func scanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	open := make([]int, 0)
	for _, port := range ports {
		portCtx, cancel := context.WithTimeout(ctx, timeout)
		if ScanPort(portCtx, ip, port, timeout) {
			open = append(open, port)
		}
		cancel()
	}
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
