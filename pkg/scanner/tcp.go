package scanner

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// ScanPort performs a TCP connect scan on a single port with configurable
// retries and rate limiting. Returns true if the connection succeeds.
func ScanPort(ctx context.Context, ip string, port int, timeout time.Duration, retries int, ppsTicket <-chan struct{}, packetsSent *atomic.Uint64) bool {
	if retries < 0 {
		retries = 0
	}
	attempts := retries + 1
	addr := net.JoinHostPort(ip, formatPort(port))
	dialer := &net.Dialer{Timeout: timeout}
	for i := range attempts {
		if ppsTicket != nil {
			select {
			case <-ppsTicket:
			case <-ctx.Done():
				return false
			}
		}
		if packetsSent != nil {
			packetsSent.Add(1)
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
		if !isRetryable(err) {
			return false
		}
		if i < attempts-1 {
			select {
			case <-time.After(time.Duration(i+1) * 25 * time.Millisecond):
			case <-ctx.Done():
				return false
			}
		}
	}
	return false
}

func isRetryable(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Transient errors only. EHOSTUNREACH/ENETUNREACH are
		// deterministic routing failures: retrying them never
		// succeeds and only burns PPS budget.
		switch {
		case errors.Is(opErr.Err, syscall.ECONNRESET),
			errors.Is(opErr.Err, syscall.ECONNABORTED),
			errors.Is(opErr.Err, syscall.EPIPE):
			return true
		}
	}
	return false
}

func formatPort(port int) string {
	return strconv.Itoa(port)
}
