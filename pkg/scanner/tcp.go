package scanner

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

func ScanPort(ctx context.Context, ip string, port int, timeout time.Duration, retries int, ppsTicket <-chan struct{}, packetsSent *atomic.Uint64) bool {
	if retries < 0 {
		retries = 0
	}
	attempts := retries + 1
	addr := net.JoinHostPort(ip, formatPort(port))
	for i := 0; i < attempts; i++ {
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
		portCtx, cancel := context.WithTimeout(ctx, timeout)
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(portCtx, "tcp", addr)
		cancel()
		if err == nil {
			_ = conn.Close()
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
		// Only retry on timeout (packet may have been dropped).
		// RST/refused means host is up but port closed — no point retrying.
		if !isTimeoutError(err) {
			return false
		}
		if i < attempts-1 {
			time.Sleep(time.Duration(i+1) * 25 * time.Millisecond)
		}
	}
	return false
}

func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

func formatPort(port int) string {
	return strconv.Itoa(port)
}
