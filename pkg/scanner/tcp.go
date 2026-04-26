package scanner

import (
	"context"
	"net"
	"strconv"
	"time"
)

func ScanPort(ctx context.Context, ip string, port int, timeout time.Duration, retries int) bool {
	if retries < 0 {
		retries = 0
	}
	attempts := retries + 1
	addr := net.JoinHostPort(ip, formatPort(port))
	for i := 0; i < attempts; i++ {
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
		if i < attempts-1 {
			time.Sleep(time.Duration(i+1) * 25 * time.Millisecond)
		}
	}
	return false
}

func formatPort(port int) string {
	return strconv.Itoa(port)
}
