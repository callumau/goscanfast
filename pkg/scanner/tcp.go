package scanner

import (
	"context"
	"net"
	"strconv"
	"time"
)

func ScanPort(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, formatPort(port))
	for retry := 0; retry < 2; retry++ {
		if retry > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(100 * time.Millisecond):
			}
		}
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

func formatPort(port int) string {
	return strconv.Itoa(port)
}
