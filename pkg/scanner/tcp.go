package scanner

import (
	"context"
	"net"
	"strconv"
	"time"
)

func ScanPort(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, formatPort(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func formatPort(port int) string {
	return strconv.Itoa(port)
}
