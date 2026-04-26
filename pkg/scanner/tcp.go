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
	if err == nil {
		_ = conn.Close()
		return true
	}

	// Retry once on timeout — may be transient packet loss to live host.
	// Connection refused / reset means host reached us; no retry needed.
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
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
