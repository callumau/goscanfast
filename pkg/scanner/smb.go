package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"goscanfast/pkg/export"
	"goscanfast/pkg/models"

	"github.com/hirochachacha/go-smb2"
)

func EnumSMB(ctx context.Context, ip, hostname string, writer export.SMBWriter, timeout time.Duration) {
	if hostname == "" {
		hostname = lookupHostname(ip)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "445"), timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User: "Guest",
		},
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(timeout))
	}

	s, err := d.DialContext(ctx, conn)
	if err != nil {
		// Even if session fails, we might want to know if it's a specific error
		_ = writer.WriteSMB(models.SMBResult{
			IP:       ip,
			Hostname: hostname,
			Share:    "SESSION_FAILED",
			Path:     err.Error(),
			Type:     "ERROR",
		})
		return
	}
	defer s.Logoff()

	shares, err := s.ListSharenames()
	if err != nil {
		_ = writer.WriteSMB(models.SMBResult{
			IP:       ip,
			Hostname: hostname,
			Share:    "LIST_FAILED",
			Path:     err.Error(),
			Type:     "ERROR",
		})
		return
	}

	if len(shares) == 0 {
		_ = writer.WriteSMB(models.SMBResult{
			IP:       ip,
			Hostname: hostname,
			Share:    "NONE",
			Path:     "NONE",
			Type:     "NONE",
		})
		return
	}

	foundAccessible := false
	for _, share := range shares {
		// Skip administrative shares that usually require higher privileges
		if strings.HasSuffix(share, "$") {
			continue
		}

		fs, err := s.Mount(share)
		if err != nil {
			continue
		}
		foundAccessible = true

		crawl(ip, hostname, share, ".", fs, writer, 0, 3)
		fs.Umount()
	}

	if !foundAccessible {
		_ = writer.WriteSMB(models.SMBResult{
			IP:       ip,
			Hostname: hostname,
			Share:    "NONE",
			Path:     "NONE",
			Type:     "NONE",
		})
	}
}

func crawl(ip, hostname, share, path string, fs *smb2.Share, writer export.SMBWriter, depth, maxDepth int) {
	if depth > maxDepth {
		return
	}

	entries, err := fs.ReadDir(path)
	if err != nil {
		// If we can't even read the root, still report the share exists
		if depth == 0 {
			_ = writer.WriteSMB(models.SMBResult{
				IP:       ip,
				Hostname: hostname,
				Share:    share,
				Path:     "ACCESS_DENIED",
				Type:     "Directory",
			})
		}
		return
	}

	if len(entries) == 0 && depth == 0 {
		_ = writer.WriteSMB(models.SMBResult{
			IP:       ip,
			Hostname: hostname,
			Share:    share,
			Path:     "EMPTY",
			Type:     "Directory",
		})
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "." || name == ".." {
			continue
		}

		entryPath := fmt.Sprintf("%s/%s", path, name)
		if path == "." {
			entryPath = name
		}

		entryType := "File"
		if entry.IsDir() {
			entryType = "Directory"
		}

		_ = writer.WriteSMB(models.SMBResult{
			IP:       ip,
			Hostname: hostname,
			Share:    share,
			Path:     entryPath,
			Type:     entryType,
		})

		if entry.IsDir() {
			crawl(ip, hostname, share, entryPath, fs, writer, depth+1, maxDepth)
		}
	}
}
