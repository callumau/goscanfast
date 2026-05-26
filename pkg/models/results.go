package models

// Result holds the scan outcome for a single host.
type Result struct {
	IP       string
	Hostname string
	Ports    []int
}

// SMBResult holds an SMB enumeration entry for a share, path, or error.
type SMBResult struct {
	IP       string
	Hostname string
	Share    string
	Path     string
	Type     string // "Directory", "File", "ERROR", or "NONE"
}
