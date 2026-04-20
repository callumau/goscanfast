package models

type Result struct {
	IP       string
	Hostname string
	Ports    []int
}

type SMBResult struct {
	IP       string
	Hostname string
	Share    string
	Path     string
	Type     string // "Directory" or "File"
}
