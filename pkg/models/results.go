package models

// Result holds the scan outcome for a single host.
type Result struct {
	IP       string
	Hostname string
	Ports    []int
}
