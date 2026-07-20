package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"goscanfast/pkg/models"
)

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestCSVWriter_SortedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	w, err := NewWriter("csv", path)
	if err != nil {
		t.Fatal(err)
	}
	// Write out of order; Close must sort by IP.
	ips := []string{"10.0.0.20", "10.0.0.3", "9.255.255.255", "10.0.0.10"}
	for _, ip := range ips {
		if err := w.Write(models.Result{IP: ip, Ports: []int{80}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	recs := readCSV(t, path)
	if len(recs) != len(ips)+1 {
		t.Fatalf("expected %d rows + header, got %d", len(ips), len(recs))
	}
	want := []string{"9.255.255.255", "10.0.0.3", "10.0.0.10", "10.0.0.20"}
	for i, ip := range want {
		if recs[i+1][0] != ip {
			t.Fatalf("row %d: expected %s, got %s", i, ip, recs[i+1][0])
		}
	}
}

func TestCSVWriter_ManyRowsExternalSort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	w, err := NewWriter("csv", path)
	if err != nil {
		t.Fatal(err)
	}
	// Exceed one sort chunk (100k) to exercise the merge path.
	const n = 150000
	for i := n; i >= 1; i-- {
		if err := w.Write(models.Result{IP: uint32ToDotted(uint32(i)), Ports: []int{443}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	recs := readCSV(t, path)
	if len(recs) != n+1 {
		t.Fatalf("expected %d rows + header, got %d", n, len(recs))
	}
	prev := uint32(0)
	for i, rec := range recs[1:] {
		ip := parseIP(rec[0])
		if ip < prev {
			t.Fatalf("row %d out of order: %v after %v", i, rec[0], prev)
		}
		prev = ip
	}
}

func uint32ToDotted(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func TestCSVWriter_DoubleClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	w, err := NewWriter("csv", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(models.Result{IP: "10.0.0.1", Ports: []int{22}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Second Close must not panic and must report the same result.
	if err := w.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

func TestCSVWriter_EmptyFileSortsCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	w, err := NewWriter("csv", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	recs := readCSV(t, path)
	if len(recs) != 1 || recs[0][0] != "ip" {
		t.Fatalf("expected header-only file, got %v", recs)
	}
}

func TestJSONWriter_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	w, err := NewWriter("json", path)
	if err != nil {
		t.Fatal(err)
	}
	in := []models.Result{
		{IP: "10.0.0.1", Hostname: "a", Ports: []int{22, 80}},
		{IP: "10.0.0.2", Ports: []int{443}},
	}
	for _, r := range in {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []models.Result
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(out) != len(in) || out[0].IP != in[0].IP || out[1].Ports[0] != 443 {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func TestNewWriter_UnsupportedFormat(t *testing.T) {
	if _, err := NewWriter("xml", ""); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestCSVWriter_ErrorOnBadPath(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "nonexistent-dir", "out.csv")
	if _, err := NewWriter("csv", bad); err == nil {
		t.Fatal("expected error for unwritable path")
	}
}
