package scanner

import "testing"

func TestCIDRSize(t *testing.T) {
	if size := CIDRSize("10.0.0.0/16"); size != 65536 {
		t.Fatalf("expected 65536, got %d", size)
	}
}

func TestTotalCIDRSize(t *testing.T) {
	size := TotalCIDRSize([]string{"10.0.0.0/16", "10.1.0.0/24"})
	if size != 65536+256 {
		t.Fatalf("expected %d, got %d", 65536+256, size)
	}
}

func TestGenerateIPsMulti(t *testing.T) {
	ch, err := GenerateIPsMulti([]string{"10.0.0.0/30"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	for range ch {
		count++
	}
	if count != 4 {
		t.Fatalf("expected 4 IPs, got %d", count)
	}
}

func TestGenerateIPsMulti_Overlap(t *testing.T) {
	// 10.0.0.0/24 includes 10.0.0.0 to 10.0.0.255
	// 10.0.0.0/30 includes 10.0.0.0 to 10.0.0.3
	ch, err := GenerateIPsMulti([]string{"10.0.0.0/24", "10.0.0.0/30"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	for range ch {
		count++
	}
	// If it doesn't deduplicate, it will have 256 + 4 = 260 IPs
	if count != 256 {
		t.Errorf("expected 256 unique IPs, got %d", count)
	}
}

func TestTotalScannableHosts(t *testing.T) {
	cases := []struct {
		name     string
		cidrs    []string
		excludes []string
		want     uint64
	}{
		{"no excludes", []string{"10.0.0.0/30"}, nil, 4},
		{"exclude half", []string{"10.0.0.0/30"}, []string{"10.0.0.0/31"}, 2},
		{"exclude all", []string{"10.0.0.0/30"}, []string{"10.0.0.0/30"}, 0},
		{"exclude superset", []string{"10.0.0.0/24"}, []string{"10.0.0.0/16"}, 0},
		{"exclude outside range", []string{"10.0.0.0/30"}, []string{"192.168.0.0/24"}, 4},
		{"exclude spanning two blocks", []string{"10.0.0.0/25", "10.0.0.128/25"}, []string{"10.0.0.0/24"}, 0},
		{"overlapping excludes", []string{"10.0.0.0/24"}, []string{"10.0.0.0/25", "10.0.0.64/26"}, 128},
		{"exclude at 255 boundary", []string{"10.0.0.248/29"}, []string{"10.0.0.255/32"}, 7},
		{"overlapping includes deduped", []string{"10.0.0.0/24", "10.0.0.0/30"}, nil, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TotalScannableHosts(tc.cidrs, tc.excludes); got != tc.want {
				t.Fatalf("TotalScannableHosts(%v, %v) = %d, want %d", tc.cidrs, tc.excludes, got, tc.want)
			}
		})
	}
}

func TestTotalScannableHosts_Invalid(t *testing.T) {
	if got := TotalScannableHosts([]string{"bogus"}, nil); got != 0 {
		t.Fatalf("expected 0 for invalid CIDR, got %d", got)
	}
	if got := TotalScannableHosts([]string{"10.0.0.0/24"}, []string{"bogus"}); got != 0 {
		t.Fatalf("expected 0 for invalid exclude, got %d", got)
	}
}
