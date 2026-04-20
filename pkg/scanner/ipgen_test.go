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
