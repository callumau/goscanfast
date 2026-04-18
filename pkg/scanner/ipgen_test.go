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
