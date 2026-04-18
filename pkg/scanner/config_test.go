package scanner

import "testing"

func TestParsePortList(t *testing.T) {
	ports, err := parsePortList("22, 80,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	if ports[0] != 22 || ports[1] != 80 || ports[2] != 443 {
		t.Fatalf("unexpected ports: %+v", ports)
	}
}

func TestLooksLikePortList(t *testing.T) {
	if !looksLikePortList("22,80,443") {
		t.Fatalf("expected port list to be recognized")
	}
	if looksLikePortList("ports.json") {
		t.Fatalf("did not expect file path to be recognized as port list")
	}
}
