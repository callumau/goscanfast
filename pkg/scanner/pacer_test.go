package scanner

import (
	"context"
	"testing"
	"time"
)

// TestPacer_NoBurst verifies tickets are always at least one interval apart.
func TestPacer_NoBurst(t *testing.T) {
	const pps = 500
	interval := time.Second / pps

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tickets := startPacer(ctx, pps)

	var prev time.Time
	for i := 0; i < 50; i++ {
		select {
		case <-tickets:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ticket")
		}
		now := time.Now()
		if !prev.IsZero() {
			gap := now.Sub(prev)
			if gap < interval*9/10 {
				t.Fatalf("ticket %d arrived %v after previous, want >= ~%v (burst)", i, gap, interval)
			}
		}
		prev = now
	}
}

// TestPacer_SustainedRate verifies the long-term rate approaches pps.
func TestPacer_SustainedRate(t *testing.T) {
	const pps = 500
	const window = 900 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tickets := startPacer(ctx, pps)

	deadline := time.Now().Add(window)
	var count int
	for time.Now().Before(deadline) {
		select {
		case <-tickets:
			count++
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ticket")
		}
	}

	want := int(window.Seconds() * pps) // ~450
	lower := want * 85 / 100
	upper := want + want/50
	if count < lower || count > upper {
		t.Fatalf("delivered %d tickets in %v, want within [%d, %d] of %d", count, window, lower, upper, want)
	}
}

// TestPacer_NoCatchUpAfterStall verifies that after the consumer stalls,
// the pacer resumes at normal spacing instead of bursting missed tickets.
func TestPacer_NoCatchUpAfterStall(t *testing.T) {
	const pps = 1000
	interval := time.Second / pps

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tickets := startPacer(ctx, pps)

	// Drain a few, then stall the consumer for 50 intervals.
	for i := 0; i < 5; i++ {
		<-tickets
	}
	time.Sleep(50 * interval)

	// After the stall, deliveries must still be spaced >= one interval.
	var prev time.Time
	for i := 0; i < 20; i++ {
		<-tickets
		now := time.Now()
		if !prev.IsZero() {
			gap := now.Sub(prev)
			if gap < interval*9/10 {
				t.Fatalf("post-stall ticket %d arrived %v after previous (catch-up burst)", i, gap)
			}
		}
		prev = now
	}
}

// TestPacer_Cancel verifies the pacer stops delivering after ctx cancel.
func TestPacer_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tickets := startPacer(ctx, 1000)

	<-tickets
	cancel()
	time.Sleep(10 * time.Millisecond)

	select {
	case <-tickets:
		t.Fatal("ticket delivered after cancel")
	case <-time.After(20 * time.Millisecond):
	}
}
