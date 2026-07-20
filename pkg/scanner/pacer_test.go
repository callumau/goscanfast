package scanner

import (
	"context"
	"testing"
	"time"
)

// TestPacer_NeverOverBudget verifies no trailing one-second window ever
// carries more than pps (+2 slack for edge ticks and measurement slop).
func TestPacer_NeverOverBudget(t *testing.T) {
	const pps = 500

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tickets := startPacer(ctx, pps)

	var times []time.Time
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case <-tickets:
			times = append(times, time.Now())
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ticket")
		}
	}
	for i, ts := range times {
		count := 1
		for j := i - 1; j >= 0 && ts.Sub(times[j]) <= time.Second; j-- {
			count++
		}
		if count > pps+2 {
			t.Fatalf("ticket %d: %d tickets in trailing second, budget %d", i, count, pps)
		}
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

// TestPacer_CatchUpAfterStall verifies missed ticks are repaid (the rate
// recovers after a consumer stall) while never exceeding the per-second
// budget. Micro-spacing is enforced sender-side (catchUpGap); receiver
// timestamps cannot measure it reliably, so only the budget is asserted.
func TestPacer_CatchUpAfterStall(t *testing.T) {
	const pps = 1000
	interval := time.Second / pps

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tickets := startPacer(ctx, pps)
	start := time.Now()

	// Drain a few, then stall the consumer for 50 intervals.
	for i := 0; i < 5; i++ {
		<-tickets
	}
	time.Sleep(50 * interval)

	// After the stall, debt must be repaid fast, and no trailing
	// one-second window may carry more than pps (+2 slack) tickets.
	var times []time.Time
	for i := 0; i < 200; i++ {
		<-tickets
		times = append(times, time.Now())
	}
	for i, ts := range times {
		count := 1
		for j := i - 1; j >= 0 && ts.Sub(times[j]) <= time.Second; j-- {
			count++
		}
		if count > pps+2 {
			t.Fatalf("ticket %d: %d tickets in trailing second, budget %d", i, count, pps)
		}
	}
	// Debt repaid: 205 tickets at pps take 205ms on the ideal schedule.
	// Without catch-up the 50ms stall is lost: ~250ms. Allow 25ms slack.
	if elapsed := time.Since(start); elapsed > 230*time.Millisecond {
		t.Fatalf("debt not repaid: 205 tickets took %v", elapsed)
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
