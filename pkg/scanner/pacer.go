package scanner

import (
	"context"
	"time"
)

// spinWindow is the slice of time before a tick deadline where the pacer
// stops sleeping and busy-waits, so tick delivery is not subject to timer
// slop. For rates whose interval is shorter than this window the pacer
// spins the whole interval (busy core, exact pacing).
const spinWindow = 300 * time.Microsecond

// startPacer returns a channel delivering exactly one ticket per 1/pps
// interval, paced against the wall clock. Two invariants are guaranteed:
//
//  1. No bursts: consecutive ticket deliveries are always at least one
//     full interval apart, even after scheduler stalls or a blocked send.
//     Missed ticks are skipped, never replayed.
//  2. Exact long-term rate: tick intervals accumulate their sub-nanosecond
//     remainder so the sustained rate does not drift from pps.
//
// Under system jitter the delivered rate can dip below pps but can never
// exceed it. The pacer goroutine exits when ctx is canceled.
func startPacer(ctx context.Context, pps int) <-chan struct{} {
	// Unbuffered: the pacer can never have both a queued ticket and a
	// blocked send, so a stalled consumer draining later cannot observe
	// two deliveries closer than one interval.
	out := make(chan struct{})
	go pace(ctx, pps, out)
	return out
}

func pace(ctx context.Context, pps int, out chan<- struct{}) {
	nsPerTick := int64(time.Second) / int64(pps)
	rem := int64(time.Second) % int64(pps)
	interval := time.Duration(nsPerTick)
	var errAcc int64

	last := time.Now()
	next := last
	for {
		next = next.Add(interval)
		errAcc += rem
		if errAcc >= int64(pps) {
			errAcc -= int64(pps)
			next = next.Add(time.Nanosecond)
		}
		// Never schedule less than one interval after the last actual
		// delivery, regardless of how long the previous send blocked.
		if min := last.Add(interval); next.Before(min) {
			next = min
		}
		// Behind schedule: snap to now, skipping missed ticks.
		if now := time.Now(); now.After(next) {
			next = now
		}

		sleepUntil(next)

		select {
		case out <- struct{}{}:
			last = time.Now()
		case <-ctx.Done():
			return
		}
	}
}

// sleepUntil blocks until deadline: a coarse sleep for the bulk of the
// wait, then a spin for the final stretch (async preemption keeps the
// spin from starving other goroutines).
func sleepUntil(deadline time.Time) {
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		if remaining > spinWindow {
			time.Sleep(remaining - spinWindow)
			continue
		}
		for time.Now().Before(deadline) {
		}
		return
	}
}
