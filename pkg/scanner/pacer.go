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

// catchUpGap is the minimum spacing between back-to-back debt repayments
// after a stall. Small enough to recover the full rate quickly, large
// enough that a recovery burst is not a single packet dump.
const catchUpGap = 100 * time.Microsecond

// startPacer returns a channel delivering tickets at a sustained rate of
// pps per second, paced against the wall clock. Two invariants hold:
//
//  1. Never over budget: delivered(t) <= floor(t * pps) at all times, so
//     any full one-second window carries at most pps tickets (+1 edge
//     tick). Missed ticks accumulate as debt and are repaid at catchUpGap
//     spacing, so jitter dips are recovered instead of lost.
//  2. Exact long-term rate: tick k falls due at start + k/pps computed
//     against the fixed start time, so the sustained rate cannot drift.
//
// The pacer goroutine exits when ctx is canceled.
func startPacer(ctx context.Context, pps int) <-chan struct{} {
	// Unbuffered: a blocked send holds at most one owed ticket, keeping
	// delivery accounting exact.
	out := make(chan struct{})
	go pace(ctx, pps, out)
	return out
}

func pace(ctx context.Context, pps int, out chan<- struct{}) {
	nsPerSec := int64(time.Second)
	start := time.Now()
	var delivered int64
	lastDelivery := start.Add(-catchUpGap)

	// due returns the number of tickets owed by time t.
	due := func(t time.Time) int64 {
		return t.Sub(start).Nanoseconds() * int64(pps) / nsPerSec
	}
	// deadline returns the wall time at which ticket k falls due.
	deadline := func(k int64) time.Time {
		return start.Add(time.Duration(k * nsPerSec / int64(pps)))
	}

	for {
		now := time.Now()
		if delivered < due(now) {
			// Behind schedule: repay one debt tick now, throttled by
			// catchUpGap against the last actual delivery. Never exceeds
			// delivered(t) <= t * pps, so the per-second budget holds.
			sleepUntil(lastDelivery.Add(catchUpGap))
		} else {
			// On schedule: wait for the next regular tick. If that tick
			// is already past due, still throttle against catchUpGap so
			// debt repayment never becomes a micro-burst.
			next := deadline(delivered + 1)
			if min := lastDelivery.Add(catchUpGap); next.Before(min) {
				next = min
			}
			sleepUntil(next)
		}

		select {
		case out <- struct{}{}:
			delivered++
			lastDelivery = time.Now()
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
