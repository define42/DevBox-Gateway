package transport

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

const ms = time.Millisecond

// zeroRand pins jitter to its maximum delay, so a progression is exact.
func zeroRand() float64 { return 0 }

// seqRand replays a fixed sequence, repeating the last value once exhausted.
func seqRand(values ...float64) func() float64 {
	var i int
	return func() float64 {
		v := values[i]
		if i < len(values)-1 {
			i++
		}
		return v
	}
}

func TestBackoffProgression(t *testing.T) {
	tests := []struct {
		name string
		opts BackoffOptions
		want []time.Duration
	}{
		{
			// DESIGN section 22: growth from 100ms, capped at 10s.
			name: "agent defaults",
			opts: BackoffOptions{Initial: 100 * ms, Max: 10 * time.Second, Multiplier: 2, Rand: zeroRand},
			want: []time.Duration{
				100 * ms, 200 * ms, 400 * ms, 800 * ms,
				1600 * ms, 3200 * ms, 6400 * ms,
				10 * time.Second, 10 * time.Second, 10 * time.Second,
			},
		},
		{
			name: "zero options fall back to the agent defaults",
			opts: BackoffOptions{Rand: zeroRand},
			want: []time.Duration{100 * ms, 200 * ms, 400 * ms, 800 * ms},
		},
		{
			name: "fractional multiplier",
			opts: BackoffOptions{Initial: 100 * ms, Max: time.Second, Multiplier: 1.5, Rand: zeroRand},
			want: []time.Duration{100 * ms, 150 * ms, 225 * ms, 337500 * time.Microsecond, 506250 * time.Microsecond},
		},
		{
			// A multiplier below 1 would shrink the delay after every failure,
			// which is the opposite of backoff.
			name: "shrinking multiplier is rejected",
			opts: BackoffOptions{Initial: 100 * ms, Max: time.Second, Multiplier: 0.5, Rand: zeroRand},
			want: []time.Duration{100 * ms, 200 * ms, 400 * ms, 800 * ms, time.Second},
		},
		{
			name: "multiplier of one holds steady",
			opts: BackoffOptions{Initial: 250 * ms, Max: 10 * time.Second, Multiplier: 1, Rand: zeroRand},
			want: []time.Duration{250 * ms, 250 * ms, 250 * ms},
		},
		{
			// A max below the initial delay is a configuration error; the
			// initial delay wins so the agent does not retry faster than asked.
			name: "max below initial",
			opts: BackoffOptions{Initial: 5 * time.Second, Max: time.Second, Multiplier: 2, Rand: zeroRand},
			want: []time.Duration{5 * time.Second, 5 * time.Second},
		},
		{
			name: "negative durations fall back to defaults",
			opts: BackoffOptions{Initial: -1, Max: -1, Multiplier: 2, Rand: zeroRand},
			want: []time.Duration{100 * ms, 200 * ms},
		},
		{
			name: "NaN multiplier falls back",
			opts: BackoffOptions{Initial: 100 * ms, Max: time.Second, Multiplier: math.NaN(), Rand: zeroRand},
			want: []time.Duration{100 * ms, 200 * ms},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBackoff(tt.opts)
			for i, want := range tt.want {
				got := b.Next()
				if got != want {
					t.Errorf("Next() #%d = %v, want %v", i+1, got, want)
				}
				if attempts := b.Attempts(); attempts != i+1 {
					t.Errorf("Attempts() after %d calls = %d, want %d", i+1, attempts, i+1)
				}
			}
		})
	}
}

func TestBackoffMonotonicAndCapped(t *testing.T) {
	const max = 10 * time.Second
	b := NewBackoff(BackoffOptions{Initial: 100 * ms, Max: max, Multiplier: 2, Jitter: 0.2, Rand: seqRand(0.5)})

	var prev time.Duration
	var reachedMax bool
	// Far more failures than a real outage needs, to be sure the exponent
	// never overflows into a nonsensical delay.
	for i := range 4096 {
		got := b.Next()
		if got > max {
			t.Fatalf("Next() #%d = %v, exceeds Max %v", i+1, got, max)
		}
		if got < 0 {
			t.Fatalf("Next() #%d = %v, negative delay", i+1, got)
		}
		if got < prev {
			t.Fatalf("Next() #%d = %v, shrank from %v", i+1, got, prev)
		}
		if got == time.Duration(float64(max)*0.9) {
			reachedMax = true
		}
		prev = got
	}
	if !reachedMax {
		t.Errorf("never reached the capped delay; last was %v", prev)
	}
	if got := b.Attempts(); got != 4096 {
		t.Errorf("Attempts() = %d, want 4096", got)
	}
}

func TestBackoffJitterBounds(t *testing.T) {
	const (
		initial = time.Second
		jitter  = 0.25
	)
	// Includes values a caller's Rand must never produce: out of range, and
	// NaN. A bad source must not produce a negative or unbounded sleep.
	draws := []float64{0, 0.001, 0.5, 0.999, 1, 1.5, -0.5, math.NaN(), math.Inf(1), math.Inf(-1)}

	lo := time.Duration(float64(initial) * (1 - jitter))
	for _, r := range draws {
		b := NewBackoff(BackoffOptions{
			Initial: initial, Max: time.Minute, Multiplier: 2, Jitter: jitter,
			Rand: seqRand(r),
		})
		got := b.Next()
		if got < lo || got > initial {
			t.Errorf("Rand()=%v gave Next() = %v, want within [%v, %v]", r, got, lo, initial)
		}
	}
}

func TestBackoffJitterClamped(t *testing.T) {
	tests := []struct {
		name   string
		jitter float64
		want   time.Duration // with Rand fixed at 0.5
	}{
		{name: "none", jitter: 0, want: time.Second},
		{name: "negative is treated as none", jitter: -1, want: time.Second},
		{name: "NaN is treated as none", jitter: math.NaN(), want: time.Second},
		{name: "half", jitter: 0.5, want: 750 * ms},
		{name: "full", jitter: 1, want: 500 * ms},
		{name: "above one is clamped to one", jitter: 4, want: 500 * ms},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBackoff(BackoffOptions{
				Initial: time.Second, Max: time.Minute, Multiplier: 2,
				Jitter: tt.jitter, Rand: seqRand(0.5),
			})
			if got := b.Next(); got != tt.want {
				t.Errorf("Next() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBackoffDefaultJitterSpreads checks the point of jitter: a fleet of guests
// reconnecting to a restarted collector must not arrive in lockstep. Every
// Backoff here is at attempt zero, as a fleet would be after a collector
// restart, and uses the package's own source rather than an injected one.
func TestBackoffDefaultJitterSpreads(t *testing.T) {
	const (
		base    = time.Second
		jitter  = 0.2
		draws   = 500
		buckets = 10
	)

	lo := time.Duration(float64(base) * (1 - jitter))
	seen := make(map[time.Duration]int, draws)
	filled := make(map[int]bool, buckets)
	var sum time.Duration

	for range draws {
		b := NewBackoff(BackoffOptions{Initial: base, Max: time.Minute, Multiplier: 2, Jitter: jitter})
		d := b.Next()
		if d < lo || d > base {
			t.Fatalf("Next() = %v, outside [%v, %v]", d, lo, base)
		}
		seen[d]++
		sum += d
		// Which tenth of the jittered window the delay landed in.
		idx := int(float64(d-lo) / float64(base-lo) * buckets)
		if idx >= buckets {
			idx = buckets - 1
		}
		filled[idx] = true
	}

	if len(seen) < draws/2 {
		t.Errorf("only %d distinct delays in %d draws; jitter is not spreading reconnections", len(seen), draws)
	}
	if len(filled) != buckets {
		t.Errorf("delays covered %d of %d buckets across the jitter window, want all of them", len(filled), buckets)
	}
	// Uniform r in [0,1) puts the mean halfway through the window.
	wantMean := float64(lo+base) / 2
	gotMean := float64(sum) / draws
	if math.Abs(gotMean-wantMean) > 0.05*float64(base) {
		t.Errorf("mean delay = %v, want about %v", time.Duration(gotMean), time.Duration(wantMean))
	}
}

func TestBackoffReset(t *testing.T) {
	b := NewBackoff(BackoffOptions{Initial: 100 * ms, Max: 10 * time.Second, Multiplier: 2, Rand: zeroRand})

	if got := b.Attempts(); got != 0 {
		t.Fatalf("Attempts() on a fresh Backoff = %d, want 0", got)
	}
	for range 5 {
		b.Next()
	}
	if got := b.Attempts(); got != 5 {
		t.Fatalf("Attempts() = %d, want 5", got)
	}

	b.Reset()
	if got := b.Attempts(); got != 0 {
		t.Errorf("Attempts() after Reset = %d, want 0", got)
	}
	if got := b.Next(); got != 100*ms {
		t.Errorf("Next() after Reset = %v, want the initial delay", got)
	}
	// Reset is idempotent: a reconnect loop may call it on every success.
	b.Reset()
	b.Reset()
	if got := b.Attempts(); got != 0 {
		t.Errorf("Attempts() after repeated Reset = %d, want 0", got)
	}
}

func TestBackoffWaitSleeps(t *testing.T) {
	b := NewBackoff(BackoffOptions{Initial: 2 * ms, Max: 5 * ms, Multiplier: 2, Rand: zeroRand})

	start := time.Now()
	if err := b.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 2*ms {
		t.Errorf("Wait returned after %v, want at least %v", elapsed, 2*ms)
	}
	if got := b.Attempts(); got != 1 {
		t.Errorf("Attempts() after Wait = %d, want 1", got)
	}
}

func TestBackoffWaitCanceledBeforeCall(t *testing.T) {
	// A delay long enough that any sleep at all would be obvious.
	b := NewBackoff(BackoffOptions{Initial: 30 * time.Second, Max: time.Minute, Multiplier: 2, Rand: zeroRand})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := b.Wait(ctx)
	elapsed := time.Since(start)

	if err != context.Canceled {
		t.Errorf("Wait = %v, want context.Canceled", err)
	}
	if elapsed > 100*ms {
		t.Errorf("Wait slept for %v on an already-cancelled context", elapsed)
	}
	// Shutting down is not a delivery failure, so it must not inflate the
	// attempt count the agent reports.
	if got := b.Attempts(); got != 0 {
		t.Errorf("Attempts() = %d after a cancelled Wait, want 0", got)
	}
}

func TestBackoffWaitCanceledDuringSleep(t *testing.T) {
	b := NewBackoff(BackoffOptions{Initial: 30 * time.Second, Max: time.Minute, Multiplier: 2, Rand: zeroRand})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(2 * ms)
		cancel()
	}()

	start := time.Now()
	err := b.Wait(ctx)
	elapsed := time.Since(start)
	cancel()

	if err != context.Canceled {
		t.Errorf("Wait = %v, want context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Errorf("Wait took %v to notice cancellation", elapsed)
	}
	if got := b.Attempts(); got != 1 {
		t.Errorf("Attempts() = %d, want 1 (the attempt was consumed before sleeping)", got)
	}
}

func TestBackoffWaitDeadline(t *testing.T) {
	b := NewBackoff(BackoffOptions{Initial: 30 * time.Second, Max: time.Minute, Multiplier: 2, Rand: zeroRand})

	ctx, cancel := context.WithTimeout(context.Background(), 2*ms)
	defer cancel()

	if err := b.Wait(ctx); err != context.DeadlineExceeded {
		t.Errorf("Wait = %v, want context.DeadlineExceeded", err)
	}
}

// TestBackoffConcurrent exercises the mutex: the sender goroutine drives the
// backoff while the heartbeat goroutine reads Attempts for its report.
func TestBackoffConcurrent(t *testing.T) {
	b := NewBackoff(BackoffOptions{Initial: ms, Max: 10 * ms, Multiplier: 2, Jitter: 0.2})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if d := b.Next(); d < 0 || d > 10*ms {
					t.Errorf("Next() = %v, outside [0, 10ms]", d)
					return
				}
				_ = b.Attempts()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			b.Reset()
		}
	}()
	wg.Wait()
}
