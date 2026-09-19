package transport

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

// Defaults matching config.DefaultAgent's reconnect section, so a zero-valued
// BackoffOptions behaves like a stock agent instead of hammering the host.
const (
	defaultBackoffInitial    = 100 * time.Millisecond
	defaultBackoffMax        = 10 * time.Second
	defaultBackoffMultiplier = 2.0
)

// BackoffOptions configures reconnection pacing.
type BackoffOptions struct {
	// Initial is the delay after the first failure. Zero or negative means
	// 100ms.
	Initial time.Duration

	// Max caps the delay however long the outage lasts. Zero or negative
	// means 10s. A guest that has been disconnected for an hour must still
	// retry regularly, because it is spooling events the whole time.
	Max time.Duration

	// Multiplier grows the delay after each consecutive failure. Values below
	// 1 would shrink it, which is never intended, so they are replaced by 2.
	Multiplier float64

	// Jitter is the fraction of the delay that is randomised, in [0,1].
	// Values outside that range are clamped. Zero disables randomisation,
	// which is what tests want and what a fleet does not.
	Jitter float64

	// Rand returns a uniform value in [0,1). It exists so tests can pin the
	// jitter; nil means a package-internal source seeded from crypto/rand.
	Rand func() float64
}

// Backoff paces reconnection attempts with capped exponential backoff.
//
// Nothing is lost while it waits: the agent keeps reading audit records into
// the queue and the spool throughout the outage, so the only thing backoff
// controls is how hard a fleet of guests hits a collector that is coming back
// up. All methods are safe for concurrent use.
type Backoff struct {
	mu         sync.Mutex
	attempts   int
	initial    time.Duration
	max        time.Duration
	multiplier float64
	jitter     float64
	rand       func() float64
}

// NewBackoff returns a Backoff with the given options, substituting defaults
// for values that are unset or out of range. It never rejects a configuration:
// a misconfigured delay must not be the reason an agent stops reconnecting.
func NewBackoff(opts BackoffOptions) *Backoff {
	b := &Backoff{
		initial:    opts.Initial,
		max:        opts.Max,
		multiplier: opts.Multiplier,
		jitter:     opts.Jitter,
		rand:       opts.Rand,
	}
	if b.initial <= 0 {
		b.initial = defaultBackoffInitial
	}
	if b.max <= 0 {
		b.max = defaultBackoffMax
	}
	if b.max < b.initial {
		b.max = b.initial
	}
	if math.IsNaN(b.multiplier) || b.multiplier < 1 {
		b.multiplier = defaultBackoffMultiplier
	}
	if math.IsNaN(b.jitter) || b.jitter < 0 {
		b.jitter = 0
	}
	if b.jitter > 1 {
		b.jitter = 1
	}
	if b.rand == nil {
		b.rand = defaultJitter
	}
	return b
}

// Next records another consecutive failure and returns how long to wait before
// the next attempt.
//
// With Initial=100ms, Multiplier=2 and Max=10s the undithered progression is
// 100ms, 200ms, 400ms, 800ms, 1.6s, 3.2s, 6.4s, 10s, 10s...
//
// Jitter is subtractive: the result is base*(1-Jitter*r) for r in [0,1), so it
// only ever shortens the wait. That keeps Max a genuine upper bound while
// still spreading a fleet of guests out, and it means a collector restart is
// not met by every VM in the fleet reconnecting in the same millisecond.
func (b *Backoff) Next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	d := b.baseLocked(b.attempts)
	// Saturate rather than wrap: an int that goes negative here would restart
	// the progression at Initial in the middle of an outage.
	if b.attempts < math.MaxInt {
		b.attempts++
	}
	if b.jitter == 0 {
		return d
	}

	// A caller-supplied Rand is not trusted to honour [0,1); a stray value
	// must not turn into a negative or unbounded sleep.
	r := b.rand()
	switch {
	case math.IsNaN(r), r < 0:
		r = 0
	case r >= 1:
		r = math.Nextafter(1, 0)
	}
	return time.Duration(float64(d) * (1 - b.jitter*r))
}

// baseLocked is the undithered delay for the n-th consecutive failure.
func (b *Backoff) baseLocked(n int) time.Duration {
	d := float64(b.initial) * math.Pow(b.multiplier, float64(n))
	// A long outage overflows the exponent to +Inf. Converting an out-of-range
	// float to a Duration is undefined, so clamp in float space first.
	if math.IsNaN(d) || d >= float64(b.max) {
		return b.max
	}
	return time.Duration(d)
}

// Reset clears the failure count, so the next delay starts from Initial again.
// The caller does this once a connection is established and usable, not merely
// dialled, otherwise a collector that accepts and immediately drops
// connections would be retried in a tight loop.
func (b *Backoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts = 0
}

// Attempts is the number of consecutive failures since the last Reset. It is
// reported in the sauron.transport.disconnected event so an operator can see
// how long a guest has been unable to deliver.
func (b *Backoff) Attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempts
}

// Wait sleeps for the next backoff interval, or returns ctx.Err() as soon as
// ctx is done, whichever happens first.
//
// A context that is already done returns immediately without sleeping and
// without counting an attempt, so a shutdown during an outage does not inflate
// the failure count that gets reported.
func (b *Backoff) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(b.Next())
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// The default jitter source is process-wide and mutex-guarded: math/rand's
// global functions are deliberately avoided so that nothing outside this
// package can reseed or perturb reconnection pacing.
var (
	jitterMu  sync.Mutex
	jitterSrc = sync.OnceValue(newJitterSource)
)

func newJitterSource() *rand.Rand {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		// Jitter only has to de-synchronise a fleet; it is not a secret and
		// carries no security weight. A degraded seed is better than an agent
		// that refuses to reconnect because the CSPRNG was unavailable.
		binary.LittleEndian.PutUint64(seed[:8], uint64(time.Now().UnixNano()))
	}
	return rand.New(rand.NewChaCha8(seed))
}

func defaultJitter() float64 {
	src := jitterSrc()
	jitterMu.Lock()
	defer jitterMu.Unlock()
	return src.Float64()
}
