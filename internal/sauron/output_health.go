package sauron

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

// observedSink preserves the all-output acceptance contract while exposing
// failed writes to readiness. An agent can remain connected and send heartbeats
// while outputs reject its data, so stream presence alone cannot prove health.
type observedSink struct {
	collector.Sink

	mu            sync.Mutex
	lastErr       error
	failures      uint64
	rejected      map[rejectedEventKey]*rejectedRecord
	rejectedBytes int
	overflow      bool

	retryCancel context.CancelFunc
	retryDone   chan struct{}
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

const maxRejectedGuestEvents = 4096

// Keys retain no guest-sized strings. A trusted UUID survives VM restarts and
// CID reassignment. Retained retries keep the original pinned attribution.
type rejectedEventKey struct {
	vm       [sha256.Size]byte
	boot     [sha256.Size]byte
	sequence uint64
}

func guestEventKey(env *collector.Envelope) (rejectedEventKey, bool) {
	if env == nil || env.Event == nil || env.Event.Sequence == 0 {
		// Host-generated diagnostics have sequence zero. Guest internal events
		// have positive sequences and need the same replay protection as data.
		return rejectedEventKey{}, false
	}
	identity := "uuid:" + env.Source.UUID
	if !env.Source.Known || env.Source.UUID == "" {
		identity = fmt.Sprintf("cid:%d:known:%t:vm:%s", env.Source.CID, env.Source.Known, env.Source.VM)
	}
	boot := env.Event.BootID
	if boot == "" && env.Source.Reported != nil {
		boot = env.Source.Reported.BootID
	}
	return rejectedEventKey{
		vm: sha256.Sum256([]byte(identity)), boot: sha256.Sum256([]byte(boot)), sequence: env.Event.Sequence,
	}, true
}

func (s *observedSink) Write(ctx context.Context, env *collector.Envelope) error {
	s.mu.Lock()
	before := s.failures
	s.mu.Unlock()
	err := s.Sink.Write(ctx, env)
	key, guest := guestEventKey(env)
	var encoded []byte
	if err != nil && guest && s.canRetain(key) {
		// Guest frames are already bounded by the collector's payload limit.
		// Encoding snapshots nested fields and source labels as well as the
		// event, without retaining mutable values owned by the session.
		encoded, _ = json.Marshal(env)
	}
	s.record(err, true, before, key, guest, encoded)
	return err
}

func (s *observedSink) Flush(ctx context.Context) error {
	err := s.Sink.Flush(ctx)
	// Only a successful event write demonstrates that output admission has
	// recovered. Flushing an empty output must not hide a rejected write.
	s.record(err, false, 0, rejectedEventKey{}, false, nil)
	return err
}

func (s *observedSink) record(
	err error, acceptedWrite bool, before uint64, key rejectedEventKey, guest bool, encoded []byte,
) {
	s.mu.Lock()
	change := s.recordLocked(err, acceptedWrite, before, key, guest, encoded)
	s.mu.Unlock()
	change.log()
}

func (s *observedSink) recordLocked(
	err error, acceptedWrite bool, before uint64, key rejectedEventKey, guest bool, encoded []byte,
) outputHealthChange {
	wasUnhealthy, wasOverflow := s.lastErr != nil || s.overflow, s.overflow
	if err != nil {
		s.failures++
		s.lastErr = err
		if guest {
			s.rejectLocked(key, encoded)
		}
	} else if acceptedWrite {
		s.acceptLocked(before, key, guest)
	}
	change := outputHealthChange{
		recovered:  wasUnhealthy && s.lastErr == nil && !s.overflow,
		overflowed: !wasOverflow && s.overflow,
	}
	if !wasUnhealthy {
		change.err = err
	}
	return change
}

type outputHealthChange struct {
	err                   error
	recovered, overflowed bool
}

func (change outputHealthChange) log() {
	if change.err != nil {
		log.Printf("sauron: event output unavailable: %v", change.err)
	} else if change.recovered {
		log.Printf("sauron: event output recovered")
	}
	if change.overflowed {
		log.Printf("sauron: rejected guest event retry capacity exhausted; readiness requires operator recovery")
	}
}

func (s *observedSink) acceptLocked(before uint64, key rejectedEventKey, guest bool) {
	if rejected, pending := s.rejected[key]; guest && pending && rejected.version <= before {
		s.releaseRecordLocked(rejected)
		delete(s.rejected, key)
	}
	// A write already in flight when another write/flush fails cannot prove
	// recovery from that failure. Neither can another event prove that a
	// previously rejected guest event can now be accepted.
	if before == s.failures && len(s.rejected) == 0 {
		s.lastErr = nil
	}
}

func (s *observedSink) rejectLocked(key rejectedEventKey, encoded []byte) {
	if s.rejected == nil {
		s.rejected = make(map[rejectedEventKey]*rejectedRecord)
	}
	if _, exists := s.rejected[key]; !exists && len(s.rejected) >= maxRejectedGuestEvents {
		s.overflow = true
		return
	}
	if old := s.rejected[key]; old != nil {
		s.releaseRecordLocked(old)
	}
	if len(encoded) == 0 || len(encoded) > maxRejectedGuestBytes-s.rejectedBytes {
		s.overflow = true
		encoded = nil
	}
	s.rejected[key] = &rejectedRecord{key: key, version: s.failures, encoded: encoded}
	s.rejectedBytes += len(encoded)
}

func (s *observedSink) releaseRecordLocked(rejected *rejectedRecord) {
	if !rejected.inflight {
		s.rejectedBytes -= len(rejected.encoded)
	}
}

func (s *observedSink) readiness() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.overflow {
		return errors.New("rejected guest event tracking overflowed; operator recovery required")
	}
	if s.lastErr != nil {
		return fmt.Errorf("event output unavailable: %w", s.lastErr)
	}
	return nil
}
