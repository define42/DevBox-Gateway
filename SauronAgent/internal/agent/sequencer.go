package agent

import (
	"sync/atomic"

	"github.com/define42/SauronAgent/internal/event"
)

// sequencer hands out the per-boot event sequence numbers.
//
// Numbering happens immediately after normalization and before the queue
// (DESIGN.md section 20), which is the ordering that lets the queue and the
// spool name the exact sequences they lost. A number assigned after the queue
// would make an overflow report "some events were dropped", which tells a
// collector nothing it can act on.
//
// Uniqueness comes from (boot id, sequence), so the counter only has to be
// strictly increasing within one boot. It is safe for concurrent use because
// internal events are produced by the listener callbacks, the loss poller and
// the sender, none of which run on the normalizer's goroutine.
type sequencer struct {
	// next is the sequence the next assignment hands out. Sequence 0 is
	// reserved by the protocol to mean "no sequence", so it is never issued.
	next atomic.Uint64

	// bootID scopes the numbering. It is stamped on events that do not carry
	// one already; see assign.
	bootID string
}

// newSequencer returns a sequencer that issues start, start+1, ... for the
// given boot id.
//
// The caller starts from spool.LastSequence()+1 when a spool is configured, so
// that an agent restart continues the numbering instead of reissuing numbers
// the host has already seen used for other events. With no spool there is
// nothing to recover from and numbering starts at 1.
//
// A spool that outlives a reboot keeps the counter climbing across boots.
// That is intended: the boot id already distinguishes the streams, and a
// counter that restarted at 1 while the spool still held events from the
// previous boot would make a cumulative ACK ambiguous -- an ACK for sequence
// 100 would cover events from two different boots at once.
func newSequencer(start uint64, bootID string) *sequencer {
	if start == 0 {
		start = 1
	}
	s := &sequencer{bootID: bootID}
	s.next.Store(start)
	return s
}

// assign numbers e and returns its sequence.
//
// An event that already carries a sequence is left alone. Renumbering one
// would break the (boot id, sequence) identity the host deduplicates on, and
// the only events that arrive pre-numbered are events that have been through
// here once already.
//
// The boot id is only filled in when the event does not have one. Events
// replayed from a spool that survived a reboot genuinely belong to the
// previous boot and must keep saying so; rewriting them would fold two boots'
// worth of evidence into one stream identity and hide the reboot itself.
func (s *sequencer) assign(e *event.Event) uint64 {
	if e == nil {
		return 0
	}
	if e.Sequence == 0 {
		// Add returns the new value, so the issued number is one less.
		e.Sequence = s.next.Add(1) - 1
	}
	if e.BootID == "" {
		e.BootID = s.bootID
	}
	return e.Sequence
}

// advanceTo lifts the counter so that the next assignment issues at least
// next, and reports the sequence that will now be issued.
//
// It never moves the counter backwards, which is the whole point: it exists
// for the case where the host turns out to be ahead of this agent's numbering
// for the current boot id -- the agent's spool was reset, rotated or lost
// while the host kept its deduplication watermark for the same boot. Numbering
// on from the host's position is what keeps a cumulative ACK meaningful, since
// the host would otherwise suppress everything we issued under numbers it
// already holds. See sender.adoptHostPosition.
//
// The gap this opens in the agent's own numbering is not a lost-event gap and
// the host does not read it as one: its watermark already covers everything
// below the new start.
func (s *sequencer) advanceTo(next uint64) uint64 {
	if next == 0 {
		next = 1
	}
	for {
		cur := s.next.Load()
		if next <= cur {
			return cur
		}
		if s.next.CompareAndSwap(cur, next) {
			return next
		}
	}
}

// peek reports the sequence the next assignment will issue, without consuming
// it. It exists for diagnostics and tests; the pipeline itself never needs to
// look ahead.
func (s *sequencer) peek() uint64 { return s.next.Load() }
