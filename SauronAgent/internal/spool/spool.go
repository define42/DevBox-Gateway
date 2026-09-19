// Package spool implements SauronAgent's disk-backed event spool.
//
// The spool is what turns "the collector is unreachable" from data loss into a
// delay. Events are appended to it after a sequence number has been assigned
// and before they are sent, and they are discarded only when the host has
// acknowledged them:
//
//	normalize -> assign sequence -> Append -> send -> ACK -> Ack
//
// Delivery is at-least-once by construction. After a crash the spool replays
// from the last durable checkpoint, so a few already-delivered events may be
// sent again; the host deduplicates on (source CID, boot ID, sequence). That
// asymmetry is deliberate and runs through every decision in this package: a
// duplicate event is a nuisance, a missing event is a blind spot in a security
// audit trail. Wherever the spool cannot keep data -- the size cap is reached,
// or a file turns out to be corrupt -- the loss is counted and reported
// through DrainDropped so the agent can emit an event about its own failure
// instead of quietly forgetting.
package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/metrics"
)

const (
	defaultMaxSize     = 1 << 30 // 1 GiB
	defaultSegmentSize = 16 << 20

	checkpointName = "checkpoint"
	checkpointTemp = "checkpoint.tmp"
	checkpointSize = 16

	// The spool holds the guest's security events before the host has them.
	// Anything readable here is evidence an intruder would like to read or
	// edit, so the directory and its files are owner-only.
	dirMode  = 0o700
	fileMode = 0o600
)

// checkpointMagic identifies the acknowledgement checkpoint file.
var checkpointMagic = [4]byte{'S', 'C', 'K', 'P'}

// errClosed is returned by every method once the spool has been closed.
var errClosed = errors.New("spool: closed")

// Options configures a Spool.
type Options struct {
	// Dir is the spool directory. It is created if it does not exist.
	Dir string

	// MaxSize caps the total size of the retained segments. When appending
	// would exceed it the oldest segment is discarded and the loss is
	// recorded for DrainDropped; the alternative, filling the guest's disk,
	// takes the whole agent down and loses everything instead of the oldest
	// part of a backlog.
	MaxSize int64

	// SegmentSize is the size at which a new segment file is started.
	// Segments are the unit of deletion, both on acknowledgement and when
	// MaxSize is reached, so this is also the granularity of both.
	SegmentSize int64

	// SyncOnWrite fsyncs the segment on every Append. See the Spool godoc for
	// what it does and does not buy.
	SyncOnWrite bool

	// SyncInterval fsyncs at most this often when SyncOnWrite is false. The
	// caller is expected to drive this by calling Sync on a ticker; Append
	// also honours it so that a spool which is being written but never synced
	// by its owner still reaches the disk.
	SyncInterval time.Duration

	// Metrics, when set, receives spool_bytes, spool_events and the dropped
	// event counter.
	Metrics *metrics.Agent

	// Logger, when set, receives recovery and data-loss diagnostics.
	Logger *slog.Logger
}

// Spool is a durable, append-only log of events awaiting acknowledgement.
//
// # Durability
//
// With SyncOnWrite the spool survives a guest power loss: Append returns only
// once the record is on the disk. Without it, Append returns once the record
// has been handed to the kernel, and the spool survives an agent crash -- the
// page cache does not care that the process died -- but a power loss or a
// hypervisor kill can lose everything appended since the last Sync, which is
// at most SyncInterval worth of events. That is the whole of the trade: one
// fsync per event costs an order of magnitude in throughput, and an agent that
// cannot keep up with the audit stream drops events at the queue instead.
// SyncOnWrite is therefore the right default only where the audit trail must
// survive the machine being cut off at the wall.
//
// # Reading
//
// Next is a read from the durable log starting at FirstUnacked, and it is
// idempotent: calling it twice without an intervening Ack returns the same
// events. Nothing is consumed by reading, because a read that consumed would
// have to assume the send that followed it succeeded. The sender tracks what
// it has in flight; only Ack advances the spool, and only a host ACK justifies
// an Ack. After a reconnect the sender simply starts again from Next, which is
// exactly the at-least-once replay the protocol expects.
//
// All methods are safe for concurrent use. They serialise on one mutex, which
// includes the disk reads Next and Ack perform, so an Append can wait behind a
// read of the backlog; the audit reader never calls into the spool directly
// for that reason (see DESIGN.md section 39).
type Spool struct {
	mu   sync.Mutex
	opts Options
	log  *slog.Logger

	// segs is ordered by base sequence. The last element is the append
	// target, and w is its open write handle.
	segs []*segment
	w    *os.File

	lastSeq      uint64
	ackedThrough uint64
	firstPending uint64
	pending      int
	bytes        int64

	// ackedInFirst and ackOffset are a cursor into segs[0]: how many of its
	// records are covered by the checkpoint and where they end. They let Ack
	// account for a partially acknowledged segment by scanning forward only
	// over records it has not already counted, so acknowledging a whole
	// segment costs one pass over it however many ACKs it took.
	ackedInFirst int
	ackOffset    int64

	dropped     uint64
	droppedLow  uint64
	droppedHigh uint64

	lastSync time.Time
	dirty    bool
	closed   bool

	buf []byte
}

// Open prepares the spool directory for use and recovers whatever the previous
// run left behind.
//
// Recovery never refuses to start. A torn record at the end of a segment is
// the normal result of a crash during an append and is truncated away; a
// corrupt record in the middle of a segment is evidence loss and is counted
// for DrainDropped; a missing or damaged checkpoint falls back to replaying
// every retained record. An agent that will not start because its spool is
// damaged is an agent that reports nothing at all, which is the one outcome
// worse than duplicate events.
func Open(opts Options) (*Spool, error) {
	if opts.Dir == "" {
		return nil, errors.New("spool: Dir must be set")
	}
	if opts.MaxSize <= 0 {
		opts.MaxSize = defaultMaxSize
	}
	if opts.SegmentSize <= 0 {
		opts.SegmentSize = defaultSegmentSize
	}
	if opts.SegmentSize > opts.MaxSize {
		// Segments are the unit of eviction: a segment larger than the cap
		// could never be evicted without emptying the spool completely.
		opts.SegmentSize = opts.MaxSize
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(opts.Dir, dirMode); err != nil {
		return nil, fmt.Errorf("spool: creating %s: %w", opts.Dir, err)
	}

	s := &Spool{opts: opts, log: log, lastSync: time.Now()}
	if err := s.recover(); err != nil {
		return nil, err
	}
	return s, nil
}

// recover rebuilds the in-memory state from the directory contents.
func (s *Spool) recover() error {
	entries, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return fmt.Errorf("spool: reading %s: %w", s.opts.Dir, err)
	}

	var (
		repaired  int
		truncated int64
	)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		nameBase, err := parseSegmentName(e.Name())
		if err != nil {
			continue
		}
		path := filepath.Join(s.opts.Dir, e.Name())
		sg, st, err := scanSegment(path, nameBase)
		if err != nil {
			return fmt.Errorf("spool: scanning %s: %w", path, err)
		}
		if st.skipped > 0 {
			repaired++
			s.recordLoss(st.skipped, st.gapLow, st.gapHigh, "corrupt records in spool segment", path)
		}
		truncated += st.torn
		if st.count == 0 {
			// A segment with nothing readable in it is either a file created
			// just before a crash or one that was destroyed entirely. Either
			// way it can only get in the way of the next append.
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("spool: removing empty segment %s: %w", path, err)
			}
			continue
		}
		s.segs = append(s.segs, sg)
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].base < s.segs[j].base })

	if n := len(s.segs); n > 0 {
		s.lastSeq = s.segs[n-1].last
	}

	// Without a usable checkpoint everything still on disk is replayed:
	// duplicates are safe, gaps are not.
	if acked, ok := s.readCheckpoint(); ok {
		s.ackedThrough = acked
		if acked > s.lastSeq {
			// The checkpoint outlived the data it refers to, because the
			// acknowledged segments were deleted. It still has to be honoured
			// for LastSequence, or a restart would reissue sequence numbers
			// the host has already seen used for other events.
			s.lastSeq = acked
		}
	}

	if err := s.dropAckedSegments(); err != nil {
		return err
	}
	if err := s.advanceAckCursor(); err != nil {
		return err
	}
	s.recount()

	if n := len(s.segs); n > 0 {
		last := s.segs[n-1]
		f, err := os.OpenFile(last.path, os.O_WRONLY|os.O_APPEND, fileMode)
		if err != nil {
			return fmt.Errorf("spool: opening %s for append: %w", last.path, err)
		}
		s.w = f
	}
	if err := s.enforceMaxSize(); err != nil {
		return err
	}
	s.publishMetrics()

	if len(s.segs) > 0 || repaired > 0 || truncated > 0 {
		s.log.Info("spool recovered",
			"dir", s.opts.Dir,
			"segments", len(s.segs),
			"pending", s.pending,
			"bytes", s.bytes,
			"last_sequence", s.lastSeq,
			"first_unacked", s.firstUnacked(),
			"segments_with_corruption", repaired,
			"truncated_bytes", truncated)
	}
	return nil
}

// Append durably records an event that has already been assigned a sequence.
//
// The sequence must be greater than LastSequence. A sender that restarts must
// therefore resume from LastSequence()+1 rather than from 1, which is what
// keeps sequence numbers from going backwards within a boot and what keeps the
// records in a segment ordered. An out-of-order sequence is refused rather
// than stored, because a spool whose ordering cannot be trusted turns a
// cumulative ACK into silent data loss.
//
// Append fails visibly. An error from encoding the event or from the write
// itself means nothing was stored and the caller still owns the event. An
// error from the durability step that follows -- the fsync, or reclaiming
// space for the record -- means the record may well be on disk but the
// guarantee the caller asked for was not met, which is equally something the
// agent has to report rather than assume away.
func (s *Spool) Append(e *event.Event) error {
	if e == nil {
		return errors.New("spool: nil event")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	if e.Sequence <= s.lastSeq {
		return fmt.Errorf("spool: sequence %d is not greater than the last appended sequence %d",
			e.Sequence, s.lastSeq)
	}

	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("spool: encoding event %d: %w", e.Sequence, err)
	}
	if len(payload) > maxRecordSize {
		return fmt.Errorf("spool: event %d encodes to %d bytes, over the %d byte record limit",
			e.Sequence, len(payload), maxRecordSize)
	}
	recLen := int64(recordHeaderSize + len(payload))

	if s.w == nil || (s.active().count > 0 && s.active().size+recLen > s.opts.SegmentSize) {
		if err := s.roll(e.Sequence); err != nil {
			return err
		}
	}

	s.buf = encodeRecord(s.buf[:0], payload)
	n, err := s.w.Write(s.buf)
	if err != nil {
		// A short write leaves a torn record. Recovery truncates it, but the
		// in-memory size has to reflect what actually reached the file or
		// every later append would be placed from a wrong offset.
		if size, serr := s.w.Seek(0, io.SeekEnd); serr == nil {
			s.active().size = size
			s.recount()
			s.publishMetrics()
		}
		return fmt.Errorf("spool: writing event %d (%d of %d bytes): %w", e.Sequence, n, len(s.buf), err)
	}

	sg := s.active()
	if sg.count == 0 {
		sg.base = e.Sequence
	}
	sg.count++
	sg.last = e.Sequence
	sg.size += recLen
	s.lastSeq = e.Sequence
	if s.firstPending == 0 {
		s.firstPending = e.Sequence
	}
	s.dirty = true
	s.recount()

	if err := s.maybeSync(); err != nil {
		return err
	}
	if err := s.enforceMaxSize(); err != nil {
		return err
	}
	s.publishMetrics()
	return nil
}

// Next returns up to max unacknowledged events in sequence order.
//
// It does not consume them: the same events are returned again until an Ack
// covers them. See the Spool godoc for why.
//
// A non-nil error means the backlog could not be read; nothing has been lost
// and the same call can be retried.
func (s *Spool) Next(max int) ([]*event.Event, error) {
	return s.NextAfter(0, max)
}

// NextAfter returns up to max unacknowledged events whose sequences exceed
// through. It lets a sender advance its session cursor past events already
// sent or skipped without consuming them: Next still replays all retained
// events after a reconnect, and only Ack releases durable records.
func (s *Spool) NextAfter(through uint64, max int) ([]*event.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errClosed
	}
	if max <= 0 || s.pending == 0 || through >= s.lastSeq {
		return nil, nil
	}

	want := max
	if want > s.pending {
		want = s.pending
	}
	out := make([]*event.Event, 0, want)
	from := s.firstPending

	for i, sg := range s.segs {
		if len(out) >= max {
			break
		}
		if sg.count == 0 || sg.last < from || sg.last <= through {
			continue
		}
		start := int64(0)
		if i == 0 {
			// Everything before the acknowledgement cursor is acknowledged,
			// so there is no reason to parse it again.
			start = s.ackOffset
		}
		var (
			bad             int
			badLow, badHigh uint64
		)
		st, err := sg.walk(start, func(seq uint64, payload []byte, _ int64) bool {
			if seq < from {
				return true
			}
			var ev event.Event
			if err := json.Unmarshal(payload, &ev); err != nil {
				// The checksum matched, so this is not disk rot: the payload
				// was replaced by something that is not an event. Skipping it
				// keeps the rest of the backlog deliverable, where failing the
				// read would let one record wedge the sender for good.
				bad++
				if badLow == 0 {
					badLow = seq
				}
				badHigh = seq
				return len(out) < max
			}
			if seq <= through {
				return true
			}
			out = append(out, &ev)
			return len(out) < max
		})
		if err != nil {
			return nil, fmt.Errorf("spool: reading %s: %w", sg.path, err)
		}
		s.reportNewDamage(sg, st)
		if bad > sg.undecodable {
			s.recordLoss(bad-sg.undecodable, badLow, badHigh,
				"records in the spool are not decodable events", sg.path)
			sg.undecodable = bad
		}
	}
	return out, nil
}

// Ack discards every event up to and including seq.
//
// The acknowledgement is recorded in a checkpoint file before any data is
// deleted, and the checkpoint is written atomically so that a crash leaves
// either the old position or the new one and never a half-written number. An
// acknowledgement of a sequence that is already covered, or of anything below
// the current position, is a no-op; an acknowledgement beyond the last
// appended event is treated as covering everything the spool holds, since the
// host cannot have acknowledged what was never sent to it.
//
// If the checkpoint cannot be written the error is returned but the data is
// still discarded: the host has the events, and the worst a stale checkpoint
// can cause is a replay of already-delivered events after a restart.
func (s *Spool) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	if seq == 0 || seq <= s.ackedThrough {
		return nil
	}
	if seq > s.lastSeq {
		seq = s.lastSeq
	}
	if seq <= s.ackedThrough {
		return nil
	}
	s.ackedThrough = seq

	cpErr := s.writeCheckpoint()
	if cpErr != nil {
		s.log.Error("spool checkpoint not written; acknowledged events may be replayed after a restart",
			"error", cpErr, "acked_through", seq)
	}

	if err := s.dropAckedSegments(); err != nil {
		return err
	}
	if err := s.advanceAckCursor(); err != nil {
		return err
	}
	s.recount()
	s.publishMetrics()
	return cpErr
}

// LastSequence is the highest sequence ever appended, surviving restart.
//
// It is recovered from the segments on disk and from the acknowledgement
// checkpoint, so it does not go backwards when the spool is emptied by
// acknowledgements either.
func (s *Spool) LastSequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

// FirstUnacked is the lowest sequence still held. When nothing is held it is
// the sequence the next appended event must exceed, i.e. LastSequence()+1.
func (s *Spool) FirstUnacked() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firstUnacked()
}

// PendingCount is the number of events held but not yet acknowledged.
func (s *Spool) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

// Bytes is the total size of the retained segments on disk.
func (s *Spool) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// DrainDropped reports data discarded because the spool hit MaxSize, and data
// that could not be read back because a segment was corrupt, which loses
// evidence in exactly the same way. It returns the number of events lost and
// the sequence range they fell in, and clears the accounting so each loss is
// reported once.
//
// ok is false when nothing has been lost since the last call.
func (s *Spool) DrainDropped() (dropped uint64, firstMissing, lastMissing uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropped == 0 {
		return 0, 0, 0, false
	}
	dropped, firstMissing, lastMissing = s.dropped, s.droppedLow, s.droppedHigh
	s.dropped, s.droppedLow, s.droppedHigh = 0, 0, 0
	return dropped, firstMissing, lastMissing, true
}

// Sync flushes appended records to the disk. It is a no-op when nothing has
// been appended since the last sync.
func (s *Spool) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	return s.sync()
}

// Close syncs and closes the spool. It is idempotent.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.sync()
	if s.w != nil {
		if cerr := s.w.Close(); err == nil {
			err = cerr
		}
		s.w = nil
	}
	return err
}

// active returns the segment appends go to.
func (s *Spool) active() *segment { return s.segs[len(s.segs)-1] }

// firstUnacked reports the lowest sequence still held; see FirstUnacked.
func (s *Spool) firstUnacked() uint64 {
	if s.pending > 0 && s.firstPending > 0 {
		return s.firstPending
	}
	return s.lastSeq + 1
}

// roll closes the current segment and starts one named for seq.
func (s *Spool) roll(seq uint64) error {
	if s.w != nil {
		if err := s.sync(); err != nil {
			return err
		}
		if err := s.w.Close(); err != nil {
			return fmt.Errorf("spool: closing segment %s: %w", s.active().path, err)
		}
		s.w = nil
	}
	path := filepath.Join(s.opts.Dir, segmentName(seq))
	// O_EXCL: a name collision would mean either a sequence that went
	// backwards or another writer in the spool directory, and appending to
	// the file anyway would interleave two streams of evidence.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, fileMode)
	if err != nil {
		return fmt.Errorf("spool: creating segment %s: %w", path, err)
	}
	s.w = f
	s.segs = append(s.segs, &segment{path: path, base: seq})
	if err := syncDir(s.opts.Dir); err != nil {
		return err
	}
	return nil
}

// maybeSync applies the configured durability policy after an append.
func (s *Spool) maybeSync() error {
	if s.opts.SyncOnWrite {
		return s.sync()
	}
	if s.opts.SyncInterval > 0 && time.Since(s.lastSync) >= s.opts.SyncInterval {
		return s.sync()
	}
	return nil
}

func (s *Spool) sync() error {
	if s.w == nil || !s.dirty {
		s.lastSync = time.Now()
		return nil
	}
	if err := s.w.Sync(); err != nil {
		return fmt.Errorf("spool: syncing %s: %w", s.active().path, err)
	}
	s.dirty = false
	s.lastSync = time.Now()
	return nil
}

// dropAckedSegments deletes every segment the checkpoint covers entirely.
func (s *Spool) dropAckedSegments() error {
	removed := false
	for len(s.segs) > 0 && s.segs[0].last <= s.ackedThrough {
		sg := s.segs[0]
		if len(s.segs) == 1 && s.w != nil {
			if err := s.w.Close(); err != nil {
				return fmt.Errorf("spool: closing segment %s: %w", sg.path, err)
			}
			s.w = nil
			s.dirty = false
		}
		if err := os.Remove(sg.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("spool: removing acknowledged segment %s: %w", sg.path, err)
		}
		s.segs = s.segs[1:]
		s.ackedInFirst, s.ackOffset = 0, 0
		s.firstPending = 0
		removed = true
	}
	if !removed {
		return nil
	}
	return syncDir(s.opts.Dir)
}

// advanceAckCursor counts the acknowledged records at the front of the oldest
// retained segment and finds the first record that is still outstanding.
func (s *Spool) advanceAckCursor() error {
	if len(s.segs) == 0 {
		s.firstPending = 0
		s.ackedInFirst, s.ackOffset = 0, 0
		return nil
	}
	sg := s.segs[0]
	if sg.base > s.ackedThrough {
		// Nothing in this segment is acknowledged.
		s.ackedInFirst, s.ackOffset = 0, 0
		s.firstPending = sg.base
		return nil
	}

	var (
		acked   int
		off     = s.ackOffset
		pending uint64
	)
	st, err := sg.walk(s.ackOffset, func(seq uint64, _ []byte, end int64) bool {
		if seq > s.ackedThrough {
			pending = seq
			return false
		}
		acked++
		off = end
		return true
	})
	if err != nil {
		return fmt.Errorf("spool: reading %s: %w", sg.path, err)
	}
	s.reportNewDamage(sg, st)
	s.ackedInFirst += acked
	s.ackOffset = off
	if pending == 0 {
		// Every record read was acknowledged even though the segment's
		// recorded last sequence said otherwise; treat the segment as spent
		// rather than pretending there is something to send.
		pending = sg.last + 1
		if s.ackedInFirst > sg.count {
			s.ackedInFirst = sg.count
		}
	}
	s.firstPending = pending
	return nil
}

// enforceMaxSize discards the oldest segments until the spool fits.
//
// The newest segment is never discarded: it is the one being appended to, and
// dropping the event that has just been accepted would report a loss the
// caller could have avoided by not appending at all.
func (s *Spool) enforceMaxSize() error {
	for s.bytes > s.opts.MaxSize && len(s.segs) > 1 {
		sg := s.segs[0]
		lost := sg.count - s.ackedInFirst
		if lost > 0 {
			low := s.firstPending
			if low == 0 || low < sg.base {
				low = sg.base
			}
			s.recordLoss(lost, low, sg.last, "spool full, oldest segment discarded", sg.path)
		}
		if err := os.Remove(sg.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("spool: removing segment %s: %w", sg.path, err)
		}
		s.segs = s.segs[1:]
		s.ackedInFirst, s.ackOffset = 0, 0
		// Acknowledged segments are deleted by Ack, so every segment after
		// the oldest is entirely outstanding.
		s.firstPending = s.segs[0].base
		s.recount()
		if err := syncDir(s.opts.Dir); err != nil {
			return err
		}
	}
	return nil
}

// recordLoss accounts for events that will never be delivered.
func (s *Spool) recordLoss(count int, low, high uint64, reason, path string) {
	if count <= 0 {
		return
	}
	s.dropped += uint64(count)
	if s.droppedLow == 0 || (low > 0 && low < s.droppedLow) {
		s.droppedLow = low
	}
	if high > s.droppedHigh {
		s.droppedHigh = high
	}
	if s.opts.Metrics != nil {
		s.opts.Metrics.EventsDropped.Add(uint64(count))
	}
	s.log.Warn("spool discarded events",
		"reason", reason, "path", path, "events", count,
		"first_missing_sequence", low, "last_missing_sequence", high)
}

// reportNewDamage accounts for corruption a read found that recovery had not
// already reported, so that tampering with a segment at runtime is visible but
// a hole that is already known is not counted again on every read.
func (s *Spool) reportNewDamage(sg *segment, st walkStats) {
	if st.skipped <= sg.reported {
		return
	}
	newly := st.skipped - sg.reported
	sg.reported = st.skipped
	s.recordLoss(newly, st.gapLow, st.gapHigh, "corrupt records in spool segment", sg.path)
}

// recount refreshes the derived totals after a structural change. The segment
// list is short (MaxSize/SegmentSize entries), so recomputing is cheaper than
// keeping several counters in step by hand.
func (s *Spool) recount() {
	var (
		bytes int64
		count int
	)
	for _, sg := range s.segs {
		bytes += sg.size
		count += sg.count
	}
	s.bytes = bytes
	s.pending = count - s.ackedInFirst
	if s.pending < 0 {
		s.pending = 0
	}
	if s.pending == 0 {
		s.firstPending = 0
	}
}

func (s *Spool) publishMetrics() {
	if s.opts.Metrics == nil {
		return
	}
	s.opts.Metrics.SpoolBytes.Store(s.bytes)
	s.opts.Metrics.SpoolEvents.Store(int64(s.pending))
}

// readCheckpoint returns the acknowledged sequence, or ok=false when there is
// no usable checkpoint. A damaged checkpoint is not an error: replaying from
// the oldest retained record costs duplicates, while trusting a corrupt number
// would skip past events that were never delivered.
func (s *Spool) readCheckpoint() (uint64, bool) {
	path := filepath.Join(s.opts.Dir, checkpointName)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Warn("spool checkpoint unreadable, replaying from the oldest retained record",
				"path", path, "error", err)
		}
		return 0, false
	}
	if len(data) != checkpointSize ||
		string(data[0:4]) != string(checkpointMagic[:]) ||
		crc32.Checksum(data[4:12], crcTable) != binary.BigEndian.Uint32(data[12:16]) {
		s.log.Warn("spool checkpoint corrupt, replaying from the oldest retained record", "path", path)
		return 0, false
	}
	return binary.BigEndian.Uint64(data[4:12]), true
}

// writeCheckpoint records the acknowledged sequence atomically: a temporary
// file is written and fsynced, renamed over the old checkpoint, and the
// directory is fsynced so the rename itself survives a power loss.
func (s *Spool) writeCheckpoint() error {
	var buf [checkpointSize]byte
	copy(buf[0:4], checkpointMagic[:])
	binary.BigEndian.PutUint64(buf[4:12], s.ackedThrough)
	binary.BigEndian.PutUint32(buf[12:16], crc32.Checksum(buf[4:12], crcTable))

	tmp := filepath.Join(s.opts.Dir, checkpointTemp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("spool: creating %s: %w", tmp, err)
	}
	if _, err := f.Write(buf[:]); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("spool: writing %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("spool: syncing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("spool: closing %s: %w", tmp, err)
	}
	final := filepath.Join(s.opts.Dir, checkpointName)
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("spool: renaming %s: %w", tmp, err)
	}
	return syncDir(s.opts.Dir)
}

// syncDir fsyncs a directory so that creations, renames and removals in it are
// durable. Without it a crash can resurrect a deleted segment or lose a
// renamed checkpoint even though every file's own data was synced.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("spool: opening %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("spool: syncing %s: %w", dir, err)
	}
	return nil
}
