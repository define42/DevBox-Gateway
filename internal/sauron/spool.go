package sauron

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	// Guest events carry command lines, file paths and user names from every
	// VM: readable by the gateway and a log group only, like the event log.
	spoolDirMode  fs.FileMode = 0o750
	spoolFileMode fs.FileMode = 0o640

	// spoolSegmentSize is the size at which the spool starts a new segment
	// file. Disk space is reclaimed a whole segment at a time, once the
	// forwarder has delivered everything in it.
	spoolSegmentSize int64 = 64 << 20

	spoolSegmentDigits  = 20
	spoolSegmentSuffix  = ".jsonl"
	spoolCheckpointName = "checkpoint"

	// spoolTailScanChunk is how much of a segment is read at a time when
	// looking for the end of its last complete record after a crash.
	spoolTailScanChunk = 64 << 10
)

var (
	errSpoolFull   = errors.New("sauron spool is full")
	errSpoolClosed = errors.New("sauron spool is closed")
)

// spoolPosition is a place in the spool: a segment and a byte offset in it.
type spoolPosition struct {
	Segment uint64 `json:"segment"`
	Offset  int64  `json:"offset"`
}

func (p spoolPosition) before(q spoolPosition) bool {
	return p.Segment < q.Segment || (p.Segment == q.Segment && p.Offset < q.Offset)
}

func (p spoolPosition) String() string {
	return fmt.Sprintf("segment %d offset %d", p.Segment, p.Offset)
}

// spoolSegment is one segment file and its size.
type spoolSegment struct {
	id   uint64
	size int64
}

// spoolRecord is one record read back from the spool.
type spoolRecord struct {
	data []byte
	// end is the position just after the record: delivering it moves the
	// checkpoint there.
	end spoolPosition
}

// spool is the gateway's durable queue of guest events on their way to
// Splunk. The collector acknowledges an event to its guest -- which then
// deletes its own copy -- once Append has returned, so from then on the spool
// holds the only copy. It therefore survives gateway restarts, and holds
// events for as long as Splunk is unreachable, up to its size limit.
//
// On disk it is a directory of append-only segment files, each holding
// newline-terminated JSON records named by an increasing number, plus a
// checkpoint file recording how far the forwarder has delivered. A segment is
// deleted once the checkpoint has moved past it.
type spool struct {
	dir         string
	maxBytes    int64
	segmentSize int64

	mu         sync.Mutex
	segments   []spoolSegment // oldest first; the last one is being appended to
	active     *os.File       // the last segment, open for appending
	total      int64          // bytes in all segment files
	appended   uint64         // records appended so far
	synced     uint64         // records known to be on stable storage
	committed  spoolPosition  // everything before it is on stable storage
	checkpoint spoolPosition  // latest successfully recorded delivery position
	full       bool           // the last Append was refused for lack of space
	closed     bool

	// syncMu serializes fsyncs. A writer that finds its record already
	// covered by another writer's fsync returns without one of its own, which
	// is what lets concurrent guests share them.
	syncMu sync.Mutex

	// ready is signalled whenever committed advances.
	ready chan struct{}
}

// openSpool opens or creates the spool in dir. A record torn by a crash --
// never acknowledged to its guest, which still holds it -- is discarded.
func openSpool(dir string, maxBytes int64) (*spool, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("sauron spool size limit must be positive, got %d", maxBytes)
	}
	if err := os.MkdirAll(dir, spoolDirMode); err != nil {
		return nil, fmt.Errorf("create sauron spool directory %s: %w", dir, err)
	}
	segments, err := listSpoolSegments(dir)
	if err != nil {
		return nil, err
	}

	s := &spool{
		dir:         dir,
		maxBytes:    maxBytes,
		segmentSize: min(spoolSegmentSize, max(maxBytes/4, 1)),
		ready:       make(chan struct{}, 1),
	}
	if err := s.openSegments(segments); err != nil {
		return nil, err
	}
	for _, segment := range s.segments {
		s.total += segment.size
	}
	last := s.segments[len(s.segments)-1]
	s.committed = spoolPosition{Segment: last.id, Offset: last.size}
	s.checkpoint = s.loadCheckpoint()
	if err := s.removeDeliveredSegmentsLocked(); err != nil {
		log.Printf("sauron: %v", err)
	}
	return s, nil
}

// openSegments adopts the segments found on disk, repairing the last one's
// tail and opening it for appending, or starts the first segment.
func (s *spool) openSegments(segments []spoolSegment) error {
	if len(segments) == 0 {
		return s.createSegmentLocked(1)
	}
	last := &segments[len(segments)-1]
	size, err := repairSpoolTail(s.segmentPath(last.id), last.size)
	if err != nil {
		return err
	}
	last.size = size
	file, err := os.OpenFile(s.segmentPath(last.id), os.O_WRONLY|os.O_APPEND, spoolFileMode) // #nosec G304 -- segment path built from the operator-configured spool dir and a numeric id
	if err != nil {
		return fmt.Errorf("open sauron spool segment: %w", err)
	}
	s.segments = segments
	s.active = file
	return nil
}

func (s *spool) segmentPath(id uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%0*d%s", spoolSegmentDigits, id, spoolSegmentSuffix))
}

// listSpoolSegments returns the segment files in dir, oldest first.
func listSpoolSegments(dir string) ([]spoolSegment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read sauron spool directory %s: %w", dir, err)
	}
	var segments []spoolSegment
	for _, entry := range entries {
		name := entry.Name()
		digits, ok := strings.CutSuffix(name, spoolSegmentSuffix)
		if !ok || len(digits) != spoolSegmentDigits || !entry.Type().IsRegular() {
			continue
		}
		id, err := strconv.ParseUint(digits, 10, 64)
		if err != nil || id == 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat sauron spool segment %s: %w", name, err)
		}
		segments = append(segments, spoolSegment{id: id, size: info.Size()})
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].id < segments[j].id })
	return segments, nil
}

// repairSpoolTail truncates a segment after its last complete record and
// returns the resulting size.
func repairSpoolTail(path string, size int64) (int64, error) {
	if size == 0 {
		return 0, nil
	}
	file, err := os.OpenFile(path, os.O_RDWR, spoolFileMode) // #nosec G304 -- segment path built from the operator-configured spool dir and a numeric id
	if err != nil {
		return 0, fmt.Errorf("open sauron spool segment: %w", err)
	}
	defer func() { _ = file.Close() }()

	keep := int64(0)
	buffer := make([]byte, spoolTailScanChunk)
	for end := size; end > 0 && keep == 0; {
		start := max(end-spoolTailScanChunk, 0)
		chunk := buffer[:end-start]
		if _, err := file.ReadAt(chunk, start); err != nil {
			return 0, fmt.Errorf("read sauron spool segment: %w", err)
		}
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			keep = start + int64(i) + 1
		}
		end = start
	}
	if keep == size {
		return size, nil
	}
	log.Printf("sauron: discarding %d bytes of a spool record torn by a crash in %s; it was never acknowledged, so its guest sends it again", size-keep, path)
	if err := file.Truncate(keep); err != nil {
		return 0, fmt.Errorf("truncate torn sauron spool record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return 0, fmt.Errorf("sync sauron spool segment: %w", err)
	}
	return keep, nil
}

// loadCheckpoint returns where delivery resumes. A missing, unreadable or
// implausible checkpoint resumes at the oldest record: that delivers some
// events twice, where trusting a bad checkpoint could skip some for good.
func (s *spool) loadCheckpoint() spoolPosition {
	oldest := spoolPosition{Segment: s.segments[0].id}
	data, err := os.ReadFile(filepath.Join(s.dir, spoolCheckpointName))
	if errors.Is(err, fs.ErrNotExist) {
		return oldest
	}
	var position spoolPosition
	if err == nil {
		err = json.Unmarshal(data, &position)
	}
	if err != nil {
		log.Printf("sauron: spool checkpoint unreadable (%v); delivering every spooled event again", err)
		return oldest
	}
	if position.before(oldest) {
		return oldest
	}
	if err := s.validateCheckpointLocked(position); err != nil {
		log.Printf("sauron: spool checkpoint %s is invalid (%v); delivering every spooled event again", position, err)
		return oldest
	}
	return position
}

// validateCheckpointLocked accepts only boundaries of committed records in a
// known segment. A corrupt offset must never authorize deleting pending data.
func (s *spool) validateCheckpointLocked(position spoolPosition) error {
	if position.Offset < 0 || s.committed.before(position) {
		return errors.New("position lies outside committed data")
	}
	for _, segment := range s.segments {
		if segment.id != position.Segment {
			continue
		}
		if position.Offset > segment.size {
			return errors.New("offset exceeds segment size")
		}
		if position.Offset == 0 {
			return nil
		}
		return s.validateRecordBoundary(position)
	}
	return errors.New("segment is missing")
}

func (s *spool) validateRecordBoundary(position spoolPosition) error {
	file, err := os.Open(s.segmentPath(position.Segment))
	if err != nil {
		return fmt.Errorf("open checkpoint segment: %w", err)
	}
	defer func() { _ = file.Close() }()
	var previous [1]byte
	if _, err := file.ReadAt(previous[:], position.Offset-1); err != nil {
		return fmt.Errorf("read checkpoint boundary: %w", err)
	}
	if previous[0] != '\n' {
		return errors.New("offset does not end a record")
	}
	return nil
}

// Append durably adds one record. When it returns nil the record is on
// stable storage and the guest may be told so. record must not contain a
// newline; JSON encoding never produces one.
func (s *spool) Append(record []byte) error {
	line := make([]byte, 0, len(record)+1)
	line = append(append(line, record...), '\n')

	s.mu.Lock()
	generation, err := s.appendLocked(line)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.syncThrough(generation)
}

func (s *spool) appendLocked(line []byte) (uint64, error) {
	if s.closed {
		return 0, errSpoolClosed
	}
	size := int64(len(line))
	if err := s.ensureCapacityLocked(size); err != nil {
		return 0, err
	}

	last := &s.segments[len(s.segments)-1]
	if s.active == nil || (last.size > 0 && last.size+size > s.segmentSize) {
		if err := s.rotateLocked(); err != nil {
			return 0, err
		}
		last = &s.segments[len(s.segments)-1]
	}
	n, err := s.active.Write(line)
	if err != nil {
		if n > 0 {
			// A partial line would corrupt the record after it. Take it back;
			// the event is not acknowledged and its guest sends it again.
			err = errors.Join(err, s.active.Truncate(last.size))
		}
		return 0, fmt.Errorf("append to sauron spool: %w", err)
	}
	last.size += int64(n)
	s.total += int64(n)
	s.appended++
	return s.appended, nil
}

func (s *spool) ensureCapacityLocked(size int64) error {
	if size <= s.maxBytes && size > s.maxBytes-s.total {
		if err := s.reclaimDeliveredLocked(); err != nil {
			return err
		}
	}
	if size > s.maxBytes-s.total {
		if !s.full {
			s.full = true
			log.Printf("sauron: the splunk hec spool in %s is full (%d MiB); guest events are no longer acknowledged and wait in the guests' own spools until Splunk takes the backlog", s.dir, s.maxBytes>>20)
		}
		return errSpoolFull
	}
	if s.full {
		s.full = false
		log.Printf("sauron: the splunk hec spool has room again; acknowledging guest events")
	}
	return nil
}

// reclaimDeliveredLocked rotates a fully delivered active segment before the
// capacity check. Its empty successor is durable before any file is deleted,
// so a restart always preserves increasing segment IDs and pending records.
func (s *spool) reclaimDeliveredLocked() error {
	last := s.segments[len(s.segments)-1]
	if last.size > 0 && s.checkpoint == (spoolPosition{Segment: last.id, Offset: last.size}) {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	return s.removeDeliveredSegmentsLocked()
}

// rotateLocked makes the active segment durable, closes it, and starts the
// next one. Every record in the closed segment is then committed.
func (s *spool) rotateLocked() error {
	next := s.segments[len(s.segments)-1].id + 1
	if s.active != nil {
		if err := s.active.Sync(); err != nil {
			return fmt.Errorf("sync sauron spool segment: %w", err)
		}
		if err := s.active.Close(); err != nil {
			return fmt.Errorf("close sauron spool segment: %w", err)
		}
		s.active = nil
		s.synced = s.appended
	}
	if err := s.createSegmentLocked(next); err != nil {
		return err
	}
	s.advanceCommittedLocked(spoolPosition{Segment: next})
	return nil
}

func (s *spool) createSegmentLocked(id uint64) error {
	file, err := os.OpenFile(s.segmentPath(id), os.O_CREATE|os.O_WRONLY|os.O_APPEND, spoolFileMode) // #nosec G304 -- segment path built from the operator-configured spool dir and a numeric id
	if err != nil {
		return fmt.Errorf("create sauron spool segment: %w", err)
	}
	// The new directory entry must survive a power loss too, or the records
	// about to be acknowledged in it would vanish with it.
	if err := syncDir(s.dir); err != nil {
		_ = file.Close()
		return err
	}
	s.active = file
	s.segments = append(s.segments, spoolSegment{id: id})
	return nil
}

// syncThrough returns once the record numbered generation is on stable
// storage, issuing an fsync only if no other writer's fsync covered it.
func (s *spool) syncThrough(generation uint64) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	s.mu.Lock()
	if s.synced >= generation {
		s.mu.Unlock()
		return nil
	}
	file, target := s.active, s.appended
	last := s.segments[len(s.segments)-1]
	s.mu.Unlock()
	if file == nil {
		return errSpoolClosed
	}

	err := file.Sync()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if s.synced >= generation {
			// A rotation synced and closed the file while this fsync ran.
			return nil
		}
		return fmt.Errorf("sync sauron spool: %w", err)
	}
	if target > s.synced {
		s.synced = target
	}
	s.advanceCommittedLocked(spoolPosition{Segment: last.id, Offset: last.size})
	return nil
}

func (s *spool) advanceCommittedLocked(position spoolPosition) {
	if !s.committed.before(position) {
		return
	}
	s.committed = position
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// readBatch returns up to maxRecords committed records, and roughly up to
// maxBytes, starting at from. It returns nothing once from has caught up.
func (s *spool) readBatch(from spoolPosition, maxRecords, maxBytes int) ([]spoolRecord, error) {
	var records []spoolRecord
	size := 0
	position := from
	for len(records) < maxRecords && size < maxBytes {
		limit, next, ok := s.readableRange(position)
		if !ok {
			break
		}
		if position.Offset >= limit {
			if next == 0 {
				break
			}
			position = spoolPosition{Segment: next}
			continue
		}
		read, err := s.readSegment(position, limit, maxRecords-len(records), maxBytes-size)
		if err != nil {
			return records, err
		}
		if len(read) == 0 {
			break
		}
		for _, record := range read {
			size += len(record.data) + 1
		}
		records = append(records, read...)
		position = read[len(read)-1].end
	}
	return records, nil
}

// readableRange reports how far the segment at position may be read -- to
// its end once complete, to the commit point while it is being appended to
// -- and the id of the segment after it (0 for none). ok is false once
// position has reached the commit point.
func (s *spool) readableRange(position spoolPosition) (limit int64, next uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !position.before(s.committed) {
		return 0, 0, false
	}
	for i, segment := range s.segments {
		if segment.id < position.Segment {
			continue
		}
		if segment.id > position.Segment {
			return 0, segment.id, true
		}
		limit = segment.size
		if segment.id == s.committed.Segment {
			limit = s.committed.Offset
		}
		if i+1 < len(s.segments) {
			next = s.segments[i+1].id
		}
		return limit, next, true
	}
	return 0, 0, false
}

// readSegment reads whole records from one segment between position and
// limit, which always lies on a record boundary.
func (s *spool) readSegment(position spoolPosition, limit int64, maxRecords, maxBytes int) ([]spoolRecord, error) {
	file, err := os.Open(s.segmentPath(position.Segment))
	if err != nil {
		return nil, fmt.Errorf("open sauron spool segment: %w", err)
	}
	defer func() { _ = file.Close() }()

	reader := bufio.NewReader(io.NewSectionReader(file, position.Offset, limit-position.Offset))
	var records []spoolRecord
	offset, size := position.Offset, 0
	for len(records) < maxRecords && size < maxBytes {
		line, err := reader.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return records, fmt.Errorf("read sauron spool segment: %w", err)
		}
		offset += int64(len(line))
		size += len(line)
		records = append(records, spoolRecord{
			data: line[:len(line)-1],
			end:  spoolPosition{Segment: position.Segment, Offset: offset},
		})
	}
	return records, nil
}

// acknowledge records that everything before position has been delivered and
// deletes the segments that holds entirely. The checkpoint is replaced
// atomically but not fsynced: losing its latest update to a power cut only
// delivers some events twice.
func (s *spool) acknowledge(position spoolPosition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSpoolClosed
	}
	if position == s.checkpoint {
		return s.removeDeliveredSegmentsLocked()
	}
	if position.before(s.checkpoint) {
		return errors.New("sauron spool checkpoint cannot move backwards")
	}
	if err := s.validateCheckpointLocked(position); err != nil {
		return fmt.Errorf("invalid sauron spool checkpoint %s: %w", position, err)
	}
	data, err := json.Marshal(position)
	if err != nil {
		return fmt.Errorf("encode sauron spool checkpoint: %w", err)
	}
	temporary := filepath.Join(s.dir, spoolCheckpointName+".tmp")
	if err := os.WriteFile(temporary, data, spoolFileMode); err != nil {
		return fmt.Errorf("write sauron spool checkpoint: %w", err)
	}
	if err := os.Rename(temporary, filepath.Join(s.dir, spoolCheckpointName)); err != nil {
		return fmt.Errorf("replace sauron spool checkpoint: %w", err)
	}
	s.checkpoint = position
	return s.removeDeliveredSegmentsLocked()
}

// removeDeliveredSegmentsLocked deletes fully delivered segments, never the
// active one. Failed deletions still count toward the capacity limit.
func (s *spool) removeDeliveredSegmentsLocked() error {
	for len(s.segments) > 1 {
		segment := s.segments[0]
		if s.checkpoint.before(spoolPosition{Segment: segment.id, Offset: segment.size}) {
			break
		}
		if err := os.Remove(s.segmentPath(segment.id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("delete delivered spool segment: %w", err)
		}
		s.total -= segment.size
		s.segments = s.segments[1:]
	}
	return nil
}

// usage is the disk space the spool's segments take.
func (s *spool) usage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// Close makes every appended record durable and closes the spool.
func (s *spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.active == nil {
		return nil
	}
	file := s.active
	s.active = nil
	return errors.Join(file.Sync(), file.Close())
}

// syncDir makes changes to a directory's entries durable.
func syncDir(dir string) error {
	handle, err := os.Open(dir) // #nosec G304 -- the operator-configured spool dir
	if err != nil {
		return fmt.Errorf("open sauron spool directory: %w", err)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync sauron spool directory: %w", err)
	}
	return nil
}
