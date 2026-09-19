package spool

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"strings"
)

// Segment file layout. One record per spooled event:
//
//	+------------------+
//	| Magic "SREC"     | 4 bytes
//	+------------------+
//	| Payload length   | 4 bytes, big-endian
//	+------------------+
//	| CRC32C(payload)  | 4 bytes, big-endian
//	+------------------+
//	| Payload          | N bytes, the JSON-encoded event
//	+------------------+
//
// The magic is what makes recovery possible at all: after a crash or a
// corrupted write the reader has to find where the next record begins, and a
// length field alone gives it nothing to resynchronise on. The checksum is
// Castagnoli rather than IEEE because it has a hardware implementation on the
// amd64 and arm64 hosts this agent runs on, so verifying every record on
// startup costs almost nothing.
const recordHeaderSize = 12

// maxRecordSize bounds a single record's payload.
//
// The length is read from the file before the payload, so an unvalidated value
// would let a corrupted or tampered spool file dictate an allocation. The
// ceiling is deliberately larger than the protocol's default frame limit (1
// MiB) so that the spool is never the component that silently refuses an event
// the transport would have carried.
const maxRecordSize = 8 << 20

// segmentSuffix and segmentNameDigits give segments names whose lexical order
// is their sequence order, so the directory listing alone orders recovery
// without opening a single file.
const (
	segmentSuffix     = ".seg"
	segmentNameDigits = 20
)

var recordMagic = [4]byte{'S', 'R', 'E', 'C'}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// errNotSegment marks a directory entry that is not a spool segment.
var errNotSegment = errors.New("spool: not a segment file")

// segmentName returns the file name a segment beginning at seq is stored under.
func segmentName(seq uint64) string {
	return fmt.Sprintf("%0*d%s", segmentNameDigits, seq, segmentSuffix)
}

// parseSegmentName returns the first sequence encoded in a segment file name.
// Names that are not exactly the format segmentName produces are rejected
// rather than guessed at, so that an unrelated file dropped into the spool
// directory is never read as evidence.
func parseSegmentName(name string) (uint64, error) {
	digits, ok := strings.CutSuffix(name, segmentSuffix)
	if !ok || len(digits) != segmentNameDigits {
		return 0, errNotSegment
	}
	seq, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, errNotSegment
	}
	return seq, nil
}

// encodeRecord appends a complete record for payload to dst.
//
// Header and payload are built in one buffer so a record reaches the kernel in
// a single write: a torn record then requires a short write or a power loss,
// not merely an unlucky interleaving.
func encodeRecord(dst, payload []byte) []byte {
	var hdr [recordHeaderSize]byte
	copy(hdr[0:4], recordMagic[:])
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[8:12], crc32.Checksum(payload, crcTable))
	dst = append(dst, hdr[:]...)
	return append(dst, payload...)
}

// sequenceOf extracts only the sequence number from a stored payload.
//
// Recovery and acknowledgement need the sequence of every record but not the
// rest of the event, and decoding into the full model would allocate slices,
// maps and strings for data that is thrown away again immediately.
func sequenceOf(payload []byte) (uint64, error) {
	var hdr struct {
		Sequence uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(payload, &hdr); err != nil {
		return 0, err
	}
	return hdr.Sequence, nil
}

// walkStats reports what a pass over a segment found.
type walkStats struct {
	// count is the number of valid records the pass accepted.
	count int
	// validEnd is the offset just past the last valid record, which is where
	// a torn tail has to be cut back to.
	validEnd int64
	// skipped counts corrupt regions that were followed by a valid record,
	// i.e. evidence destroyed in the middle of the file. It is a lower bound:
	// one unreadable region may have held any number of records.
	skipped int
	// gapLow and gapHigh bound the sequence numbers those regions held, taken
	// from the surviving records on either side of them.
	gapLow  uint64
	gapHigh uint64
	// torn is the number of bytes after validEnd, i.e. a partially written
	// record at the end of the file. It is set by scanSegment, which is the
	// only caller that reads a segment to its end.
	torn int64
	// stopped reports that the callback ended the pass early, in which case
	// validEnd describes only the part of the file that was read.
	stopped bool
}

// walkRecords reads records sequentially from r, which must already be
// positioned at start, and calls fn for each valid one.
//
// The walk is the only place the spool interprets bytes it did not just write,
// so every field is validated before it is used: the length is checked against
// both maxRecordSize and the real file size before a buffer is sized from it,
// and a record only counts once its checksum and its sequence number agree
// with the header. Anything else is treated as damage, and the walk
// resynchronises by advancing a byte at a time until the next record start.
// That guarantees forward progress on any input, so a malformed file costs a
// bounded scan rather than a hang, an over-allocation or a panic.
//
// The payload handed to fn is reused between records and must not be retained.
func walkRecords(r io.Reader, start, size int64, fn func(seq uint64, payload []byte, end int64) bool) (walkStats, error) {
	st := walkStats{validEnd: start}
	br := bufio.NewReaderSize(r, 64<<10)

	off := start
	var prevSeq uint64
	var havePrev, inDamage bool
	var buf []byte

	for {
		hdr, err := br.Peek(recordHeaderSize)
		if err != nil {
			// Fewer than a header's worth of bytes are left: a clean end of
			// file, or a tail the caller will truncate.
			if errors.Is(err, io.EOF) {
				break
			}
			return st, err
		}

		length := int64(binary.BigEndian.Uint32(hdr[4:8]))
		crcWant := binary.BigEndian.Uint32(hdr[8:12])
		if string(hdr[0:4]) != string(recordMagic[:]) ||
			length == 0 || length > maxRecordSize ||
			off+recordHeaderSize+length > size {
			if _, err := br.Discard(1); err != nil {
				break
			}
			off++
			inDamage = true
			continue
		}
		if _, err := br.Discard(recordHeaderSize); err != nil {
			break
		}

		if int64(len(buf)) < length {
			buf = make([]byte, length)
		}
		payload := buf[:length]
		if _, err := io.ReadFull(br, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return st, err
		}
		end := off + recordHeaderSize + length

		seq, seqErr := uint64(0), error(nil)
		if crc32.Checksum(payload, crcTable) != crcWant {
			seqErr = errors.New("checksum mismatch")
		} else {
			seq, seqErr = sequenceOf(payload)
		}
		// Sequences must rise strictly within a segment. A file that says
		// otherwise has been damaged or edited, and honouring it would break
		// the ordering every reader of the spool depends on.
		if seqErr != nil || seq == 0 || (havePrev && seq <= prevSeq) {
			off = end
			inDamage = true
			continue
		}

		if inDamage {
			st.skipped++
			low := prevSeq + 1
			high := seq - 1
			if high < low {
				high = low
			}
			if st.gapLow == 0 {
				st.gapLow = low
			}
			st.gapHigh = high
			inDamage = false
		}

		st.count++
		st.validEnd = end
		prevSeq, havePrev = seq, true

		cont := fn(seq, payload, end)
		off = end
		if !cont {
			st.stopped = true
			break
		}
	}
	// Damage that runs to the end of the file is a torn tail, not a gap: it is
	// the expected shape of a crash during an append, and the record it holds
	// was never reported as durable to anyone.
	return st, nil
}

// segment is one append-only spool file.
type segment struct {
	path string
	// base and last are the lowest and highest sequence the file holds.
	base uint64
	last uint64
	// count and size describe the valid records only; bytes past size are a
	// tail that recovery has already cut off.
	count int
	size  int64
	// reported and undecodable are how much damage in this file has been
	// accounted for already -- corrupt regions and records that survive their
	// checksum but are not events -- so that a permanent hole is reported once
	// rather than on every read of the segment.
	reported    int
	undecodable int
}

// walk iterates the segment's records from byte offset start.
func (sg *segment) walk(start int64, fn func(seq uint64, payload []byte, end int64) bool) (walkStats, error) {
	f, err := os.Open(sg.path)
	if err != nil {
		return walkStats{validEnd: start}, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return walkStats{validEnd: start}, err
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return walkStats{validEnd: start}, err
		}
	}
	return walkRecords(f, start, fi.Size(), fn)
}

// scanSegment validates every record in path and repairs the file in place,
// returning the recovered segment and what the pass had to discard.
//
// nameBase is the sequence encoded in the file name; it is used only as a
// lower bound when reporting a gap that starts before the first surviving
// record, since the records that would have named it are gone.
func scanSegment(path string, nameBase uint64) (*segment, walkStats, error) {
	sg := &segment{path: path, base: nameBase}

	st, err := sg.walk(0, func(seq uint64, _ []byte, _ int64) bool {
		if sg.count == 0 {
			sg.base = seq
		}
		sg.count++
		sg.last = seq
		return true
	})
	if err != nil {
		return nil, st, err
	}
	sg.size = st.validEnd
	sg.reported = st.skipped
	if st.gapLow != 0 && st.gapLow < nameBase {
		st.gapLow = nameBase
	}
	if st.gapHigh < st.gapLow {
		st.gapHigh = st.gapLow
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, st, err
	}
	if fi.Size() > st.validEnd {
		st.torn = fi.Size() - st.validEnd
		if err := truncateSegment(path, st.validEnd); err != nil {
			return nil, st, err
		}
	}
	return sg, st, nil
}

// truncateSegment cuts a segment back to its last valid record boundary and
// makes that durable, so the next append lands on a clean boundary even if the
// agent is killed again before it syncs.
func truncateSegment(path string, size int64) error {
	if err := os.Truncate(path, size); err != nil {
		return fmt.Errorf("spool: truncating %s to %d bytes: %w", path, size, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, fileMode)
	if err != nil {
		return fmt.Errorf("spool: reopening %s after truncation: %w", path, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("spool: syncing %s after truncation: %w", path, err)
	}
	return nil
}
