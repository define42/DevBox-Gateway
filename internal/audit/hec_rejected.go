package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// rejectedRecords is an append-only JSON Lines file of complete HEC envelopes
// the collector refused as invalid. It sits beside the delivery spool, which
// ignores it, and holds each envelope byte-for-byte so an operator can inspect
// and resubmit it. A crash before the spool checkpoint advances can append the
// same envelope twice; it never loses one.
type rejectedRecords struct {
	path string
}

// append syncs the record, and the directory entry of a newly created file,
// before returning.
func (r rejectedRecords) append(record []byte) error {
	_, err := os.Lstat(r.path)
	created := errors.Is(err, fs.ErrNotExist)
	file, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o640) // #nosec G302,G304 -- fixed filename under the operator-configured spool directory; group-readable like the audit file
	if err != nil {
		return fmt.Errorf("open rejected audit records %q: %w", r.path, err)
	}
	line := make([]byte, 0, len(record)+1)
	line = append(append(line, record...), '\n')
	_, writeErr := file.Write(line)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return fmt.Errorf("write rejected audit records %q: %w", r.path, err)
	}
	if created {
		return syncAuditDirectory(filepath.Dir(r.path))
	}
	return nil
}
