package virt

import "testing"

func TestPrintProgressUnknownTotal(t *testing.T) {
	// When total is unknown (e.g. response has no Content-Length), the
	// progress reporter should still execute without panicking.
	pr := &progressReader{total: 0, downloaded: 1234}
	pr.printProgress()
}

func TestPrintProgressKnownTotal(t *testing.T) {
	pr := &progressReader{total: 100, downloaded: 50}
	pr.printProgress()
}
