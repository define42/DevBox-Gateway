package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"libvirt.org/go/libvirt"
)

// sendStreamWithContext owns cancellation until all send/finish/abort calls
// have returned. The caller may free the stream only after this function exits.
// Abort must run concurrently with SendAll to interrupt a blocked libvirt send.
func sendStreamWithContext(ctx context.Context, stream *libvirt.Stream, chunks func(*libvirt.Stream, int) ([]byte, error)) error {
	abort := sync.OnceFunc(func() { _ = stream.Abort() })
	aborted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(aborted)
		abort()
	})
	defer func() {
		if !stop() {
			<-aborted
		}
	}()

	next := func(s *libvirt.Stream, size int) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := chunks(s, size)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return data, err
	}
	if err := stream.SendAll(next); err != nil {
		abort()
		return fmt.Errorf("stream send: %w", errors.Join(err, ctx.Err()))
	}
	if err := ctx.Err(); err != nil {
		abort()
		return err
	}
	if err := stream.Finish(); err != nil {
		abort()
		return fmt.Errorf("stream finish: %w", errors.Join(err, ctx.Err()))
	}
	return ctx.Err()
}
