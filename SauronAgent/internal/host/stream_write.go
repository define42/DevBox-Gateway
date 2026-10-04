package host

import (
	"context"
	"fmt"
)

// streamWriteGate serializes event acceptance without holding dedup.mu during
// output I/O. References include the holder and every waiter; idle gates are
// removed, so their number is bounded by admitted sessions, not guest boot IDs.
type streamWriteGate struct {
	token chan struct{}
	refs  int
}

func (s *session) lockEventWrite() (func(), error) {
	// Writes already received survive shutdown, but waiting for another session
	// must still be bounded. A timeout leaves this event with the guest for replay.
	ctx, cancel := context.WithTimeout(s.writeCtx, s.writeTimeout)
	defer cancel()
	unlockPeer, err := s.srv.dedup.lockWrite(ctx, "peer:"+s.peer.bucket())
	if err != nil {
		return nil, fmt.Errorf("waiting for peer event output: %w", err)
	}
	if !s.src.Known || s.src.UUID == "" {
		return unlockPeer, nil
	}
	// A retained event can return under another HELLO boot or CID. The trusted
	// UUID also serializes those writes. Always acquire peer before UUID; no
	// holder of a UUID gate ever waits for another peer gate.
	unlockVM, err := s.srv.dedup.lockWrite(ctx, "uuid:"+s.src.UUID)
	if err != nil {
		unlockPeer()
		return nil, fmt.Errorf("waiting for VM event output: %w", err)
	}
	return func() {
		unlockVM()
		unlockPeer()
	}, nil
}

func (d *dedup) lockWrite(ctx context.Context, key string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.writes == nil {
		d.writes = make(map[string]*streamWriteGate)
	}
	gate := d.writes[key]
	if gate == nil {
		gate = &streamWriteGate{token: make(chan struct{}, 1)}
		d.writes[key] = gate
	}
	gate.refs++
	d.mu.Unlock()

	select {
	case gate.token <- struct{}{}:
		return func() {
			<-gate.token
			d.releaseWrite(key, gate)
		}, nil
	case <-ctx.Done():
		d.releaseWrite(key, gate)
		return nil, ctx.Err()
	}
}

func (d *dedup) releaseWrite(key string, gate *streamWriteGate) {
	d.mu.Lock()
	defer d.mu.Unlock()
	gate.refs--
	if gate.refs == 0 {
		delete(d.writes, key)
	}
}
