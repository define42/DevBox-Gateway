package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// rejectionLogInterval throttles connection-cap logging so a flood at the cap
// reports a periodic count instead of one line per rejected connection.
const rejectionLogInterval = 30 * time.Second

// failFastLimitListener caps the number of simultaneously open accepted
// connections. Unlike netutil.LimitListener, which blocks Accept at the cap —
// leaving new clients hanging in the kernel accept backlog with no trace in
// the logs — this listener keeps accepting and immediately closes connections
// over the cap: clients fail fast and retry, and every saturation episode is
// visible in the logs.
type failFastLimitListener struct {
	net.Listener

	// slots holds one token per open accepted connection; capacity is the cap.
	slots chan struct{}

	rejectedSinceLog atomic.Uint64
	lastRejectionLog atomic.Int64 // unix nanoseconds of the last saturation log
}

func newFailFastLimitListener(ln net.Listener, maxConns int) *failFastLimitListener {
	return &failFastLimitListener{
		Listener: ln,
		slots:    make(chan struct{}, maxConns),
	}
}

func (l *failFastLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &slotTrackedConn{Conn: conn, release: l.releaseSlot}, nil
		default:
			_ = conn.Close()
			l.noteRejection(conn.RemoteAddr())
		}
	}
}

func (l *failFastLimitListener) releaseSlot() {
	<-l.slots
}

// noteRejection counts a rejected connection and logs at most once per
// rejectionLogInterval so saturation is visible without flooding the log.
func (l *failFastLimitListener) noteRejection(remote net.Addr) {
	count := l.rejectedSinceLog.Add(1)
	now := time.Now().UnixNano()
	last := l.lastRejectionLog.Load()
	if now-last < int64(rejectionLogInterval) || !l.lastRejectionLog.CompareAndSwap(last, now) {
		return
	}
	l.rejectedSinceLog.Store(0)
	log.Printf("front connection cap (%d) reached: %d connections rejected since last report (latest from %s); consider raising MAX_CONCURRENT_CONNECTIONS", cap(l.slots), count, remote)
}

// slotTrackedConn returns its listener slot exactly once when closed, however
// many times Close is called on it along the connection's teardown paths.
type slotTrackedConn struct {
	net.Conn

	releaseOnce sync.Once
	release     func()
}

func (c *slotTrackedConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}
