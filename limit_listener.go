package main

import (
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// rejectionLogInterval throttles connection-cap logging so a flood at the cap
// reports a periodic count instead of one line per rejected connection.
const rejectionLogInterval = 30 * time.Second

// rejectionThrottle counts rejected connections and admits at most one log
// line per rejectionLogInterval, so saturation is visible without flooding
// the log.
type rejectionThrottle struct {
	rejectedSinceLog atomic.Uint64
	lastRejectionLog atomic.Int64 // unix nanoseconds of the last saturation log
}

// note counts one rejection. When it returns true the caller should log,
// reporting the returned number of rejections since the previous log line.
func (t *rejectionThrottle) note() (uint64, bool) {
	count := t.rejectedSinceLog.Add(1)
	now := time.Now().UnixNano()
	last := t.lastRejectionLog.Load()
	if now-last < int64(rejectionLogInterval) || !t.lastRejectionLog.CompareAndSwap(last, now) {
		return 0, false
	}
	t.rejectedSinceLog.Store(0)
	return count, true
}

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

	rejections rejectionThrottle
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
			if count, ok := l.rejections.note(); ok {
				log.Printf("front connection cap (%d) reached: %d connections rejected since last report (latest from %s); consider raising MAX_CONCURRENT_CONNECTIONS", cap(l.slots), count, conn.RemoteAddr())
			}
		}
	}
}

func (l *failFastLimitListener) releaseSlot() {
	<-l.slots
}

// perSourceLimitListener caps the number of simultaneously open accepted
// connections per source address, so one unauthenticated source cannot occupy
// the whole shared connection budget enforced by failFastLimitListener (e.g.
// by parking idle keep-alive connections on the unauthenticated health
// endpoint). Like failFastLimitListener it fails fast: connections over a
// source's cap are accepted and immediately closed, and saturation is logged.
type perSourceLimitListener struct {
	net.Listener

	maxPerSource int

	mu     sync.Mutex
	counts map[string]int // open connections per perSourceLimitKey bucket

	rejections rejectionThrottle
}

func newPerSourceLimitListener(ln net.Listener, maxPerSource int) *perSourceLimitListener {
	return &perSourceLimitListener{
		Listener:     ln,
		maxPerSource: maxPerSource,
		counts:       make(map[string]int),
	}
}

func (l *perSourceLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := perSourceLimitKey(conn.RemoteAddr())
		if l.acquire(key) {
			return &slotTrackedConn{Conn: conn, release: func() { l.release(key) }}, nil
		}
		_ = conn.Close()
		if count, ok := l.rejections.note(); ok {
			log.Printf("per-source connection cap (%d) reached: %d connections rejected since last report (latest from %s); consider raising MAX_CONNECTIONS_PER_SOURCE if this source is a shared NAT or proxy", l.maxPerSource, count, conn.RemoteAddr())
		}
	}
}

func (l *perSourceLimitListener) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] >= l.maxPerSource {
		return false
	}
	l.counts[key]++
	return true
}

// release returns one slot for key, dropping the map entry at zero so the
// table stays bounded by open connections rather than by distinct sources seen.
func (l *perSourceLimitListener) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] <= 1 {
		delete(l.counts, key)
		return
	}
	l.counts[key]--
}

// perSourceLimitKey buckets a remote address for the per-source cap: one
// bucket per IPv4 address, one per /64 prefix for IPv6 — a single IPv6 host
// commonly controls an entire /64, so per-address buckets would be trivial to
// rotate through. Unparseable addresses fall back to the raw string so they
// are still limited rather than exempt.
func perSourceLimitKey(remote net.Addr) string {
	if remote == nil {
		return "unknown"
	}
	raw := remote.String()
	addrPort, err := netip.ParseAddrPort(raw)
	if err != nil {
		return raw
	}
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
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
