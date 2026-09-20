package virt

import (
	"context"
	"sync"
)

// keyedMutex hands out a distinct mutex per string key, so operations that share
// a key are serialized while operations on different keys run concurrently. It
// ref-counts live keys and drops a key's entry once no goroutine holds or waits
// on it, so the map does not grow without bound as VDI names come and go over
// the life of the process.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedMutexEntry
}

// keyedMutexEntry is the per-key semaphore plus a count of the goroutines
// holding or waiting on it. waiters is guarded by keyedMutex.mu, so acquisition,
// release and cancellation update the count atomically. A key is only removed
// from the map when no goroutine still references its entry.
type keyedMutexEntry struct {
	held    chan struct{}
	waiters int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: make(map[string]*keyedMutexEntry)}
}

// Lock acquires the mutex for key, blocking until it is available, and returns a
// release function that must be called exactly once to unlock it. VM lifecycle
// callers acquire one VM-name key, then optionally the reserved network key.
// Network operations never acquire a VM-name key, preserving that lock order.
func (k *keyedMutex) Lock(key string) (release func()) {
	release, _ = k.LockContext(context.Background(), key)
	return release
}

// LockContext acquires key or returns the context error without waiting for its
// current holder. On success the caller must invoke release exactly once.
func (k *keyedMutex) LockContext(ctx context.Context, key string) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k.mu.Lock()
	entry, ok := k.locks[key]
	if !ok {
		entry = &keyedMutexEntry{held: make(chan struct{}, 1)}
		k.locks[key] = entry
	}
	// Count this goroutine before releasing the map lock so the entry cannot be
	// deleted out from under us while we wait for its semaphore below.
	entry.waiters++
	k.mu.Unlock()

	select {
	case entry.held <- struct{}{}:
	case <-ctx.Done():
		k.releaseReference(key, entry)
		return nil, ctx.Err()
	}

	release = func() {
		<-entry.held
		k.releaseReference(key, entry)
	}
	// Cancellation may race with acquisition of an available semaphore.
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (k *keyedMutex) releaseReference(key string, entry *keyedMutexEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(k.locks, key)
	}
}

// liveKeys reports how many keys currently have an entry. It exists for tests to
// assert the map is reclaimed once every key is released.
func (k *keyedMutex) liveKeys() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.locks)
}
