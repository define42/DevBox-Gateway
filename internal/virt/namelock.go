package virt

import "sync"

// keyedMutex hands out a distinct mutex per string key, so operations that share
// a key are serialized while operations on different keys run concurrently. It
// ref-counts live keys and drops a key's entry once no goroutine holds or waits
// on it, so the map does not grow without bound as VDI names come and go over
// the life of the process.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedMutexEntry
}

// keyedMutexEntry is the per-key lock plus a count of the goroutines currently
// holding or waiting on it. waiters is guarded by keyedMutex.mu (not by mu), so
// the increment in Lock and the decrement/delete in the returned release are
// atomic with respect to each other — a key is only removed from the map when
// no goroutine still references its entry.
type keyedMutexEntry struct {
	mu      sync.Mutex
	waiters int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: make(map[string]*keyedMutexEntry)}
}

// Lock acquires the mutex for key, blocking until it is available, and returns a
// release function that must be called exactly once to unlock it. Callers that
// hold one key never acquire a second key, so keyedMutex cannot deadlock against
// itself regardless of key ordering.
func (k *keyedMutex) Lock(key string) (release func()) {
	k.mu.Lock()
	entry, ok := k.locks[key]
	if !ok {
		entry = &keyedMutexEntry{}
		k.locks[key] = entry
	}
	// Count this goroutine before releasing the map lock so the entry cannot be
	// deleted out from under us while we block on entry.mu below.
	entry.waiters++
	k.mu.Unlock()

	entry.mu.Lock()

	return func() {
		entry.mu.Unlock()

		k.mu.Lock()
		entry.waiters--
		if entry.waiters == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

// liveKeys reports how many keys currently have an entry. It exists for tests to
// assert the map is reclaimed once every key is released.
func (k *keyedMutex) liveKeys() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.locks)
}
