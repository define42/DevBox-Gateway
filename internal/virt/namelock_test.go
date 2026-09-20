package virt

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestKeyedMutexCanceledWaitDoesNotReleaseHolder(t *testing.T) {
	km := newKeyedMutex()
	release := sync.OnceFunc(km.Lock("vm"))
	defer release()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		unlock, err := km.LockContext(ctx, "vm")
		if unlock != nil {
			unlock()
		}
		done <- err
	}()
	waitForVMActivityWaiter(t, km, "vm")
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled wait = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled acquisition waited for the holder")
	}

	// Canceling a waiter must not remove the entry while its holder is active.
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	unlock, err := km.LockContext(ctx, "vm")
	if unlock != nil {
		unlock()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second acquisition = %v, want deadline while original holder remains", err)
	}
	release()
	if n := km.liveKeys(); n != 0 {
		t.Fatalf("canceled waiters leaked %d lock entries", n)
	}
	unlock, err = km.LockContext(t.Context(), "vm")
	if err != nil {
		t.Fatalf("reacquire after cancellations: %v", err)
	}
	unlock()
}

func TestKeyedMutexRejectsAlreadyCanceledContext(t *testing.T) {
	km := newKeyedMutex()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	unlock, err := km.LockContext(ctx, "unused")
	if unlock != nil {
		unlock()
		t.Error("returned a release function for canceled acquisition")
	}
	if !errors.Is(err, context.Canceled) || km.liveKeys() != 0 {
		t.Fatalf("canceled acquisition: error=%v, live keys=%d", err, km.liveKeys())
	}
}

// TestKeyedMutexSerializesSameKey exercises many goroutines contending on one
// key. The unguarded counter increment is only safe because the per-key lock
// serializes them, so `go test -race` on this test proves the mutual exclusion.
func TestKeyedMutexSerializesSameKey(t *testing.T) {
	km := newKeyedMutex()
	const goroutines = 50
	const perGoroutine = 200

	var counter int
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				release := km.Lock("same")
				counter++
				release()
			}
		}()
	}
	wg.Wait()

	if want := goroutines * perGoroutine; counter != want {
		t.Fatalf("counter = %d, want %d (lost updates mean the key was not serialized)", counter, want)
	}
	if n := km.liveKeys(); n != 0 {
		t.Fatalf("expected the keyed mutex to release every key, got %d live entries", n)
	}
}

// TestKeyedMutexDifferentKeysDoNotBlock confirms holding one key never blocks a
// lock on a different key — the whole point of a keyed (rather than global) lock.
func TestKeyedMutexDifferentKeysDoNotBlock(t *testing.T) {
	km := newKeyedMutex()

	releaseA := km.Lock("a")
	done := make(chan struct{})
	go func() {
		releaseB := km.Lock("b")
		releaseB()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Lock on key \"b\" blocked behind the unrelated held key \"a\"")
	}

	releaseA()
	if n := km.liveKeys(); n != 0 {
		t.Fatalf("expected empty map after release, got %d live entries", n)
	}
}

// TestKeyedMutexSameKeyBlocksUntilReleased confirms a second acquire of the same
// key waits for the first to release, then succeeds — and that the entry is
// cleaned up afterward.
func TestKeyedMutexSameKeyBlocksUntilReleased(t *testing.T) {
	km := newKeyedMutex()

	release1 := km.Lock("k")
	acquired := make(chan struct{})
	go func() {
		release2 := km.Lock("k")
		release2()
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second Lock acquired the key while it was still held")
	case <-time.After(100 * time.Millisecond):
	}

	release1()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("second Lock never acquired after the first released")
	}

	if n := km.liveKeys(); n != 0 {
		t.Fatalf("expected empty map after both released, got %d live entries", n)
	}
}
