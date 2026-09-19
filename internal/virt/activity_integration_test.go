package virt

import (
	"testing"
	"time"
)

func TestTrackVMUsePersistsFinalDisconnect(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("activeuse")
	_ = viocovDefineDomain(t, conn, name, "")
	t.Cleanup(func() { vmLastUsed.remove(name) })

	first := TrackVMUse(" " + name + " ")
	t.Cleanup(first)
	second := TrackVMUse(name)
	t.Cleanup(second)
	first()
	if !vmLastUsed.inUse(name) {
		t.Fatal("first disconnect removed the second connection's protection")
	}

	beforeDisconnect := time.Now()
	second()
	if vmLastUsed.inUse(name) {
		t.Fatal("final disconnect left the VM protected")
	}
	lastUsed, ok := vmLastUsed.get(name)
	if !ok || lastUsed.Before(beforeDisconnect) {
		t.Fatalf("disconnect timestamp = %v (present=%t), want at least %v", lastUsed, ok, beforeDisconnect)
	}
	persisted, ok := loadVMLastUsedFromMetadata(name)
	if !ok || !persisted.Equal(lastUsed.UTC().Truncate(time.Second)) {
		t.Fatalf("persisted disconnect timestamp = %v (present=%t), want %v", persisted, ok, lastUsed)
	}

	// Repeated cleanup must not extend the countdown or rewrite metadata.
	second()
	assertVMActivityTimestamp(t, vmLastUsed, name, lastUsed)
}

func TestTrackVMUseProtectsEvenWhenPersistenceFails(t *testing.T) {
	name := viocovUniqueName("missing-activeuse")
	t.Cleanup(func() { vmLastUsed.remove(name) })
	end := TrackVMUse(name)
	t.Cleanup(end)
	if !vmLastUsed.inUse(name) {
		t.Fatal("metadata failure discarded the active connection")
	}
	end()
	if vmLastUsed.inUse(name) {
		t.Fatal("metadata failure prevented connection cleanup")
	}
	if _, ok := vmLastUsed.get(name); !ok {
		t.Fatal("metadata failure discarded the disconnect timestamp")
	}
}
