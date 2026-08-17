package virt

import (
	"testing"
	"time"
)

func TestVMLastUsedRegistryLifecycle(t *testing.T) {
	registry := newVMLastUsedRegistry()

	if _, ok := registry.get("vm-a"); ok {
		t.Fatal("expected an empty registry to report no last-used time")
	}

	first := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	registry.set("vm-a", first)
	registry.set("vm-b", first.Add(time.Hour))

	got, ok := registry.get("vm-a")
	if !ok || !got.Equal(first) {
		t.Fatalf("get vm-a = %v (present=%v), want %v", got, ok, first)
	}

	registry.retainNames(map[string]struct{}{"vm-b": {}})
	if _, ok := registry.get("vm-a"); ok {
		t.Fatal("expected vm-a to be pruned by retainNames")
	}
	if _, ok := registry.get("vm-b"); !ok {
		t.Fatal("expected vm-b to survive retainNames")
	}

	registry.remove("vm-b")
	if _, ok := registry.get("vm-b"); ok {
		t.Fatal("expected vm-b to be removed")
	}
}

func TestLastUsedTimestampRoundTrip(t *testing.T) {
	at := time.Date(2026, 8, 15, 12, 30, 45, 0, time.UTC)

	parsed, err := parseLastUsedTimestamp(" " + formatLastUsedTimestamp(at) + " ")
	if err != nil {
		t.Fatalf("parse formatted timestamp: %v", err)
	}
	if !parsed.Equal(at) {
		t.Fatalf("round-tripped timestamp = %v, want %v", parsed, at)
	}

	if _, err := parseLastUsedTimestamp("not-a-time"); err == nil {
		t.Fatal("expected parse error for a malformed timestamp")
	}
}

func TestMarkVMUsedBlankNameIsIgnored(t *testing.T) {
	MarkVMUsed("   ")
	if _, ok := vmLastUsed.get("   "); ok {
		t.Fatal("expected a blank name not to be recorded")
	}
}

func TestMarkVMUsedRecordsCacheAndMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("lastused")
	dom := viocovDefineDomain(t, conn, name, "")
	t.Cleanup(func() { vmLastUsed.remove(name) })

	if _, ok := loadVMLastUsedFromMetadata(name); ok {
		t.Fatal("expected no last-used metadata on a fresh domain")
	}

	before := time.Now().Add(-time.Second)
	MarkVMUsed(name)

	cached, ok := vmLastUsed.get(name)
	if !ok {
		t.Fatal("expected MarkVMUsed to populate the in-memory registry")
	}
	if cached.Before(before) {
		t.Fatalf("cached last-used %v predates the call (started after %v)", cached, before)
	}

	value, has, err := domainLastUsed(dom)
	if err != nil || !has {
		t.Fatalf("expected persisted last-used metadata, got %q (has=%v, err=%v)", value, has, err)
	}
	persisted, ok := loadVMLastUsedFromMetadata(name)
	if !ok {
		t.Fatal("expected loadVMLastUsedFromMetadata to recover the persisted timestamp")
	}
	// The RFC3339 representation drops sub-second precision.
	if want := cached.UTC().Truncate(time.Second); !persisted.Equal(want) {
		t.Fatalf("persisted last-used = %v, want %v", persisted, want)
	}
}

func TestLoadVMLastUsedFromMetadataFailureModes(t *testing.T) {
	if _, ok := loadVMLastUsedFromMetadata(viocovUniqueName("absent")); ok {
		t.Fatal("expected no last-used timestamp for a missing domain")
	}

	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("badlastused")
	dom := viocovDefineDomain(t, conn, name, "")

	if err := setDomainLastUsedMetadata(dom, "not-a-time"); err != nil {
		t.Fatalf("set malformed last-used metadata: %v", err)
	}
	if _, ok := loadVMLastUsedFromMetadata(name); ok {
		t.Fatal("expected an unparsable timestamp to be reported absent")
	}
}

func TestGetVMsOverlaysRegistryLastUsed(t *testing.T) {
	const name = "overlay-vm"
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{{Name: name, Owner: "alice", LastUsed: "2026-08-15T12:00:00Z"}})
	t.Cleanup(func() { vmLastUsed.remove(name) })

	// Without a registry entry the persisted snapshot value passes through.
	vms := worker.GetVMs("alice")
	if len(vms) != 1 || vms[0].LastUsed != "2026-08-15T12:00:00Z" {
		t.Fatalf("GetVMs without registry entry = %+v, want the snapshot timestamp", vms)
	}

	// A registry entry (a touch since the sweep) takes precedence.
	touched := time.Date(2026, 8, 16, 9, 30, 0, 0, time.UTC)
	vmLastUsed.set(name, touched)
	vms = worker.GetVMs("alice")
	if len(vms) != 1 || vms[0].LastUsed != formatLastUsedTimestamp(touched) {
		t.Fatalf("GetVMs with registry entry = %+v, want the registry timestamp", vms)
	}

	// The overlay must not leak into the worker's internal snapshot.
	if internal := worker.snapshotVMs(); internal[0].LastUsed != "2026-08-15T12:00:00Z" {
		t.Fatalf("internal snapshot was mutated by the overlay: %+v", internal)
	}
}

func TestNotifyVMDataChangedWakesSubscribers(t *testing.T) {
	worker := &SingletonWorker{}
	updates, unsubscribe := worker.SubscribeVMChanges()
	defer unsubscribe()

	worker.NotifyVMDataChanged()

	select {
	case <-updates:
	default:
		t.Fatal("expected NotifyVMDataChanged to signal subscribers")
	}
}

func TestMarkDomainUsedRecordsCacheAndMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("domused")
	dom := viocovDefineDomain(t, conn, name, "")
	t.Cleanup(func() { vmLastUsed.remove(name) })

	markDomainUsed(dom, name)

	if _, ok := vmLastUsed.get(name); !ok {
		t.Fatal("expected markDomainUsed to populate the in-memory registry")
	}
	if _, ok := loadVMLastUsedFromMetadata(name); !ok {
		t.Fatal("expected markDomainUsed to persist last-used metadata")
	}
}
