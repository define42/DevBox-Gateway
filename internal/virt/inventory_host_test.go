package virt

import (
	"errors"
	"testing"
)

func TestLoadInventoryHostIdentityUsesCanonicalURIAndHostUUID(t *testing.T) {
	const capabilities = `<capabilities>
  <host>
    <uuid> 7B55704C29F411B2A85C9DC6FF50623F </uuid>
    <cpu><arch>x86_64</arch></cpu>
  </host>
</capabilities>`

	uriCalls := 0
	capabilitiesCalls := 0
	hostnameCalls := 0
	identity, err := loadInventoryHostIdentity(
		func() (string, error) {
			uriCalls++
			return " qemu:///system ", nil
		},
		func() (string, error) {
			capabilitiesCalls++
			return capabilities, nil
		},
		func() (string, error) {
			hostnameCalls++
			return "unused.example", nil
		},
	)
	if err != nil {
		t.Fatalf("load inventory host identity: %v", err)
	}
	want := inventoryHostIdentity{
		URI:      "qemu:///system",
		HostUUID: "7b55704c-29f4-11b2-a85c-9dc6ff50623f",
	}
	if identity != want {
		t.Fatalf("host identity = %+v, want %+v", identity, want)
	}
	if uriCalls != 1 || capabilitiesCalls != 1 || hostnameCalls != 0 {
		t.Fatalf("identity calls = URI %d, capabilities %d, hostname %d; want 1/1/0", uriCalls, capabilitiesCalls, hostnameCalls)
	}
}

func TestLoadInventoryHostIdentityFallsBackToHostname(t *testing.T) {
	identity, err := loadInventoryHostIdentity(
		func() (string, error) { return "test:///default", nil },
		func() (string, error) { return `<capabilities><host/></capabilities>`, nil },
		func() (string, error) { return " TestHost.EXAMPLE. ", nil },
	)
	if err != nil {
		t.Fatalf("load hostname inventory identity: %v", err)
	}
	want := inventoryHostIdentity{URI: "test:///default", Hostname: "testhost.example"}
	if identity != want {
		t.Fatalf("hostname identity = %+v, want %+v", identity, want)
	}
}

func TestLoadInventoryHostIdentityRejectsUnavailableIdentity(t *testing.T) {
	tests := map[string]struct {
		uri          string
		uriErr       error
		capabilities string
		capsErr      error
		hostname     string
		hostnameErr  error
	}{
		"URI error":          {uriErr: errors.New("connection unavailable")},
		"empty URI":          {capabilities: `<capabilities><host/></capabilities>`, hostname: "host"},
		"capabilities error": {uri: "qemu:///system", capsErr: errors.New("daemon unavailable")},
		"malformed XML":      {uri: "qemu:///system", capabilities: `<capabilities><host>`},
		"wrong XML root":     {uri: "qemu:///system", capabilities: `<domain><host/></domain>`, hostname: "host"},
		"malformed UUID":     {uri: "qemu:///system", capabilities: `<capabilities><host><uuid>not-a-uuid</uuid></host></capabilities>`},
		"hostname error":     {uri: "test:///default", capabilities: `<capabilities><host/></capabilities>`, hostnameErr: errors.New("missing hostname")},
		"empty hostname":     {uri: "test:///default", capabilities: `<capabilities><host/></capabilities>`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := loadInventoryHostIdentity(
				func() (string, error) { return tc.uri, tc.uriErr },
				func() (string, error) { return tc.capabilities, tc.capsErr },
				func() (string, error) { return tc.hostname, tc.hostnameErr },
			); err == nil {
				t.Fatal("expected unavailable host identity to fail")
			}
		})
	}
}

func TestLoadInventoryHostIdentityFallsBackForZeroUUID(t *testing.T) {
	identity, err := loadInventoryHostIdentity(
		func() (string, error) { return "qemu:///system", nil },
		func() (string, error) {
			return `<capabilities><host><uuid>00000000-0000-0000-0000-000000000000</uuid></host></capabilities>`, nil
		},
		func() (string, error) { return "host.example", nil },
	)
	if err != nil {
		t.Fatalf("load zero-UUID fallback identity: %v", err)
	}
	want := inventoryHostIdentity{URI: "qemu:///system", Hostname: "host.example"}
	if identity != want {
		t.Fatalf("zero-UUID fallback identity = %+v, want %+v", identity, want)
	}
}

func TestSetInventoryHostIdentityPreservesCachesForSameHost(t *testing.T) {
	identity := inventoryHostIdentity{
		URI:      "qemu:///system",
		HostUUID: "7b55704c-29f4-11b2-a85c-9dc6ff50623f",
	}
	worker := &SingletonWorker{}

	if previous, changed := worker.setInventoryHostIdentity(identity); changed || previous != (inventoryHostIdentity{}) {
		t.Fatalf("initial identity = (%+v, %v), want empty previous without change", previous, changed)
	}
	worker.metadataByUUID = map[string]domainMetadataSnapshot{
		"cached-domain": {CreatedAt: "2026-08-15T12:00:00Z"},
	}
	worker.diskByUUID = map[string]domainDiskSnapshot{
		"cached-domain": {UsedGB: 1, TotalGB: 2},
	}
	if previous, changed := worker.setInventoryHostIdentity(identity); changed || previous != identity {
		t.Fatalf("same-host identity = (%+v, %v), want (%+v, false)", previous, changed, identity)
	}
	assertWorkerInventorySnapshotsPresent(t, worker)
}

func TestSetInventoryHostIdentityClearsCachesWithUnknownProvenance(t *testing.T) {
	identity := inventoryHostIdentity{
		URI:      "qemu:///system",
		HostUUID: "7b55704c-29f4-11b2-a85c-9dc6ff50623f",
	}
	worker := workerWithInventorySnapshots()
	worker.setVMs([]VMInfo{{Name: "unverified-host-vm", Owner: "alice"}})

	previous, invalidated := worker.setInventoryHostIdentity(identity)
	if !invalidated || previous != (inventoryHostIdentity{}) {
		t.Fatalf("initial identity = (%+v, %v), want empty previous with invalidation", previous, invalidated)
	}
	if worker.inventoryHostIdentity != identity {
		t.Fatalf("recorded host identity = %+v, want %+v", worker.inventoryHostIdentity, identity)
	}
	if len(worker.metadataByUUID) != 0 || len(worker.diskByUUID) != 0 {
		t.Fatalf("initial identity retained unverified caches: metadata=%+v disk=%+v", worker.metadataByUUID, worker.diskByUUID)
	}
	if vms := worker.GetVMs(""); len(vms) != 0 {
		t.Fatalf("initial identity retained unverified VM snapshot: %+v", vms)
	}
}

func TestSetInventoryHostIdentityClearsCachesOnlyForConfirmedChange(t *testing.T) {
	oldIdentity := inventoryHostIdentity{
		URI:      "qemu:///system",
		HostUUID: "7b55704c-29f4-11b2-a85c-9dc6ff50623f",
	}
	newIdentity := inventoryHostIdentity{
		URI:      oldIdentity.URI,
		HostUUID: "3f78332b-eac2-4c43-9387-e307a653899a",
	}
	worker := workerWithInventorySnapshots()
	worker.inventoryHostIdentity = oldIdentity
	worker.setVMs([]VMInfo{{Name: "old-host-vm", Owner: "alice"}})

	if previous, changed := worker.setInventoryHostIdentity(inventoryHostIdentity{}); changed || previous != (inventoryHostIdentity{}) {
		t.Fatalf("unknown identity = (%+v, %v), want empty previous without change", previous, changed)
	}
	assertWorkerInventorySnapshotsPresent(t, worker)

	if previous, changed := worker.setInventoryHostIdentity(newIdentity); !changed || previous != oldIdentity {
		t.Fatalf("changed identity = (%+v, %v), want (%+v, true)", previous, changed, oldIdentity)
	}
	if worker.inventoryHostIdentity != newIdentity {
		t.Fatalf("recorded host identity = %+v, want %+v", worker.inventoryHostIdentity, newIdentity)
	}
	if len(worker.metadataByUUID) != 0 {
		t.Fatalf("host change retained metadata cache: %+v", worker.metadataByUUID)
	}
	if len(worker.diskByUUID) != 0 {
		t.Fatalf("host change retained disk cache: %+v", worker.diskByUUID)
	}
	if vms := worker.GetVMs(""); len(vms) != 0 {
		t.Fatalf("host change retained old VM snapshot: %+v", vms)
	}
}

func workerWithInventorySnapshots() *SingletonWorker {
	return &SingletonWorker{
		metadataByUUID: map[string]domainMetadataSnapshot{
			"cached-domain": {CreatedAt: "2026-08-15T12:00:00Z"},
		},
		diskByUUID: map[string]domainDiskSnapshot{
			"cached-domain": {UsedGB: 1, TotalGB: 2},
		},
	}
}

func assertWorkerInventorySnapshotsPresent(t *testing.T, worker *SingletonWorker) {
	t.Helper()
	if len(worker.metadataByUUID) != 1 {
		t.Fatalf("metadata cache was cleared: %+v", worker.metadataByUUID)
	}
	if len(worker.diskByUUID) != 1 {
		t.Fatalf("disk cache was cleared: %+v", worker.diskByUUID)
	}
}
