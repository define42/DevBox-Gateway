package virt

import (
	"errors"
	"testing"

	"libvirt.org/go/libvirt"
)

func TestLoadDomainMetadataSnapshotUsesOneInactiveXMLRead(t *testing.T) {
	const xmlDesc = `<domain><metadata>
  <owner:owner xmlns:owner="urn:devboxgateway:domain:owner"> alice </owner:owner>
  <guest:guestuser xmlns:guest="urn:devboxgateway:domain:guestuser"> devbox </guest:guestuser>
  <image:baseimage xmlns:image="urn:devboxgateway:domain:baseimage"> ubuntu.qcow2 </image:baseimage>
  <created:createdat xmlns:created="urn:devboxgateway:domain:createdat"> 2026-08-15T12:00:00Z </created:createdat>
</metadata></domain>`

	calls := 0
	var gotFlags libvirt.DomainXMLFlags
	metadata, err := loadDomainMetadataSnapshot(func(flags libvirt.DomainXMLFlags) (string, error) {
		calls++
		gotFlags = flags
		return xmlDesc, nil
	})
	if err != nil {
		t.Fatalf("load metadata snapshot: %v", err)
	}
	if calls != 1 {
		t.Fatalf("GetXMLDesc calls = %d, want exactly 1", calls)
	}
	if gotFlags != libvirt.DOMAIN_XML_INACTIVE {
		t.Fatalf("GetXMLDesc flags = %d, want DOMAIN_XML_INACTIVE (%d)", gotFlags, libvirt.DOMAIN_XML_INACTIVE)
	}
	want := domainMetadataSnapshot{
		Owner:     "alice",
		GuestUser: "devbox",
		BaseImage: "ubuntu.qcow2",
		CreatedAt: "2026-08-15T12:00:00Z",
	}
	if metadata != want {
		t.Fatalf("metadata = %+v, want %+v", metadata, want)
	}
}

func TestParseDomainMetadataSnapshotIsNamespaceAware(t *testing.T) {
	const xmlDesc = `<domain><metadata>
  <wrong:owner xmlns:wrong="urn:example:wrong">mallory</wrong:owner>
  <unqualified>ignored</unqualified>
  <owner:notowner xmlns:owner="urn:devboxgateway:domain:owner">also-ignored</owner:notowner>
  <guest:guestuser xmlns:guest="urn:devboxgateway:domain:guestuser">devbox</guest:guestuser>
  <wrong:baseimage xmlns:wrong="urn:devboxgateway:domain:owner">evil.qcow2</wrong:baseimage>
  <wrapper><owner:owner xmlns:owner="urn:devboxgateway:domain:owner">nested-mallory</owner:owner></wrapper>
</metadata></domain>`

	metadata, err := parseDomainMetadataSnapshot(xmlDesc)
	if err != nil {
		t.Fatalf("parse metadata snapshot: %v", err)
	}
	want := domainMetadataSnapshot{GuestUser: "devbox"}
	if metadata != want {
		t.Fatalf("namespace-colliding metadata = %+v, want %+v", metadata, want)
	}
}

func TestParseDomainMetadataSnapshotUsesFirstDirectChildPerNamespace(t *testing.T) {
	tests := []struct {
		name    string
		xmlDesc string
		want    domainMetadataSnapshot
	}{
		{
			name: "wrong local name prevents later valid owner",
			xmlDesc: `<domain><metadata>
  <owner:notowner xmlns:owner="urn:devboxgateway:domain:owner">mallory</owner:notowner>
  <owner:owner xmlns:owner="urn:devboxgateway:domain:owner">alice</owner:owner>
</metadata></domain>`,
			want: domainMetadataSnapshot{},
		},
		{
			name: "first valid owner wins",
			xmlDesc: `<domain><metadata>
  <owner:owner xmlns:owner="urn:devboxgateway:domain:owner">alice</owner:owner>
  <owner:owner xmlns:owner="urn:devboxgateway:domain:owner">mallory</owner:owner>
</metadata></domain>`,
			want: domainMetadataSnapshot{Owner: "alice"},
		},
		{
			name: "blank owner prevents later valid owner",
			xmlDesc: `<domain><metadata>
  <owner:owner xmlns:owner="urn:devboxgateway:domain:owner"> </owner:owner>
  <owner:owner xmlns:owner="urn:devboxgateway:domain:owner">mallory</owner:owner>
</metadata></domain>`,
			want: domainMetadataSnapshot{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := parseDomainMetadataSnapshot(tc.xmlDesc)
			if err != nil {
				t.Fatalf("parse metadata snapshot: %v", err)
			}
			if metadata != tc.want {
				t.Fatalf("metadata = %+v, want %+v", metadata, tc.want)
			}
		})
	}
}

func TestParseDomainMetadataSnapshotMissingAndBlankValues(t *testing.T) {
	tests := map[string]string{
		"no metadata": `<domain><devices/></domain>`,
		"blank values": `<domain><metadata>
  <owner:owner xmlns:owner="urn:devboxgateway:domain:owner"> </owner:owner>
  <guest:guestuser xmlns:guest="urn:devboxgateway:domain:guestuser"></guest:guestuser>
</metadata></domain>`,
	}
	for name, xmlDesc := range tests {
		t.Run(name, func(t *testing.T) {
			metadata, err := parseDomainMetadataSnapshot(xmlDesc)
			if err != nil {
				t.Fatalf("parse metadata snapshot: %v", err)
			}
			if metadata != (domainMetadataSnapshot{}) {
				t.Fatalf("metadata = %+v, want empty", metadata)
			}
		})
	}
}

func TestParseDomainMetadataSnapshotRejectsMalformedXML(t *testing.T) {
	if _, err := parseDomainMetadataSnapshot(`<domain><metadata><owner:owner xmlns:owner="urn:devboxgateway:domain:owner">alice`); err == nil {
		t.Fatal("expected malformed XML error")
	}
}

func TestLoadDomainMetadataSnapshotPropagatesXMLReadError(t *testing.T) {
	wantErr := errors.New("xml unavailable")
	calls := 0
	_, err := loadDomainMetadataSnapshot(func(libvirt.DomainXMLFlags) (string, error) {
		calls++
		return "", wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("load error = %v, want wrapped %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("GetXMLDesc calls = %d, want exactly 1", calls)
	}
}

func TestDomainMetadataCacheSweepReusesCompleteSnapshot(t *testing.T) {
	const domainUUID = "11111111-1111-1111-1111-111111111111"
	want := domainMetadataSnapshot{CreatedAt: "2026-08-15T12:00:00Z"}
	calls := 0

	firstSweep := newDomainMetadataCacheSweep(nil)
	got, err := firstSweep.load(domainUUID, func() (domainMetadataSnapshot, error) {
		calls++
		return want, nil
	})
	if err != nil || got != want {
		t.Fatalf("first load = %+v, %v; want %+v, nil", got, err, want)
	}

	secondSweep := newDomainMetadataCacheSweep(firstSweep.retainedEntries())
	got, err = secondSweep.load(domainUUID, func() (domainMetadataSnapshot, error) {
		calls++
		return domainMetadataSnapshot{Owner: "unexpected", CreatedAt: want.CreatedAt}, nil
	})
	if err != nil || got != want {
		t.Fatalf("cached load = %+v, %v; want %+v, nil", got, err, want)
	}
	if calls != 1 {
		t.Fatalf("metadata loader calls = %d, want exactly 1", calls)
	}
	if cached := secondSweep.retainedEntries()[domainUUID]; cached != want {
		t.Fatalf("cached metadata = %+v, want %+v", cached, want)
	}
}

func TestDomainMetadataCacheSweepRetriesIncompleteSnapshot(t *testing.T) {
	const domainUUID = "22222222-2222-2222-2222-222222222222"
	incomplete := domainMetadataSnapshot{Owner: "alice"}
	complete := domainMetadataSnapshot{Owner: "alice", CreatedAt: "2026-08-15T12:00:00Z"}
	calls := 0

	firstSweep := newDomainMetadataCacheSweep(nil)
	got, err := firstSweep.load(domainUUID, func() (domainMetadataSnapshot, error) {
		calls++
		return incomplete, nil
	})
	if err != nil || got != incomplete {
		t.Fatalf("incomplete load = %+v, %v; want %+v, nil", got, err, incomplete)
	}
	if len(firstSweep.retainedEntries()) != 0 {
		t.Fatalf("incomplete metadata was cached: %+v", firstSweep.retainedEntries())
	}

	secondSweep := newDomainMetadataCacheSweep(firstSweep.retainedEntries())
	got, err = secondSweep.load(domainUUID, func() (domainMetadataSnapshot, error) {
		calls++
		return complete, nil
	})
	if err != nil || got != complete {
		t.Fatalf("retry load = %+v, %v; want %+v, nil", got, err, complete)
	}
	if calls != 2 {
		t.Fatalf("metadata loader calls = %d, want 2", calls)
	}
	if cached := secondSweep.retainedEntries()[domainUUID]; cached != complete {
		t.Fatalf("cached metadata after retry = %+v, want %+v", cached, complete)
	}
}

func TestDomainMetadataCacheSweepRetriesLoaderError(t *testing.T) {
	const domainUUID = "33333333-3333-3333-3333-333333333333"
	wantErr := errors.New("metadata XML unavailable")
	want := domainMetadataSnapshot{Owner: "alice", CreatedAt: "2026-08-15T12:00:00Z"}
	calls := 0

	firstSweep := newDomainMetadataCacheSweep(nil)
	_, err := firstSweep.load(domainUUID, func() (domainMetadataSnapshot, error) {
		calls++
		return domainMetadataSnapshot{}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("first load error = %v, want %v", err, wantErr)
	}
	if len(firstSweep.retainedEntries()) != 0 {
		t.Fatalf("failed metadata was cached: %+v", firstSweep.retainedEntries())
	}

	secondSweep := newDomainMetadataCacheSweep(firstSweep.retainedEntries())
	got, err := secondSweep.load(domainUUID, func() (domainMetadataSnapshot, error) {
		calls++
		return want, nil
	})
	if err != nil || got != want {
		t.Fatalf("retry load = %+v, %v; want %+v, nil", got, err, want)
	}
	if calls != 2 {
		t.Fatalf("metadata loader calls = %d, want 2", calls)
	}
}

func TestDomainMetadataCacheSweepDoesNotCacheWithoutUUID(t *testing.T) {
	calls := 0
	previous := map[string]domainMetadataSnapshot(nil)
	for range 2 {
		sweep := newDomainMetadataCacheSweep(previous)
		_, err := sweep.load("  ", func() (domainMetadataSnapshot, error) {
			calls++
			return domainMetadataSnapshot{CreatedAt: "2026-08-15T12:00:00Z"}, nil
		})
		if err != nil {
			t.Fatalf("load without UUID: %v", err)
		}
		previous = sweep.retainedEntries()
	}
	if calls != 2 {
		t.Fatalf("metadata loader calls without UUID = %d, want 2", calls)
	}
	if len(previous) != 0 {
		t.Fatalf("metadata without UUID was cached: %+v", previous)
	}
}

func TestDomainMetadataCacheSweepInvalidatesReplacementAndPrunesRemoval(t *testing.T) {
	const oldUUID = "44444444-4444-4444-4444-444444444444"
	const newUUID = "55555555-5555-5555-5555-555555555555"
	oldMetadata := domainMetadataSnapshot{Owner: "alice", CreatedAt: "2026-08-15T12:00:00Z"}
	newMetadata := domainMetadataSnapshot{Owner: "bob", CreatedAt: oldMetadata.CreatedAt}

	firstSweep := newDomainMetadataCacheSweep(nil)
	if _, err := firstSweep.load(oldUUID, func() (domainMetadataSnapshot, error) {
		return oldMetadata, nil
	}); err != nil {
		t.Fatalf("load old same-name domain: %v", err)
	}

	secondSweep := newDomainMetadataCacheSweep(firstSweep.retainedEntries())
	got, err := secondSweep.load(newUUID, func() (domainMetadataSnapshot, error) {
		return newMetadata, nil
	})
	if err != nil || got != newMetadata {
		t.Fatalf("replacement load = %+v, %v; want %+v, nil", got, err, newMetadata)
	}
	retained := secondSweep.retainedEntries()
	if len(retained) != 1 || retained[newUUID] != newMetadata {
		t.Fatalf("replacement cache = %+v, want only new UUID", retained)
	}
	if _, ok := retained[oldUUID]; ok {
		t.Fatalf("old UUID %q survived replacement sweep", oldUUID)
	}

	removalSweep := newDomainMetadataCacheSweep(retained)
	if got := removalSweep.retainedEntries(); len(got) != 0 {
		t.Fatalf("removed domain cache survived empty sweep: %+v", got)
	}
}
