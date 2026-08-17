package virt

import (
	"fmt"
	"strings"
	"testing"

	"libvirt.org/go/libvirt"
)

// viocovMetadataAccess bundles one domain-metadata kind (owner, guest user,
// created-at, base image) so every branch can be exercised uniformly.
type viocovMetadataAccess struct {
	kind      string
	namespace string
	prefix    string
	build     func(string) (string, error)
	set       func(*libvirt.Domain, string) error
	get       func(*libvirt.Domain) (string, bool, error)
}

func viocovMetadataAccessors() []viocovMetadataAccess {
	return []viocovMetadataAccess{
		{
			kind: "owner", namespace: domainOwnerMetadataNamespace, prefix: domainOwnerMetadataPrefix,
			build: domainOwnerMetadataXML, set: setDomainOwnerMetadata, get: domainOwner,
		},
		{
			kind: "guestuser", namespace: domainGuestUserMetadataNamespace, prefix: domainGuestUserMetadataPrefix,
			build: domainGuestUserMetadataXML, set: setDomainGuestUserMetadata, get: domainGuestUser,
		},
		{
			kind: "createdat", namespace: domainCreatedAtMetadataNamespace, prefix: domainCreatedAtMetadataPrefix,
			build: domainCreatedAtMetadataXML, set: setDomainCreatedAtMetadata, get: domainCreatedAt,
		},
		{
			kind: "lastused", namespace: domainLastUsedMetadataNamespace, prefix: domainLastUsedMetadataPrefix,
			build: domainLastUsedMetadataXML, set: setDomainLastUsedMetadata, get: domainLastUsed,
		},
		{
			kind: "baseimage", namespace: domainBaseImageMetadataNamespace, prefix: domainBaseImageMetadataPrefix,
			build: domainBaseImageMetadataXML, set: setDomainBaseImageMetadata, get: domainBaseImage,
		},
	}
}

func TestViocovMetadataXMLBuilders(t *testing.T) {
	for _, access := range viocovMetadataAccessors() {
		t.Run(access.kind, func(t *testing.T) {
			if _, err := access.build("   "); err == nil {
				t.Fatal("expected error for blank metadata value")
			}
			payload, err := access.build("viocov-value")
			if err != nil {
				t.Fatalf("building metadata payload: %v", err)
			}
			if !strings.Contains(payload, "viocov-value") {
				t.Fatalf("expected payload to contain the value, got %q", payload)
			}
		})
	}
}

func TestViocovSetMetadataRejectsBlankValue(t *testing.T) {
	// Validation fails before the domain handle is touched.
	dom := &libvirt.Domain{}
	for _, access := range viocovMetadataAccessors() {
		if err := access.set(dom, "  "); err == nil {
			t.Fatalf("%s: expected error for blank metadata value", access.kind)
		}
	}
}

func TestViocovMetadataRoundTripAndAbsence(t *testing.T) {
	conn := newTestLibvirtConn(t)
	dom := viocovDefineDomain(t, conn, viocovUniqueName("meta"), "")

	for _, access := range viocovMetadataAccessors() {
		value, has, err := access.get(dom)
		if err != nil {
			t.Fatalf("%s: reading absent metadata: %v", access.kind, err)
		}
		if has || value != "" {
			t.Fatalf("%s: expected no metadata on a fresh domain, got %q", access.kind, value)
		}

		want := "viocov-" + access.kind
		if err := access.set(dom, want); err != nil {
			t.Fatalf("%s: setting metadata: %v", access.kind, err)
		}
		value, has, err = access.get(dom)
		if err != nil {
			t.Fatalf("%s: reading metadata: %v", access.kind, err)
		}
		if !has || value != want {
			t.Fatalf("%s: expected %q, got %q (has=%v)", access.kind, want, value, has)
		}
	}
}

func TestViocovInventoryMetadataSnapshotReadsRunningPersistentConfig(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("runningmeta")
	dom := viocovStartDomain(t, conn, name, "")

	want := domainMetadataSnapshot{
		Owner:     "cvio-owner",
		GuestUser: "cvio-guest",
		BaseImage: "cvio-base.qcow2",
		CreatedAt: "2026-08-15T12:00:00Z",
	}
	// These setters deliberately affect only persistent configuration. Inventory
	// must therefore request DOMAIN_XML_INACTIVE even while the domain is active.
	if err := setDomainOwnerMetadata(dom, want.Owner); err != nil {
		t.Fatalf("set owner metadata: %v", err)
	}
	if err := setDomainGuestUserMetadata(dom, want.GuestUser); err != nil {
		t.Fatalf("set guest-user metadata: %v", err)
	}
	if err := setDomainBaseImageMetadata(dom, want.BaseImage); err != nil {
		t.Fatalf("set base-image metadata: %v", err)
	}
	if err := setDomainCreatedAtMetadata(dom, want.CreatedAt); err != nil {
		t.Fatalf("set created-at metadata: %v", err)
	}

	metadata, err := loadDomainMetadataSnapshot(dom.GetXMLDesc)
	if err != nil {
		t.Fatalf("load running domain metadata: %v", err)
	}
	if metadata != want {
		t.Fatalf("running domain metadata = %+v, want %+v", metadata, want)
	}

	info, ok := domainVMInfo(*dom, want.Owner)
	if !ok {
		t.Fatal("running domain was not listed for its configured owner")
	}
	if info.Owner != want.Owner || info.GuestUser != want.GuestUser ||
		info.BaseImage != want.BaseImage || info.CreatedAt != want.CreatedAt {
		t.Fatalf("inventory metadata = %+v, want %+v", info, want)
	}
}

func TestViocovWorkerMetadataCacheLifecycle(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("worker-meta-cache")
	createdAt := "2026-08-15T12:00:00Z"
	worker := &SingletonWorker{}

	first, firstUUID := viocovCreatePartialMetadataDomain(t, conn, worker, name)
	viocovCompleteMetadataCacheEntry(t, conn, worker, first, firstUUID, createdAt)

	second, secondUUID := viocovReplaceMetadataDomain(t, conn, worker, first, firstUUID, name, createdAt)
	viocovAssertMetadataReplacement(t, worker, name, firstUUID, secondUUID)
	viocovAssertMetadataSnapshotIsImmutable(t, conn, worker, second, name)
	viocovRemoveMetadataDomain(t, conn, worker, second, secondUUID)
}

func viocovCreatePartialMetadataDomain(
	t *testing.T,
	conn *libvirt.Connect,
	worker *SingletonWorker,
	name string,
) (*libvirt.Domain, string) {
	t.Helper()
	first := viocovDefineDomain(t, conn, name, "")
	firstUUID, err := first.GetUUIDString()
	if err != nil {
		t.Fatalf("get first domain UUID: %v", err)
	}
	if err := setDomainOwnerMetadata(first, "alice"); err != nil {
		t.Fatalf("set partial owner metadata: %v", err)
	}
	if err := worker.doWork(conn); err != nil {
		t.Fatalf("inventory partial metadata: %v", err)
	}
	if _, ok := viocovWorkerCachedMetadata(worker, firstUUID); ok {
		t.Fatal("metadata without the CreatedAt completion marker was cached")
	}
	return first, firstUUID
}

func viocovCompleteMetadataCacheEntry(
	t *testing.T,
	conn *libvirt.Connect,
	worker *SingletonWorker,
	domain *libvirt.Domain,
	domainUUID string,
	createdAt string,
) {
	t.Helper()
	if err := setDomainCreatedAtMetadata(domain, createdAt); err != nil {
		t.Fatalf("set first created-at metadata: %v", err)
	}
	if err := worker.doWork(conn); err != nil {
		t.Fatalf("inventory complete metadata: %v", err)
	}
	if metadata, ok := viocovWorkerCachedMetadata(worker, domainUUID); !ok ||
		metadata.Owner != "alice" || metadata.CreatedAt != createdAt {
		t.Fatalf("first cached metadata = %+v (present=%v)", metadata, ok)
	}
	worker.inventoryCacheMu.Lock()
	_, diskCachedWithoutDisk := worker.diskByUUID[domainUUID]
	worker.inventoryCacheMu.Unlock()
	if diskCachedWithoutDisk {
		t.Fatal("failed block-info lookup was cached alongside valid metadata")
	}
}

func viocovReplaceMetadataDomain(
	t *testing.T,
	conn *libvirt.Connect,
	worker *SingletonWorker,
	first *libvirt.Domain,
	firstUUID string,
	name string,
	createdAt string,
) (*libvirt.Domain, string) {
	t.Helper()
	if err := first.Undefine(); err != nil {
		t.Fatalf("undefine first same-name domain: %v", err)
	}
	second := viocovDefineDomain(t, conn, name, "")
	secondUUID, err := second.GetUUIDString()
	if err != nil {
		t.Fatalf("get replacement domain UUID: %v", err)
	}
	if secondUUID == firstUUID {
		t.Fatalf("replacement UUID = old UUID %q", firstUUID)
	}
	if err := setDomainOwnerMetadata(second, "bob"); err != nil {
		t.Fatalf("set replacement owner metadata: %v", err)
	}
	if err := setDomainCreatedAtMetadata(second, createdAt); err != nil {
		t.Fatalf("set replacement created-at metadata: %v", err)
	}
	if err := worker.doWork(conn); err != nil {
		t.Fatalf("inventory same-name replacement: %v", err)
	}
	return second, secondUUID
}

func viocovAssertMetadataReplacement(
	t *testing.T,
	worker *SingletonWorker,
	name string,
	firstUUID string,
	secondUUID string,
) {
	t.Helper()
	if _, ok := viocovWorkerCachedMetadata(worker, firstUUID); ok {
		t.Fatalf("old UUID %q survived replacement sweep", firstUUID)
	}
	if metadata, ok := viocovWorkerCachedMetadata(worker, secondUUID); !ok || metadata.Owner != "bob" {
		t.Fatalf("replacement cached metadata = %+v (present=%v)", metadata, ok)
	}
	if vm := requireListedVM(t, worker.GetVMs(""), name); vm.Owner != "bob" {
		t.Fatalf("replacement inventory owner = %q, want bob", vm.Owner)
	}
}

func viocovAssertMetadataSnapshotIsImmutable(
	t *testing.T,
	conn *libvirt.Connect,
	worker *SingletonWorker,
	domain *libvirt.Domain,
	name string,
) {
	t.Helper()
	// Completed inventory metadata is intentionally immutable in the worker,
	// while the direct authorization getter continues to read current libvirt
	// configuration without consulting this cache.
	if err := setDomainOwnerMetadata(domain, "carol"); err != nil {
		t.Fatalf("externally edit replacement owner metadata: %v", err)
	}
	owner, hasOwner, err := domainOwner(domain)
	if err != nil || !hasOwner || owner != "carol" {
		t.Fatalf("direct owner after external edit = %q, %v, %v", owner, hasOwner, err)
	}
	if err := worker.doWork(conn); err != nil {
		t.Fatalf("inventory cached replacement: %v", err)
	}
	if vm := requireListedVM(t, worker.GetVMs(""), name); vm.Owner != "bob" {
		t.Fatalf("worker did not reuse immutable metadata: owner=%q, want bob", vm.Owner)
	}
}

func viocovRemoveMetadataDomain(
	t *testing.T,
	conn *libvirt.Connect,
	worker *SingletonWorker,
	domain *libvirt.Domain,
	domainUUID string,
) {
	t.Helper()
	if err := domain.Undefine(); err != nil {
		t.Fatalf("undefine replacement domain: %v", err)
	}
	if err := worker.doWork(conn); err != nil {
		t.Fatalf("inventory after removal: %v", err)
	}
	if _, ok := viocovWorkerCachedMetadata(worker, domainUUID); ok {
		t.Fatalf("removed UUID %q survived pruning sweep", domainUUID)
	}
}

func viocovWorkerCachedMetadata(
	worker *SingletonWorker,
	domainUUID string,
) (domainMetadataSnapshot, bool) {
	worker.inventoryCacheMu.Lock()
	defer worker.inventoryCacheMu.Unlock()
	metadata, ok := worker.metadataByUUID[domainUUID]
	return metadata, ok
}

func TestViocovMetadataMalformedAndBlankPayloads(t *testing.T) {
	conn := newTestLibvirtConn(t)
	dom := viocovDefineDomain(t, conn, viocovUniqueName("badmeta"), "")

	setRaw := func(access viocovMetadataAccess, payload string) {
		t.Helper()
		err := dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, payload, access.prefix, access.namespace, libvirt.DOMAIN_AFFECT_CONFIG)
		if err != nil {
			t.Fatalf("%s: setting raw metadata %q: %v", access.kind, payload, err)
		}
	}

	for _, access := range viocovMetadataAccessors() {
		// A payload with an unexpected root element must surface a parse error.
		setRaw(access, "<viocovwrongroot>x</viocovwrongroot>")
		if _, _, err := access.get(dom); err == nil {
			t.Fatalf("%s: expected parse error for wrong metadata root element", access.kind)
		}

		// A whitespace-only value is treated as absent, not as an error.
		setRaw(access, fmt.Sprintf("<%s> </%s>", access.kind, access.kind))
		value, has, err := access.get(dom)
		if err != nil {
			t.Fatalf("%s: reading blank metadata: %v", access.kind, err)
		}
		if has || value != "" {
			t.Fatalf("%s: expected blank metadata to be reported absent, got %q", access.kind, value)
		}
	}
}

func TestViocovMetadataGettersInvalidDomain(t *testing.T) {
	dom := &libvirt.Domain{}
	for _, access := range viocovMetadataAccessors() {
		if _, _, err := access.get(dom); err == nil {
			t.Fatalf("%s: expected error for an invalid domain handle", access.kind)
		}
	}
}

func TestViocovVMOwnerBranches(t *testing.T) {
	owner, has, err := VMOwner("   ")
	if err != nil || has || owner != "" {
		t.Fatalf("VMOwner(blank): expected no owner, got %q %v %v", owner, has, err)
	}

	owner, has, err = VMOwner(viocovUniqueName("absent"))
	if err != nil || has || owner != "" {
		t.Fatalf("VMOwner(missing domain): expected no owner, got %q %v %v", owner, has, err)
	}

	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("owner")
	dom := viocovDefineDomain(t, conn, name, "")

	owner, has, err = VMOwner(name)
	if err != nil || has || owner != "" {
		t.Fatalf("VMOwner(no metadata): expected no owner, got %q %v %v", owner, has, err)
	}

	if err := setDomainOwnerMetadata(dom, "cvio-alice"); err != nil {
		t.Fatalf("setting owner metadata: %v", err)
	}
	owner, has, err = VMOwner(name)
	if err != nil {
		t.Fatalf("VMOwner(with metadata): %v", err)
	}
	if !has || owner != "cvio-alice" {
		t.Fatalf("expected owner cvio-alice, got %q (has=%v)", owner, has)
	}
}

func TestViocovVMOwnerMalformedMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("ownerbad")
	dom := viocovDefineDomain(t, conn, name, "")

	err := dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		"<viocovwrongroot>x</viocovwrongroot>",
		domainOwnerMetadataPrefix,
		domainOwnerMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		t.Fatalf("setting malformed owner metadata: %v", err)
	}

	if _, _, err := VMOwner(name); err == nil {
		t.Fatal("expected VMOwner to surface the metadata parse error")
	}
	if _, err := UserOwnsVM(name, "cvio-alice"); err == nil {
		t.Fatal("expected UserOwnsVM to propagate the metadata error")
	}
}

func TestViocovUserOwnsVMMatchesOwnerMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("owned")
	dom := viocovDefineDomain(t, conn, name, "")

	if err := setDomainOwnerMetadata(dom, "cvio-bob"); err != nil {
		t.Fatalf("setting owner metadata: %v", err)
	}

	owned, err := UserOwnsVM(name, "cvio-bob")
	if err != nil {
		t.Fatalf("UserOwnsVM(owner): %v", err)
	}
	if !owned {
		t.Fatal("expected owner to own the VM")
	}

	owned, err = UserOwnsVM(name, "cvio-alice")
	if err != nil {
		t.Fatalf("UserOwnsVM(other): %v", err)
	}
	if owned {
		t.Fatal("did not expect a different user to own the VM")
	}
}
