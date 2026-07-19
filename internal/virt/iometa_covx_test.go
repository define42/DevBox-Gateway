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
