package virt

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/backendidentity"
	"libvirt.org/go/libvirt"
)

func testBackendCredentials(t *testing.T) backendidentity.Credentials {
	t.Helper()
	credentials, err := backendidentity.Generate("security-test")
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func testNetworkReservation(t *testing.T, conn *libvirt.Connect, name string) NetworkIdentity {
	t.Helper()
	identity, err := reserveNetworkIdentity(conn, name)
	if err != nil {
		t.Fatalf("reserve test network: %v", err)
	}
	t.Cleanup(func() {
		if err := releaseNetworkIdentity(conn, name); err != nil {
			t.Errorf("release test network: %v", err)
		}
	})
	return identity
}

func defineProtectedTestDomain(t *testing.T, conn *libvirt.Connect, name, devices string) *libvirt.Domain {
	t.Helper()
	identity := testNetworkReservation(t, conn, name)
	credentials := testBackendCredentials(t)
	document := DomainXML(name, "seed.iso", "test", 1, 128, false, identity)
	_, iface, ok := strings.Cut(document, "<interface ")
	if !ok {
		t.Fatal("generated domain has no interface")
	}
	iface, _, ok = strings.Cut(iface, "</interface>")
	if !ok {
		t.Fatal("generated interface is unterminated")
	}
	dom := viocovDefineDomain(t, conn, name, devices+"<interface "+iface+"</interface>")
	if err := setDomainBackendIdentity(dom, credentials.CertificatePEM, credentials.ServerName); err != nil {
		t.Fatal(err)
	}
	return dom
}

func TestBackendMetadataBindsPublicIdentityToDomain(t *testing.T) {
	credentials := testBackendCredentials(t)
	metadata := domainBackendMetadata{
		UUID: "expected-domain", Certificate: credentials.CertificatePEM, ServerName: credentials.ServerName,
	}
	payload, err := xml.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "PRIVATE KEY") {
		t.Fatal("private key leaked into libvirt metadata")
	}
	if _, err := parseDomainBackendIdentity(string(payload), "expected-domain"); err != nil {
		t.Fatalf("valid persisted identity: %v", err)
	}
	for _, uuid := range []string{"different-domain", ""} {
		if _, err := parseDomainBackendIdentity(string(payload), uuid); err == nil {
			t.Errorf("accepted metadata for mismatched UUID %q", uuid)
		}
	}
	for _, bad := range []string{"", "<backend", `<backend uuid="expected-domain"/>`} {
		if _, err := parseDomainBackendIdentity(bad, "expected-domain"); err == nil {
			t.Errorf("accepted invalid metadata %q", bad)
		}
	}
}

func TestUnprotectedDomainFailsClosed(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("unprotected")
	dom := viocovDefineDomain(t, conn, name, "")
	for _, operation := range []func(string) error{StartExistingVM, RestartVM} {
		if err := operation(name); err == nil {
			t.Fatal("unprotected domain was allowed to start")
		}
	}
	if _, _, err := VMBackendIdentity(name); err == nil {
		t.Fatal("unprotected domain was given a backend identity")
	}
	if _, route := domainDisplayIPs(*dom, libvirt.DOMAIN_RUNNING); route != "" {
		t.Fatalf("unprotected domain has routing address %q", route)
	}
}

func TestProtectedDomainIdentityPersistsAndRejectsMissingMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("protected")
	dom := defineProtectedTestDomain(t, conn, name, "")
	certificate, serverName, err := VMBackendIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backendidentity.TLSConfig(certificate, serverName); err != nil {
		t.Fatal(err)
	}
	identity, err := domainNetworkIdentity(dom)
	if err != nil {
		t.Fatal(err)
	}
	if _, route := domainDisplayIPs(*dom, libvirt.DOMAIN_RUNNING); route != identity.IP {
		t.Fatalf("route = %q, want persisted assignment %q without a DHCP lease", route, identity.IP)
	}
	if err := dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "", "devboxgatewaybackend",
		domainBackendIdentityNamespace, libvirt.DOMAIN_AFFECT_CONFIG); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VMBackendIdentity(name); err == nil {
		t.Fatal("missing identity accepted")
	}
}
