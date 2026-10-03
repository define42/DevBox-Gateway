package cert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
)

func TestIsACMETLSALPN(t *testing.T) {
	if !IsACMETLSALPN(acmez.ACMETLS1Protocol) {
		t.Fatal("expected true for ACME TLS-ALPN protocol")
	}
	if IsACMETLSALPN("http/1.1") {
		t.Fatal("expected false for http/1.1")
	}
	if IsACMETLSALPN("") {
		t.Fatal("expected false for empty string")
	}
}

func TestResolveACMECA(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"staging", "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{"STAGING", "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{"  staging  ", "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{"production", "https://acme-v02.api.letsencrypt.org/directory"},
		{"prod", "https://acme-v02.api.letsencrypt.org/directory"},
		{"https://custom.ca/dir", "https://custom.ca/dir"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := resolveACMECA(tc.input); got != tc.want {
				t.Fatalf("resolveACMECA(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate")
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected non-nil private key")
	}
}

func TestSecureCipherSuiteIDs(t *testing.T) {
	ids := secureCipherSuiteIDs()
	if len(ids) == 0 {
		t.Fatal("expected at least one cipher suite ID")
	}

	// Verify all secure suites are included.
	for _, suite := range tls.CipherSuites() {
		found := false
		for _, id := range ids {
			if id == suite.ID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("cipher suite %s (0x%04x) not found", suite.Name, suite.ID)
		}
	}

	// Verify no insecure suites leak into the front-facing TLS config.
	for _, suite := range tls.InsecureCipherSuites() {
		for _, id := range ids {
			if id == suite.ID {
				t.Fatalf("insecure cipher suite %s (0x%04x) must not be offered", suite.Name, suite.ID)
			}
		}
	}
}

func TestNewTLSManagerWithoutACME(t *testing.T) {
	t.Setenv(config.ACME_ENABLE, "false")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	settings := config.NewSettings(false)

	tm, err := NewTLSManager(settings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm == nil {
		t.Fatal("expected non-nil TLSManager")
		return
	}
	cfg := tm.TLSConfig()
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
		return
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS1.2, got %v", cfg.MinVersion)
	}
}

func TestLoadOrGenerateCertNoFiles(t *testing.T) {
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_ENABLE, "false")
	settings := config.NewSettings(false)

	cert, err := LoadOrGenerateCert(settings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected generated certificate")
	}
}

func TestLoadOrGenerateCertOnlyOnePath(t *testing.T) {
	t.Setenv(config.CERT_FILE, "/tmp/cert.pem")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_ENABLE, "false")
	settings := config.NewSettings(false)

	_, err := LoadOrGenerateCert(settings)
	if err == nil {
		t.Fatal("expected error when only cert is provided")
	}
}

func TestLoadOrGenerateCertFromFiles(t *testing.T) {
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_ENABLE, "false")

	settings := config.NewSettings(false)
	generated, err := LoadOrGenerateCert(settings)
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}

	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generated.Certificate[0]}), 0o644); err != nil {
		t.Fatalf("write cert file: %v", err)
	}

	keyDER, ok := generated.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA private key, got %T", generated.PrivateKey)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyDER)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	t.Setenv(config.CERT_FILE, certPath)
	t.Setenv(config.KEY_FILE, keyPath)
	settings = config.NewSettings(false)

	loaded, err := LoadOrGenerateCert(settings)
	if err != nil {
		t.Fatalf("load cert pair: %v", err)
	}
	if len(loaded.Certificate) == 0 {
		t.Fatal("expected loaded certificate chain")
	}
}

func TestACMEGetCertificateFallback(t *testing.T) {
	fallback, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate fallback cert: %v", err)
	}

	getCertificate := acmeGetCertificate(certmagic.NewDefault(), fallback, "fallback.example.test")
	cert, err := getCertificate(nil)
	if err != nil {
		t.Fatalf("fallback for nil hello: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		t.Fatal("expected non-empty fallback certificate for nil hello")
	}

	cert, err = getCertificate(testCertificateHello(t, ""))
	if err != nil {
		t.Fatalf("fallback for empty hello: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		t.Fatal("expected non-empty fallback certificate for empty server name")
	}
}

func TestNewTLSManagerACMERequiresFrontDomain(t *testing.T) {
	snapshotCertmagicDefaults(t)
	t.Setenv(config.ACME_ENABLE, "true")
	t.Setenv(config.FRONT_DOMAIN, "")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")

	settings := config.NewSettings(false)
	if _, err := NewTLSManager(settings); err == nil {
		t.Fatal("expected ACME-enabled TLS manager without front domain to fail")
	}
}

func TestNewTLSManagerACMEDefersIssuance(t *testing.T) {
	snapshotCertmagicDefaults(t)
	// With ACME enabled and a front domain, NewTLSManager must prepare
	// certificate management without any network I/O: issuance is deferred to
	// StartManaging so it can run after the front listener is accepting
	// TLS-ALPN-01 validation.
	t.Setenv(config.ACME_ENABLE, "true")
	t.Setenv(config.FRONT_DOMAIN, "vdi.example.test")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.DATA_ROOT_DIR, t.TempDir())

	settings := config.NewSettings(false)
	tm, err := NewTLSManager(settings)
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}

	if tm.magic == nil {
		t.Fatal("expected certmagic config for ACME-enabled manager")
	}
	if len(tm.domains) != 1 || tm.domains[0] != "vdi.example.test" {
		t.Fatalf("expected initial domains [vdi.example.test], got %v", tm.domains)
	}
	// Issuance has not started, and closing the prepared manager must be safe.
	if err := tm.Close(); err != nil {
		t.Fatalf("Close before StartManaging should be a no-op, got %v", err)
	}
}

func TestStartManagingStaticNoop(t *testing.T) {
	t.Setenv(config.ACME_ENABLE, "false")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")

	settings := config.NewSettings(false)
	tm, err := NewTLSManager(settings)
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}

	if err := tm.StartManaging(); err != nil {
		t.Fatalf("StartManaging on a static manager should be a no-op, got %v", err)
	}
	if err := tm.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewManagedTLSConfigWraps(t *testing.T) {
	fallback, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate fallback cert: %v", err)
	}
	magic := certmagic.NewDefault()
	cfg := newManagedTLSConfig(magic, fallback, "managed.example.test")
	if cfg == nil {
		t.Fatal("expected non-nil tls config")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS1.2, got 0x%04x", cfg.MinVersion)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("expected GetCertificate to be set")
	}
	// HTTP/1.1 should be advertised first so non-ACME clients can negotiate the gateway.
	if len(cfg.NextProtos) == 0 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("expected http/1.1 as first NextProto, got %v", cfg.NextProtos)
	}
	if !slices.Contains(cfg.NextProtos, acmez.ACMETLS1Protocol) {
		t.Fatalf("expected TLS-ALPN certificate validation protocol, got %v", cfg.NextProtos)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("expected cipher suites to be populated")
	}

	// GetCertificate should return the fallback cert for nil/empty hello.
	cert, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected fallback certificate for nil hello")
	}
}

func TestInitialManagedDomains(t *testing.T) {
	tests := []struct {
		name        string
		frontDomain string
		want        string
	}{
		{name: "empty"},
		{name: "whitespace", frontDomain: "  "},
		{name: "single shared domain", frontDomain: "gateway.example.test", want: "gateway.example.test"},
		{name: "normalized shared domain", frontDomain: " Gateway.Example.Test ", want: "gateway.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domains, err := initialManagedDomains(tt.frontDomain)
			if tt.want == "" {
				if err == nil {
					t.Fatal("expected error when FRONT_DOMAIN is empty")
				}
				return
			}
			if err != nil {
				t.Fatalf("initial managed domains: %v", err)
			}
			if len(domains) != 1 || domains[0] != tt.want {
				t.Fatalf("managed domains = %v, want only %q", domains, tt.want)
			}
		})
	}
}

type blockingCertificateStorage struct {
	certmagic.Storage

	started chan context.Context
	release chan struct{}
	once    sync.Once
}

func (s *blockingCertificateStorage) Load(ctx context.Context, _ string) ([]byte, error) {
	s.once.Do(func() { s.started <- ctx })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.release:
		return nil, errors.New("test storage released")
	}
}

func TestTLSManagerCloseCancelsCertificateManagement(t *testing.T) {
	storage := &blockingCertificateStorage{
		Storage: &certmagic.FileStorage{Path: t.TempDir()},
		started: make(chan context.Context, 1),
		release: make(chan struct{}),
	}
	magic := certmagic.NewDefault()
	magic.Storage = storage
	manager := &TLSManager{
		magic:   magic,
		domains: []string{"shutdown.example.test"},
	}
	t.Cleanup(func() {
		close(storage.release)
		_ = manager.Close()
	})
	if err := manager.StartManaging(); err != nil {
		t.Fatalf("start certificate management: %v", err)
	}
	var operationCtx context.Context
	select {
	case operationCtx = <-storage.started:
	case <-time.After(time.Second):
		t.Fatal("certificate management did not start")
	}
	// Repeated startup must preserve the original operation's cancellation.
	if err := manager.StartManaging(); err != nil {
		t.Fatalf("repeat certificate management: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("close certificate management: %v", err)
	}
	select {
	case <-operationCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel certificate management")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("close certificate management again: %v", err)
	}
}

func TestTLSManagerClosedBeforeStart(t *testing.T) {
	manager := &TLSManager{
		magic:   certmagic.NewDefault(),
		domains: []string{"closed.example.test"},
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("close manager before startup: %v", err)
	}
	if err := manager.StartManaging(); err == nil {
		t.Fatal("expected certificate management after Close to be rejected")
	}
}

func TestACMEGetCertificateUsesOnlySharedDomain(t *testing.T) {
	const frontDomain = "shared-cert.example.test"
	const legacyDomain = "0123456789abcdef0123456789abcdef." + frontDomain
	fallback := testCertificateForDomain(t, "fallback-cert.example.test")
	shared := testCertificateForDomain(t, frontDomain)
	legacy := testCertificateForDomain(t, legacyDomain)
	magic := certmagic.NewDefault()
	magic.Storage = &certmagic.FileStorage{Path: t.TempDir()}
	for _, certificate := range []tls.Certificate{shared, legacy} {
		if _, err := magic.CacheUnmanagedTLSCertificate(t.Context(), certificate, nil); err != nil {
			t.Fatalf("cache test certificate: %v", err)
		}
	}
	getCertificate := acmeGetCertificate(magic, fallback, frontDomain)
	for _, serverName := range []string{frontDomain, "SHARED-CERT.EXAMPLE.TEST", ""} {
		t.Run("shared/"+serverName, func(t *testing.T) {
			got, err := getCertificate(testCertificateHello(t, serverName))
			if err != nil {
				t.Fatalf("get shared certificate: %v", err)
			}
			if !bytes.Equal(got.Certificate[0], shared.Certificate[0]) {
				t.Fatal("expected the shared domain certificate")
			}
		})
	}
	for _, serverName := range []string{legacyDomain, "foreign.example.test"} {
		t.Run("rejected/"+serverName, func(t *testing.T) {
			if _, err := getCertificate(testCertificateHello(t, serverName)); err == nil {
				t.Fatal("expected certificate selection for another domain to be rejected")
			}
		})
	}
}

func TestACMEGetCertificateDoesNotFallbackForChallenge(t *testing.T) {
	const frontDomain = "missing-challenge.example.test"
	fallback := testCertificateForDomain(t, frontDomain)
	magic := certmagic.NewDefault()
	magic.Storage = &certmagic.FileStorage{Path: t.TempDir()}
	getCertificate := acmeGetCertificate(magic, fallback, frontDomain)
	hello := testCertificateHello(t, frontDomain)
	hello.SupportedProtos = []string{acmez.ACMETLS1Protocol}
	if _, err := getCertificate(hello); err == nil {
		t.Fatal("expected missing ACME challenge to fail without serving fallback")
	}
}

func testCertificateHello(t *testing.T, serverName string) *tls.ClientHelloInfo {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return &tls.ClientHelloInfo{
		Conn:              server,
		ServerName:        serverName,
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.PSSWithSHA256, tls.PKCS1WithSHA256},
		CipherSuites:      secureCipherSuiteIDs(),
	}
}

func testCertificateForDomain(t *testing.T, domain string) tls.Certificate {
	t.Helper()
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	leaf.DNSNames = []string{domain}
	leaf.IPAddresses = nil
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, certificate.PrivateKey)
	if err != nil {
		t.Fatalf("sign test certificate: %v", err)
	}
	certificate.Certificate = [][]byte{der}
	certificate.Leaf = nil
	return certificate
}
