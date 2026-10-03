package cert

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"

	"github.com/caddyserver/certmagic"
)

// snapshotCertmagicDefaults restores the certmagic package globals mutated by
// configureACMEDefaults once the test finishes, so tests stay order-independent.
func snapshotCertmagicDefaults(t *testing.T) {
	t.Helper()

	prevEmail := certmagic.DefaultACME.Email
	prevCA := certmagic.DefaultACME.CA
	prevAgreed := certmagic.DefaultACME.Agreed
	prevDisableHTTP := certmagic.DefaultACME.DisableHTTPChallenge
	prevStorage := certmagic.Default.Storage
	t.Cleanup(func() {
		certmagic.DefaultACME.Email = prevEmail
		certmagic.DefaultACME.CA = prevCA
		certmagic.DefaultACME.Agreed = prevAgreed
		certmagic.DefaultACME.DisableHTTPChallenge = prevDisableHTTP
		certmagic.Default.Storage = prevStorage
	})
}

func TestConfigureACMEDefaultsWithEmailAndCA(t *testing.T) {
	snapshotCertmagicDefaults(t)
	t.Setenv(config.ACME_EMAIL, "ops@covx.example.test")
	t.Setenv(config.ACME_CA, "staging")
	t.Setenv(config.DATA_ROOT_DIR, t.TempDir())
	settings := config.NewSettings(false)

	configureACMEDefaults(settings)

	if got := certmagic.DefaultACME.Email; got != "ops@covx.example.test" {
		t.Fatalf("expected ACME email to be applied, got %q", got)
	}
	if got := certmagic.DefaultACME.CA; got != certmagic.LetsEncryptStagingCA {
		t.Fatalf("expected staging CA %q, got %q", certmagic.LetsEncryptStagingCA, got)
	}
	if !certmagic.DefaultACME.Agreed || !certmagic.DefaultACME.DisableHTTPChallenge {
		t.Fatal("expected ACME defaults to agree to terms and disable the HTTP challenge")
	}
}

func TestStartManagingBeginsBackgroundManagement(t *testing.T) {
	snapshotCertmagicDefaults(t)
	t.Setenv(config.ACME_ENABLE, "true")
	t.Setenv(config.FRONT_DOMAIN, "covx-start.example.test")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_EMAIL, "")
	t.Setenv(config.ACME_CA, "")
	t.Setenv(config.DATA_ROOT_DIR, t.TempDir())
	settings := config.NewSettings(false)

	tm, err := NewTLSManager(settings)
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}
	// Switch the config to on-demand allowlisting so ManageAsync records the
	// initial domains without performing any ACME network I/O in this test.
	tm.magic.OnDemand = new(certmagic.OnDemandConfig)

	if err := tm.StartManaging(); err != nil {
		t.Fatalf("StartManaging: %v", err)
	}
	got := tm.domains
	if len(got) != 1 || got[0] != "covx-start.example.test" {
		t.Fatalf("expected managed domains [covx-start.example.test], got %v", got)
	}
	if err := tm.Close(); err != nil {
		t.Fatalf("Close after StartManaging: %v", err)
	}
}

func TestACMEGetCertificateUnmanagedServerName(t *testing.T) {
	fallback, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate fallback cert: %v", err)
	}

	magic := certmagic.NewDefault()
	magic.Storage = &certmagic.FileStorage{Path: t.TempDir()}

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	getCertificate := acmeGetCertificate(magic, fallback, "shared.example.test")
	serverName := fmt.Sprintf("covx-unmanaged-%d.example.test", time.Now().UnixNano())
	if _, err := getCertificate(&tls.ClientHelloInfo{ServerName: serverName, Conn: server}); err == nil {
		t.Fatal("expected error for a server name with no managed certificate")
	}
}
