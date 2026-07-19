package cert

import (
	"context"
	"crypto/tls"
	"devboxgateway/internal/config"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	settings := config.NewSettingType(false)

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
	settings := config.NewSettingType(false)

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
	got := tm.managedDomains()
	if len(got) != 1 || got[0] != "covx-start.example.test" {
		t.Fatalf("expected managed domains [covx-start.example.test], got %v", got)
	}
	if err := tm.Close(); err != nil {
		t.Fatalf("Close after StartManaging: %v", err)
	}
}

func TestWorkerTickUpdatesDomains(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "covx-tick.example.test")
	t.Setenv(config.SNI_HASH_SECRET, "covx-secret")
	settings := config.NewSettingType(false)

	magic := certmagic.NewDefault()
	// On-demand allowlisting keeps the periodic ManageSync entirely offline.
	magic.OnDemand = new(certmagic.OnDemandConfig)
	magic.Storage = &certmagic.FileStorage{Path: t.TempDir()}

	manager := &TLSManager{magic: magic, settings: settings, workerDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())

	go manager.worker(ctx, time.NewTicker(25*time.Millisecond))

	deadline := time.Now().Add(10 * time.Second)
	for len(manager.managedDomains()) == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for a worker tick to update managed domains")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-manager.workerDone

	if got := manager.managedDomains(); len(got) == 0 || got[0] != "covx-tick.example.test" {
		t.Fatalf("expected front domain first in managed domains, got %v", got)
	}
}

func TestUpdateDomainsManageSyncError(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "covx-err.example.test")
	t.Setenv(config.SNI_HASH_SECRET, "covx-secret")
	settings := config.NewSettingType(false)

	// A regular file as the storage path makes every storage access fail with
	// ENOTDIR, so ManageSync errors out quickly without any network I/O.
	storagePath := filepath.Join(t.TempDir(), "storage-is-a-file")
	if err := os.WriteFile(storagePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write storage placeholder file: %v", err)
	}

	magic := certmagic.NewDefault()
	magic.Storage = &certmagic.FileStorage{Path: storagePath}

	manager := &TLSManager{magic: magic, settings: settings}
	manager.updateDomains()

	if got := manager.managedDomains(); len(got) != 0 {
		t.Fatalf("expected managed domains unchanged after ManageSync failure, got %v", got)
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

	getCertificate := acmeGetCertificate(magic, fallback)
	serverName := fmt.Sprintf("covx-unmanaged-%d.example.test", time.Now().UnixNano())
	if _, err := getCertificate(&tls.ClientHelloInfo{ServerName: serverName, Conn: server}); err == nil {
		t.Fatal("expected error for a server name with no managed certificate")
	}
}
