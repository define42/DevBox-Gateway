package cert

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"testing"

	"github.com/mholt/acmez"
)

func TestSameElements(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both empty", nil, nil, true},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"equal different order", []string{"b", "a"}, []string{"a", "b"}, true},
		{"different lengths", []string{"a"}, []string{"a", "b"}, false},
		{"different elements", []string{"a", "c"}, []string{"a", "b"}, false},
		{"duplicates equal", []string{"a", "a"}, []string{"a", "a"}, true},
		{"duplicates different count", []string{"a", "a"}, []string{"a", "b"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameElements(tc.a, tc.b); got != tc.want {
				t.Fatalf("sameElements(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

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

func TestAllCipherSuiteIDs(t *testing.T) {
	ids := allCipherSuiteIDs()
	if len(ids) == 0 {
		t.Fatal("expected at least one cipher suite ID")
	}

	// Verify all secure suites are included
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
}

func TestNewTLSManagerWithoutACME(t *testing.T) {
	t.Setenv(config.ACME_ENABLE, "false")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	settings := config.NewSettingType(false)

	tm, err := NewTLSManager(settings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm == nil {
		t.Fatal("expected non-nil TLSManager")
	}
	cfg := tm.GetTLSConfig()
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if cfg.MinVersion != tls.VersionTLS10 {
		t.Fatalf("expected MinVersion TLS1.0, got %v", cfg.MinVersion)
	}
}

func TestLoadOrGenerateCertNoFiles(t *testing.T) {
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_ENABLE, "false")
	settings := config.NewSettingType(false)

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
	settings := config.NewSettingType(false)

	_, err := LoadOrGenerateCert(settings)
	if err == nil {
		t.Fatal("expected error when only cert is provided")
	}
}

func TestLoadOrGenerateCertFromFiles(t *testing.T) {
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_ENABLE, "false")

	settings := config.NewSettingType(false)
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
	settings = config.NewSettingType(false)

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

	getCertificate := acmeGetCertificate(nil, fallback)
	cert, err := getCertificate(nil)
	if err != nil {
		t.Fatalf("fallback for nil hello: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		t.Fatal("expected non-empty fallback certificate for nil hello")
	}

	cert, err = getCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("fallback for empty hello: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		t.Fatal("expected non-empty fallback certificate for empty server name")
	}
}

func TestNewTLSManagerACMERequiresFrontDomain(t *testing.T) {
	t.Setenv(config.ACME_ENABLE, "true")
	t.Setenv(config.FRONT_DOMAIN, "")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")

	settings := config.NewSettingType(false)
	if _, err := NewTLSManager(settings); err == nil {
		t.Fatal("expected ACME-enabled TLS manager without front domain to fail")
	}
}

func TestUpdateDomainsNoChange(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	manager := &TLSManager{
		settings: settings,
		domains:  []string{"example.test"},
	}
	manager.updateDomains()

	if len(manager.domains) != 1 || manager.domains[0] != "example.test" {
		t.Fatalf("expected domains to remain unchanged, got %v", manager.domains)
	}
}
