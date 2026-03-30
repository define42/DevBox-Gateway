package cert

import (
	"crypto/tls"
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
