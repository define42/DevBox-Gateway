package backendidentity

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func TestGenerateDistinctVMIdentities(t *testing.T) {
	t.Parallel()
	first := generateTestCredentials(t)
	second := generateTestCredentials(t)
	if first.ServerName == second.ServerName || first.PrivateKeyPEM == second.PrivateKeyPEM || first.CertificatePEM == second.CertificatePEM {
		t.Fatal("recreating the same VM must generate an unrelated identity")
	}
	if _, err := Generate(" "); err == nil {
		t.Fatal("expected an empty VM name to be rejected")
	}
}

func TestTLSConfigAuthenticatesProvisionedVM(t *testing.T) {
	t.Parallel()
	trusted := generateTestCredentials(t)
	impostor := generateTestCredentials(t)
	for _, tc := range []struct {
		name        string
		credentials Credentials
		wantError   bool
	}{
		{name: "provisioned VM", credentials: trusted},
		{name: "another VM", credentials: impostor, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config, err := TLSConfig(trusted.CertificatePEM, trusted.ServerName)
			if err != nil {
				t.Fatal(err)
			}
			if config.InsecureSkipVerify || config.MinVersion < tls.VersionTLS12 {
				t.Fatal("backend TLS must retain normal verification and require TLS 1.2")
			}
			if err := identityHandshake(t, config, tc.credentials); (err != nil) != tc.wantError {
				t.Fatalf("TLS handshake error = %v, want error %t", err, tc.wantError)
			}
		})
	}
}

func TestTLSConfigRejectsInvalidIdentity(t *testing.T) {
	t.Parallel()
	valid := generateTestCredentials(t)
	expired := expiredTestCertificate(t, valid)
	for _, tc := range []struct {
		name        string
		certificate string
		serverName  string
	}{
		{name: "missing certificate", serverName: valid.ServerName},
		{name: "missing name", certificate: valid.CertificatePEM},
		{name: "wrong name", certificate: valid.CertificatePEM, serverName: "impostor.devbox.internal"},
		{name: "invalid certificate", certificate: "not a certificate", serverName: valid.ServerName},
		{name: "certificate bundle", certificate: valid.CertificatePEM + valid.CertificatePEM, serverName: valid.ServerName},
		{name: "expired certificate", certificate: expired, serverName: valid.ServerName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := TLSConfig(tc.certificate, tc.serverName); err == nil {
				t.Fatal("expected invalid backend identity to be rejected")
			}
		})
	}
}

func TestTLSConfigRechecksExpiryAtHandshake(t *testing.T) {
	t.Parallel()
	credentials := generateTestCredentials(t)
	config, err := TLSConfig(credentials.CertificatePEM, credentials.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	config.Time = func() time.Time { return time.Now().AddDate(11, 0, 0) }
	if err := identityHandshake(t, config, credentials); err == nil {
		t.Fatal("a certificate that expires after configuration must fail the TLS handshake")
	}
}

func generateTestCredentials(t *testing.T) Credentials {
	t.Helper()
	credentials, err := Generate("alice.desktop")
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func expiredTestCertificate(t *testing.T, credentials Credentials) string {
	t.Helper()
	pair, err := tls.X509KeyPair([]byte(credentials.CertificatePEM), []byte(credentials.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	certificate.NotBefore = time.Now().Add(-2 * time.Hour)
	certificate.NotAfter = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, certificate.PublicKey, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func identityHandshake(t *testing.T, config *tls.Config, credentials Credentials) error {
	t.Helper()
	pair, err := tls.X509KeyPair([]byte(credentials.CertificatePEM), []byte(credentials.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
		_ = server.HandshakeContext(ctx)
	}()
	client := tls.Client(clientConn, config)
	err = client.HandshakeContext(ctx)
	_ = clientConn.Close()
	<-serverDone
	return err
}
