// Package cert manages frontend TLS certificates and certificate lifecycle.
package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/internal/config"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
)

// TLSManager owns the shared frontend TLS configuration and ACME lifecycle.
type TLSManager struct {
	magic       *certmagic.Config
	tlsConfig   *tls.Config
	domains     []string
	startOnce   sync.Once
	startErr    error
	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	closed      bool
}

// TLSConfig returns the tls.Config used for incoming frontend connections.
func (tm *TLSManager) TLSConfig() *tls.Config {
	return tm.tlsConfig
}

// Close cancels ACME issuance and retries. It is safe to call more than once.
func (tm *TLSManager) Close() error {
	tm.lifecycleMu.Lock()
	tm.closed = true
	cancel := tm.cancel
	tm.lifecycleMu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

// NewTLSManager builds the frontend TLS manager from the active settings. When
// ACME is enabled it prepares certificate management but does not yet obtain any
// certificates: the caller must invoke StartManaging once the front listener is
// accepting connections, so that ACME TLS-ALPN-01 validation can be answered.
func NewTLSManager(settings *config.Settings) (*TLSManager, error) {
	acmeEnabled := settings.IsTrue(config.ACME_ENABLE)
	fallback, err := LoadOrGenerateCert(settings)
	if err != nil {
		log.Fatalf("cert setup: %v", err)
		return nil, err
	}

	if !acmeEnabled {
		return newStaticTLSManager(fallback), nil
	}

	return newACMETLSManager(settings, fallback)
}

// LoadOrGenerateCert loads the configured certificate pair or creates a self-signed fallback.
func LoadOrGenerateCert(settings *config.Settings) (tls.Certificate, error) {
	certPath := settings.Get(config.CERT_FILE)
	keyPath := settings.Get(config.KEY_FILE)
	acmeEnabled := settings.IsTrue(config.ACME_ENABLE)
	if certPath == "" && keyPath == "" {
		if acmeEnabled {
			log.Printf("acme enabled; no -cert/-key provided; generating self-signed fallback certificate")
		} else {
			log.Printf("no -cert/-key provided; generating self-signed certificate for this run")
		}
		return generateSelfSignedCert()
	}
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("both -cert and -key must be provided, or neither for auto-generated cert")
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// IsACMETLSALPN reports whether the negotiated ALPN protocol is ACME TLS-ALPN-01.
func IsACMETLSALPN(protocol string) bool {
	return protocol == acmez.ACMETLS1Protocol
}

func newStaticTLSManager(fallback tls.Certificate) *TLSManager {
	frontTLS := &tls.Config{
		Certificates: []tls.Certificate{fallback},
	}

	frontTLS.MinVersion = tls.VersionTLS12
	frontTLS.CipherSuites = secureCipherSuiteIDs()

	return &TLSManager{
		tlsConfig: frontTLS,
	}
}

func newACMETLSManager(
	settings *config.Settings,
	fallback tls.Certificate,
) (*TLSManager, error) {
	configureACMEDefaults(settings)

	domains, err := initialManagedDomains(settings.Get(config.FRONT_DOMAIN))
	if err != nil {
		return nil, err
	}

	magic := certmagic.NewDefault()

	return &TLSManager{
		magic:     magic,
		tlsConfig: newManagedTLSConfig(magic, fallback, domains[0]),
		domains:   domains,
	}, nil
}

// StartManaging begins ACME certificate management. It must be called only after
// the gateway's front listener is accepting connections, because ACME
// TLS-ALPN-01 validation is answered through that listener's TLS handshakes.
// Certificates are obtained in the background with exponential-backoff retry,
// so a transient validation failure at startup does not block the gateway: it
// serves the self-signed fallback certificate until issuance succeeds. For a
// static (non-ACME) manager this is a no-op.
func (tm *TLSManager) StartManaging() error {
	if tm.magic == nil {
		return nil
	}

	tm.startOnce.Do(func() {
		tm.lifecycleMu.Lock()
		if tm.closed {
			tm.startErr = errors.New("cert: TLS manager is closed")
			tm.lifecycleMu.Unlock()
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		tm.cancel = cancel
		tm.lifecycleMu.Unlock()

		log.Printf("acme: managing certificate for: %s", strings.Join(tm.domains, ", "))
		if err := tm.magic.ManageAsync(ctx, tm.domains); err != nil {
			cancel()
			tm.startErr = fmt.Errorf("acme: manage domain: %w", err)
		}
	})
	return tm.startErr
}

func configureACMEDefaults(settings *config.Settings) {
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DisableHTTPChallenge = true

	email := settings.Get(config.ACME_EMAIL)
	if email != "" {
		certmagic.DefaultACME.Email = email
	} else {
		log.Printf("acme: no -acme-email provided; account registration may be rejected by some CAs")
	}

	if ca := settings.Get(config.ACME_CA); ca != "" {
		certmagic.DefaultACME.CA = resolveACMECA(ca)
	}
	if storage := config.ACMEStorageDir(settings); storage != "" {
		certmagic.Default.Storage = &certmagic.FileStorage{Path: storage}
	}
}

func initialManagedDomains(frontDomain string) ([]string, error) {
	frontDomain = strings.ToLower(strings.TrimSpace(frontDomain))
	if frontDomain == "" {
		return nil, errors.New("acme enabled but FRONT_DOMAIN is empty")
	}
	return []string{frontDomain}, nil
}

func newManagedTLSConfig(magic *certmagic.Config, fallback tls.Certificate, frontDomain string) *tls.Config {
	tlsCfg := magic.TLSConfig()
	tlsCfg.NextProtos = append([]string{"http/1.1"}, tlsCfg.NextProtos...)
	tlsCfg.GetCertificate = acmeGetCertificate(magic, fallback, frontDomain)
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.CipherSuites = secureCipherSuiteIDs()
	return tlsCfg
}

func acmeGetCertificate(
	magic *certmagic.Config,
	fallback tls.Certificate,
	frontDomain string,
) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil {
			return &fallback, nil
		}
		if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, frontDomain) {
			return nil, errors.New("tls: server name does not match FRONT_DOMAIN")
		}
		// Use the shared certificate for clients without SNI too. Copying the
		// hello preserves its handshake context and TLS-ALPN challenge fields.
		sharedHello := *hello
		sharedHello.ServerName = frontDomain
		certificate, err := magic.GetCertificate(&sharedHello)
		if err != nil && !slices.Contains(hello.SupportedProtos, acmez.ACMETLS1Protocol) {
			return &fallback, nil
		}
		return certificate, err
	}
}

func resolveACMECA(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "staging":
		return certmagic.LetsEncryptStagingCA
	case "production", "prod":
		return certmagic.LetsEncryptProductionCA
	default:
		return raw
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "devbox-gateway",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// secureCipherSuiteIDs returns the IDs of the cipher suites Go considers secure
// for TLS 1.2. Suites from tls.InsecureCipherSuites() (RC4, 3DES, CBC-SHA, …) are
// intentionally excluded so the credential-bearing dashboard and RDP front are
// not exposed to downgrade/weak-cipher attacks. TLS 1.3 suites are not
// configurable and are negotiated automatically.
func secureCipherSuiteIDs() []uint16 {
	suites := make([]uint16, 0, len(tls.CipherSuites()))
	for _, suite := range tls.CipherSuites() {
		suites = append(suites, suite.ID)
	}
	return suites
}
