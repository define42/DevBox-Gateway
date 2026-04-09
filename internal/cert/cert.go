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
	"fmt"
	"log"
	"math/big"
	"net"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/virt"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
)

// TLSManager owns the frontend TLS configuration and ACME domain updates.
type TLSManager struct {
	magic     *certmagic.Config
	settings  *config.SettingsType
	tlsConfig *tls.Config
	domains   []string
}

// GetTLSConfig returns the tls.Config used for incoming frontend connections.
func (tm *TLSManager) GetTLSConfig() *tls.Config {
	return tm.tlsConfig
}

func (tm *TLSManager) worker() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		for range ticker.C {
			tm.updateDomains()
		}
	}
}

func (tm *TLSManager) updateDomains() {
	vmNames := virt.GetInstance().GetVMnames()
	frontPageDomain := tm.settings.Get(config.FRONT_DOMAIN)

	var domains []string
	domains = append(domains, frontPageDomain)

	for _, name := range vmNames {
		domains = append(domains, name+"."+frontPageDomain)
	}

	if sameElements(tm.domains, domains) {
		return
	}
	if err := tm.magic.ManageSync(context.Background(), domains); err != nil {
		log.Printf("acme: error updating managed domains: %v", err)
		return
	}
	tm.domains = domains
	log.Printf("acme: updated managed domains: %s", strings.Join(tm.domains, ", "))
}

// NewTLSManager builds the frontend TLS manager from the active settings.
func NewTLSManager(settings *config.SettingsType) (*TLSManager, error) {
	fallback, err := LoadOrGenerateCert(settings)
	if err != nil {
		log.Fatalf("cert setup: %v", err)
		return nil, err
	}

	if !settings.IsTrue(config.ACME_ENABLE) {
		return newStaticTLSManager(settings, fallback), nil
	}

	return newACMETLSManager(settings, fallback)
}

// LoadOrGenerateCert loads the configured certificate pair or creates a self-signed fallback.
func LoadOrGenerateCert(settings *config.SettingsType) (tls.Certificate, error) {
	certPath := settings.Get(config.CERT_FILE)
	keyPath := settings.Get(config.KEY_FILE)
	acmeEnabled := settings.IsTrue(config.ACME_ENABLE)
	if certPath == "" && keyPath == "" {
		if acmeEnabled {
			log.Printf("acme enabled; no -cert/-key provided; generating self-signed fallback certificate for non-SNI clients")
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

func newStaticTLSManager(settings *config.SettingsType, fallback tls.Certificate) *TLSManager {
	frontTLS := &tls.Config{
		Certificates: []tls.Certificate{fallback},
	}

	frontTLS.MinVersion = tls.VersionTLS10
	frontTLS.CipherSuites = allCipherSuiteIDs()

	return &TLSManager{
		tlsConfig: frontTLS,
		settings:  settings,
	}
}

func newACMETLSManager(settings *config.SettingsType, fallback tls.Certificate) (*TLSManager, error) {
	configureACMEDefaults(settings)

	domains, err := initialManagedDomains(settings.Get(config.FRONT_DOMAIN))
	if err != nil {
		return nil, err
	}

	magic := certmagic.NewDefault()
	log.Printf("acme: pre-issuing certificates for: %s", strings.Join(domains, ", "))
	if err := magic.ManageSync(context.Background(), domains); err != nil {
		return nil, err
	}

	tm := &TLSManager{
		magic:     magic,
		tlsConfig: newManagedTLSConfig(magic, fallback),
		settings:  settings,
	}
	go tm.worker()

	return tm, nil
}

func configureACMEDefaults(settings *config.SettingsType) {
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

func initialManagedDomains(frontPageDomain string) ([]string, error) {
	var domains []string
	if frontPageDomain != "" {
		domains = append(domains, frontPageDomain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("acme enabled but no explicit hostnames provided in -routes or -frontpage-domain")
	}
	return domains, nil
}

func newManagedTLSConfig(magic *certmagic.Config, fallback tls.Certificate) *tls.Config {
	tlsCfg := magic.TLSConfig()
	tlsCfg.NextProtos = append([]string{"http/1.1"}, tlsCfg.NextProtos...)
	tlsCfg.GetCertificate = acmeGetCertificate(magic, fallback)
	tlsCfg.MinVersion = tls.VersionTLS10 // RDP backend compatibility
	tlsCfg.CipherSuites = allCipherSuiteIDs()
	return tlsCfg
}

func acmeGetCertificate(magic *certmagic.Config, fallback tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName == "" {
			return &fallback, nil
		}
		return magic.GetCertificate(hello)
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
			CommonName: "rdp-tls-gateway",
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

func sameElements(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	count := make(map[string]int, len(a))
	for _, s := range a {
		count[s]++
	}

	for _, s := range b {
		if count[s] == 0 {
			return false
		}
		count[s]--
	}

	return true
}

func allCipherSuiteIDs() []uint16 {
	suites := make([]uint16, 0, len(tls.CipherSuites())+len(tls.InsecureCipherSuites()))
	for _, suite := range tls.CipherSuites() {
		suites = append(suites, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		suites = append(suites, suite.ID)
	}
	return suites
}
