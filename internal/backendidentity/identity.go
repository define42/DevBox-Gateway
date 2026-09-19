// Package backendidentity creates and verifies the identity provisioned into each VM's RDP server.
package backendidentity

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Credentials contains the public identity and private key installed through the
// VM's seed ISO. Only CertificatePEM and ServerName belong in host metadata.
type Credentials struct {
	CertificatePEM string
	PrivateKeyPEM  string
	ServerName     string
}

// Generate creates a distinct RSA key and TLS server identity for a new VM.
// Recreating a VM, even with the same name, creates an unrelated identity.
func Generate(vmName string) (Credentials, error) {
	if strings.TrimSpace(vmName) == "" {
		return Credentials{}, errors.New("backend identity requires a VM name")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate backend private key: %w", err)
	}
	identifier, err := uuid.NewRandom()
	if err != nil {
		return Credentials{}, fmt.Errorf("generate backend identity: %w", err)
	}
	serverName := "vm-" + identifier.String() + ".devbox.internal"
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(identifier[:]),
		Subject:               pkix.Name{CommonName: vmName},
		DNSNames:              []string{serverName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return Credentials{}, fmt.Errorf("create backend certificate: %w", err)
	}
	return Credentials{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		ServerName:     serverName,
	}, nil
}

// TLSConfig trusts exactly the certificate provisioned for the selected VM.
// Normal TLS verification checks the name, validity, and server usage before the
// additional leaf pin runs. System roots and certificates learned over the guest
// network are never trusted.
func TLSConfig(certificatePEM, serverName string) (*tls.Config, error) {
	if strings.TrimSpace(serverName) == "" {
		return nil, errors.New("backend server name is required")
	}
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("backend identity must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse backend identity: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: serverName}); err != nil {
		return nil, fmt.Errorf("invalid backend identity: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, certificate.Raw) {
				return errors.New("backend certificate does not match the provisioned VM identity")
			}
			return nil
		},
	}, nil
}
