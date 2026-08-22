package hash

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestRoutingLabelIsDeterministicAndValidDNSLabel(t *testing.T) {
	secret := []byte("server-secret")
	label := RoutingLabel(secret, "alice-desktop")

	if label != RoutingLabel(secret, "alice-desktop") {
		t.Fatal("expected RoutingLabel to be deterministic for the same inputs")
	}
	if len(label) != routingLabelLen {
		t.Fatalf("expected label length %d, got %d", routingLabelLen, len(label))
	}
	if len(label) > 63 {
		t.Fatalf("label %q exceeds the 63-octet DNS label limit", label)
	}
	if _, err := hex.DecodeString(label); err != nil {
		t.Fatalf("expected label to be hex, got %q: %v", label, err)
	}
	if strings.Contains(label, "alice") || strings.Contains(label, "desktop") {
		t.Fatalf("label %q must not leak the VM name", label)
	}
}

func TestRoutingLabelVariesByNameAndSecret(t *testing.T) {
	secretA := []byte("secret-a")
	secretB := []byte("secret-b")

	if RoutingLabel(secretA, "vm1") == RoutingLabel(secretA, "vm2") {
		t.Fatal("expected different VM names to produce different labels")
	}
	if RoutingLabel(secretA, "vm1") == RoutingLabel(secretB, "vm1") {
		t.Fatal("expected different secrets to produce different labels")
	}
}

func TestCloudInitPassword(t *testing.T) {
	hash, err := CloudInitPassword("testpassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	// SHA-512 crypt hashes start with $6$
	if !strings.HasPrefix(hash, "$6$") {
		t.Fatalf("expected hash to start with $6$, got %q", hash)
	}
}

func TestCloudInitPasswordDifferentPasswords(t *testing.T) {
	h1, err := CloudInitPassword("password1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := CloudInitPassword("password2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 == h2 {
		t.Fatal("expected different hashes for different passwords")
	}
}

func TestCloudInitPasswordDifferentSalts(t *testing.T) {
	h1, err := CloudInitPassword("same")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := CloudInitPassword("same")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Random salts should produce different hashes (extremely unlikely to collide)
	if h1 == h2 {
		t.Fatal("expected different hashes due to different random salts")
	}
}
