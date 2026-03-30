package hash

import (
	"strings"
	"testing"
)

func TestCloudInitPasswordHash(t *testing.T) {
	hash, err := CloudInitPasswordHash("testpassword")
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

func TestCloudInitPasswordHashDifferentPasswords(t *testing.T) {
	h1, err := CloudInitPasswordHash("password1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := CloudInitPasswordHash("password2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 == h2 {
		t.Fatal("expected different hashes for different passwords")
	}
}

func TestCloudInitPasswordHashDifferentSalts(t *testing.T) {
	h1, err := CloudInitPasswordHash("same")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := CloudInitPasswordHash("same")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Random salts should produce different hashes (extremely unlikely to collide)
	if h1 == h2 {
		t.Fatal("expected different hashes due to different random salts")
	}
}
