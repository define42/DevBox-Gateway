package types

import (
	"strings"
	"testing"
)

func TestNewUser(t *testing.T) {
	user, err := NewUser("alice", "secret123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.GetName() != "alice" {
		t.Fatalf("expected name %q, got %q", "alice", user.GetName())
	}
	hash := user.GetCloudInitPasswordHash()
	if hash == "" {
		t.Fatal("expected non-empty password hash")
	}
	if !strings.HasPrefix(hash, "$6$") {
		t.Fatalf("expected SHA-512 hash prefix $6$, got %q", hash)
	}
}

func TestNewUserFieldAccess(t *testing.T) {
	user, err := NewUser("bob", "pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "bob" {
		t.Fatalf("expected Name %q, got %q", "bob", user.Name)
	}
	if user.CloudInitPasswordHash == "" {
		t.Fatal("expected CloudInitPasswordHash to be set")
	}
}
