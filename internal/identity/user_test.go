package identity

import (
	"testing"
)

func TestNewUser(t *testing.T) {
	user, err := NewUser("alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "alice" {
		t.Fatalf("expected name %q, got %q", "alice", user.Name)
	}
}
