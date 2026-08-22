package identity

import (
	"testing"
)

func TestNewUser(t *testing.T) {
	user, err := New("alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "alice" {
		t.Fatalf("expected name %q, got %q", "alice", user.Name)
	}
	if user.IsAdmin {
		t.Fatal("expected a newly created user to be a non-administrator")
	}
}
