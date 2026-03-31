package contextkey

import (
	"context"
	"testing"
)

func TestWithAuthUserAndAuthUserFromContext(t *testing.T) {
	ctx := context.Background()
	ctx = WithAuthUser(ctx, "alice")

	user, ok := AuthUserFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if user != "alice" {
		t.Fatalf("expected %q, got %q", "alice", user)
	}
}

func TestAuthUserFromContextMissing(t *testing.T) {
	ctx := context.Background()

	user, ok := AuthUserFromContext(ctx)
	if ok {
		t.Fatal("expected ok=false for missing user")
	}
	if user != "" {
		t.Fatalf("expected empty string, got %q", user)
	}
}

func TestAuthUserFromContextEmpty(t *testing.T) {
	ctx := context.Background()
	ctx = WithAuthUser(ctx, "")

	_, ok := AuthUserFromContext(ctx)
	if ok {
		t.Fatal("expected ok=false for empty user")
	}
}
