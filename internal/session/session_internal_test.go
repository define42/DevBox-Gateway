package session

import (
	"errors"
	"rdptlsgateway/internal/types"
	"testing"
)

func TestSessionUserNameNilUser(t *testing.T) {
	if got := sessionUserName(sessionData{}); got != "" {
		t.Fatalf("expected empty user name for nil user, got %q", got)
	}
}

func TestSessionUserNameTrims(t *testing.T) {
	user, err := types.NewUser("  alice  ", "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	got := sessionUserName(sessionData{User: user})
	if got != "alice" {
		t.Fatalf("expected trimmed name %q, got %q", "alice", got)
	}
}

func TestValidateSessionWithoutUser(t *testing.T) {
	m := NewManager()
	valid, err := m.validateSession(sessionData{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected validation to fail without a user")
	}
}

func TestValidateSessionNoValidator(t *testing.T) {
	m := NewManager()
	user, _ := types.NewUser("alice", "dogood")
	valid, err := m.validateSession(sessionData{User: user, Password: "dogood"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Fatal("expected session to be valid when no validator is configured")
	}
}

func TestValidateSessionEmptyPasswordWithValidator(t *testing.T) {
	m := NewManager()
	m.SetSessionValidator(func(_ string, _ string) (bool, error) {
		t.Fatal("validator should not be called when password is empty")
		return false, nil
	})
	user, _ := types.NewUser("alice", "dogood")
	valid, err := m.validateSession(sessionData{User: user, Password: "   "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected session with empty password to be invalid when validator is set")
	}
}

func TestValidateSessionDelegatesToValidator(t *testing.T) {
	m := NewManager()
	calls := 0
	m.SetSessionValidator(func(username, password string) (bool, error) {
		calls++
		if username != "alice" || password != "dogood" {
			t.Fatalf("unexpected validator args: %q/%q", username, password)
		}
		return true, nil
	})
	user, _ := types.NewUser("alice", "dogood")
	valid, err := m.validateSession(sessionData{User: user, Password: "dogood"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Fatal("expected validator success to mark session valid")
	}
	if calls != 1 {
		t.Fatalf("expected validator to be invoked once, got %d", calls)
	}
}

func TestValidateSessionPropagatesValidatorError(t *testing.T) {
	m := NewManager()
	wantErr := errors.New("validator failure")
	m.SetSessionValidator(func(_, _ string) (bool, error) {
		return false, wantErr
	})
	user, _ := types.NewUser("alice", "dogood")
	if _, err := m.validateSession(sessionData{User: user, Password: "dogood"}); !errors.Is(err, wantErr) {
		t.Fatalf("expected validator error, got %v", err)
	}
}
