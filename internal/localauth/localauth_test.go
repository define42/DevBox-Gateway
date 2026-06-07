package localauth

import (
	"crypto/sha256"
	"encoding/hex"
	"rdptlsgateway/internal/config"
	"testing"
)

// digest returns the hex sha256 of "username:password", matching what an
// operator would put in LOCAL_USER_SHA256.
func digest(username, password string) string {
	sum := sha256.Sum256([]byte(username + ":" + password))
	return hex.EncodeToString(sum[:])
}

func settingsWith(t *testing.T, value string) *config.SettingsType {
	t.Helper()
	t.Setenv(config.LOCAL_USER_SHA256, value)
	return config.NewSettingType(false)
}

func TestValidateEmptyConfig(t *testing.T) {
	s := settingsWith(t, "")
	if Validate("alice", "secret", s) {
		t.Fatal("Validate should be false when LOCAL_USER_SHA256 is empty")
	}
}

func TestValidateSingleMatch(t *testing.T) {
	s := settingsWith(t, digest("alice", "s3cret"))
	if !Validate("alice", "s3cret", s) {
		t.Fatal("expected a match for the configured digest")
	}
	if Validate("alice", "wrong", s) {
		t.Fatal("wrong password must not match")
	}
	if Validate("bob", "s3cret", s) {
		t.Fatal("wrong username must not match")
	}
}

func TestValidateMultipleDigestsAndDelimiters(t *testing.T) {
	// Mixed case, surrounding spaces, an empty segment, and a trailing ';'.
	value := "  " + digest("alice", "a") + " ;; " + uppercase(digest("bob", "b")) + ";"
	s := settingsWith(t, value)

	if !Validate("alice", "a", s) {
		t.Fatal("alice should match")
	}
	if !Validate("bob", "b", s) {
		t.Fatal("bob should match despite uppercase hex and spacing")
	}
	if Validate("carol", "c", s) {
		t.Fatal("unconfigured user must not match")
	}
}

func TestValidateUsernamePasswordBoundary(t *testing.T) {
	// The digest is over the exact "username:password" string, so a shifted colon
	// (same concatenation, different split) must not be accepted.
	s := settingsWith(t, digest("alice", "secret"))
	if Validate("alice:secret", "", s) {
		t.Fatal("colon position must be significant")
	}
	if Validate("alice", ":secret", s) {
		t.Fatal("colon position must be significant")
	}
}

func uppercase(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
