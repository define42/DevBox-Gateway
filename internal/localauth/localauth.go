// Package localauth validates users against a static list of
// sha256("<username>:<password>") digests supplied via the LOCAL_USER_SHA256
// setting. It is an offline alternative to (and is checked alongside) LDAP, so
// the gateway can authenticate a small set of accounts without a directory.
package localauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"rdptlsgateway/internal/config"
	"strings"
)

// digestSeparator delimits individual digests inside LOCAL_USER_SHA256.
const digestSeparator = ";"

// Validate reports whether sha256("<username>:<password>") matches one of the
// hex digests configured in LOCAL_USER_SHA256 (a ';'-delimited list). It returns
// false when no local users are configured, so it is safe to call
// unconditionally before falling back to LDAP.
//
// Generate a digest for an account with, e.g.:
//
//	printf '%s:%s' alice 's3cret' | sha256sum
func Validate(username, password string, settings *config.SettingsType) bool {
	raw := strings.TrimSpace(settings.Get(config.LOCAL_USER_SHA256))
	if raw == "" {
		return false
	}

	sum := sha256.Sum256([]byte(username + ":" + password))
	want := []byte(hex.EncodeToString(sum[:]))

	// Scan every configured digest (without short-circuiting) and compare each
	// in constant time so a match neither leaks which entry matched nor compares
	// the user-derived digest byte-by-byte.
	matched := false
	for _, entry := range strings.Split(raw, digestSeparator) {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(entry), want) == 1 {
			matched = true
		}
	}
	return matched
}
