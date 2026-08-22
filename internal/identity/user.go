// Package identity defines user identity types shared across the gateway.
package identity

// User represents an authenticated gateway user.
type User struct {
	Name string
	// IsAdmin reports whether authentication granted administrator access for
	// this session. Its zero value is deliberately fail-closed.
	IsAdmin bool
}

// New creates a non-administrator user. Directory authentication may promote
// the returned identity after verifying direct membership in the configured
// administrator group.
func New(name string) (*User, error) {
	return &User{Name: name}, nil
}
