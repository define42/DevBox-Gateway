// Package identity defines user identity types shared across the gateway.
package identity

// User represents an authenticated gateway user.
type User struct {
	Name string
}

// New creates a user.
func New(name string) (*User, error) {
	return &User{Name: name}, nil
}
