// Package identity defines user identity types shared across the gateway.
package identity

// User represents an authenticated gateway user.
type User struct {
	Name string
}

// NewUser creates a user.
func NewUser(name string) (*User, error) {
	return &User{Name: name}, nil
}
