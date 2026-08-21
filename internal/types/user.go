// Package types defines shared data structures used across the gateway.
package types

// User represents an authenticated gateway user.
type User struct {
	Name string
}

// NewUser creates a user.
func NewUser(name string) (*User, error) {
	return &User{Name: name}, nil
}
