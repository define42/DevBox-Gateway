package virt

import "testing"

func TestOwnedByUser(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		hasOwner bool
		username string
		want     bool
	}{
		{
			name:     "matching owner",
			owner:    "alice",
			hasOwner: true,
			username: "alice",
			want:     true,
		},
		{
			name:     "different owner",
			owner:    "bob",
			hasOwner: true,
			username: "alice",
			want:     false,
		},
		{
			name:     "prefix collision is not ownership",
			owner:    "alice-bob",
			hasOwner: true,
			username: "alice",
			want:     false,
		},
		{
			name:     "missing owner metadata",
			owner:    "",
			hasOwner: false,
			username: "alice",
			want:     false,
		},
		{
			name:     "blank username",
			owner:    "alice",
			hasOwner: true,
			username: "   ",
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ownedByUser(tc.owner, tc.hasOwner, tc.username)
			if got != tc.want {
				t.Fatalf("ownedByUser(%q, %v, %q) = %v, want %v", tc.owner, tc.hasOwner, tc.username, got, tc.want)
			}
		})
	}
}
