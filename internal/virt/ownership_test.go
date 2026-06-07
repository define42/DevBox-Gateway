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

func TestOwnerAllowsReplace(t *testing.T) {
	tests := []struct {
		name      string
		owner     string
		hasOwner  bool
		requester string
		want      bool
	}{
		{
			name:      "owned by requester",
			owner:     "alice",
			hasOwner:  true,
			requester: "alice",
			want:      true,
		},
		{
			name:      "owned by another user",
			owner:     "bob",
			hasOwner:  true,
			requester: "alice",
			want:      false,
		},
		{
			name:      "prefix collision is another user",
			owner:     "alice-test",
			hasOwner:  true,
			requester: "alice",
			want:      false,
		},
		{
			name:      "legacy unowned vm is replaceable",
			owner:     "",
			hasOwner:  false,
			requester: "alice",
			want:      true,
		},
		{
			name:      "owner match after trimming",
			owner:     " alice ",
			hasOwner:  true,
			requester: "alice",
			want:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ownerAllowsReplace(tc.owner, tc.hasOwner, tc.requester)
			if got != tc.want {
				t.Fatalf("ownerAllowsReplace(%q, %v, %q) = %v, want %v", tc.owner, tc.hasOwner, tc.requester, got, tc.want)
			}
		})
	}
}
