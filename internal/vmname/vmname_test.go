package vmname

import (
	"strings"
	"testing"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"simple", "johndoe", "johndoe", false},
		{"trimmed", "  johndoe  ", "johndoe", false},
		{"email/upn form", "john.doe+test@example.com", "john.doe+test@example.com", false},
		{"uppercase allowed", "JohnDoe", "JohnDoe", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"path separator", "../etc", "", true},
		{"backslash", `a\b`, "", true},
		{"xml metacharacter", "a<b", "", true},
		{"space inside", "john doe", "", true},
		{"too long", strings.Repeat("a", MaxUsernameLength+1), "", true},
		{"max length", strings.Repeat("a", MaxUsernameLength), strings.Repeat("a", MaxUsernameLength), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateUsername(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid", "my-vm-1", "my-vm-1", false},
		{"trimmed", "  web  ", "web", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"leading hyphen", "-web", "", true},
		{"trailing hyphen", "web-", "", true},
		{"uppercase", "Web", "", true},
		{"underscore", "my_vm", "", true},
		{"space", "my vm", "", true},
		{"too long", strings.Repeat("a", MaxHostnameLength+1), "", true},
		{"max length", strings.Repeat("a", MaxHostnameLength), strings.Repeat("a", MaxHostnameLength), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateHostname(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestCompose(t *testing.T) {
	tests := []struct {
		name     string
		username string
		hostname string
		want     string
		wantErr  bool
	}{
		{"simple", "alice", "web", "alice.web", false},
		{"email owner", "alice@example.com", "web", "alice@example.com.web", false},
		{"trims both parts", "  alice  ", "  web  ", "alice.web", false},
		{"hyphenated owner and hostname join unambiguously", "alice-test", "web-1", "alice-test.web-1", false},
		{"empty username", "", "web", "", true},
		{"empty hostname", "alice", "", "", true},
		{"whitespace hostname", "alice", "   ", "", true},
		{"bad username char", "ali/ce", "web", "", true},
		{"bad hostname char", "alice", "Web", "", true},
		{"hostname leading hyphen", "alice", "-web", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Compose(tc.username, tc.hostname)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for (%q, %q)", tc.username, tc.hostname)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for (%q, %q): %v", tc.username, tc.hostname, err)
			}
			if got != tc.want {
				t.Fatalf("Compose(%q, %q) = %q, want %q", tc.username, tc.hostname, got, tc.want)
			}
		})
	}
}

// TestComposeAlwaysHasOwnerPrefix asserts the core invariant: every composed VDI
// name starts with the trimmed "<username>-" owner prefix.
func TestComposeAlwaysHasOwnerPrefix(t *testing.T) {
	cases := []struct {
		username string
		hostname string
	}{
		{"alice", "web"},
		{"alice@example.com", "web"},
		{"alice-test", "web"},
		{"  bob  ", "db-1"},
	}
	for _, c := range cases {
		got, err := Compose(c.username, c.hostname)
		if err != nil {
			t.Fatalf("Compose(%q, %q): unexpected error %v", c.username, c.hostname, err)
		}
		owner := strings.TrimSpace(c.username)
		if !HasOwnerPrefix(got, owner) {
			t.Fatalf("composed name %q does not start with owner prefix %q-", got, owner)
		}
	}
}

// TestComposeRejectsReportedCollision is the regression test for the exact
// VDI-name ambiguity called out in the security report. Under the old "-" join,
// Compose("alice","bob-x") and Compose("alice-bob","x") both produced
// "alice-bob-x", letting one user squat on another user's namespace and collide
// on one libvirt domain. They must now produce distinct names.
func TestComposeRejectsReportedCollision(t *testing.T) {
	a, err := Compose("alice", "bob-x")
	if err != nil {
		t.Fatalf("Compose(alice, bob-x): %v", err)
	}
	b, err := Compose("alice-bob", "x")
	if err != nil {
		t.Fatalf("Compose(alice-bob, x): %v", err)
	}
	if a == b {
		t.Fatalf("distinct owner/hostname pairs collided: both produced %q", a)
	}
}

// TestComposeIsInjective asserts that no two distinct (username, hostname) pairs
// from a hyphen-rich grid share a composed name, and that the hostname is always
// recoverable — proving the join is the unambiguous boundary.
func TestComposeIsInjective(t *testing.T) {
	usernames := []string{"a", "a-b", "a-b-c", "alice", "alice-bob", "x-y", "a.b", "a_b"}
	hostnames := []string{"x", "b-x", "web", "web-1", "a-b-c", "y"}
	seen := make(map[string]string)
	for _, u := range usernames {
		for _, h := range hostnames {
			assertComposeInjective(t, seen, u, h)
		}
	}
}

// assertComposeInjective composes (u, h), fails if its name was already produced
// by a different pair, and confirms BareHostname recovers h from the name.
func assertComposeInjective(t *testing.T, seen map[string]string, u, h string) {
	t.Helper()
	name, err := Compose(u, h)
	if err != nil {
		t.Fatalf("Compose(%q, %q): %v", u, h, err)
	}
	key := u + "\x00" + h
	if prev, ok := seen[name]; ok && prev != key {
		t.Fatalf("collision on %q: (%q,%q) and %q", name, u, h, prev)
	}
	seen[name] = key
	if got := BareHostname(name, u); got != h {
		t.Fatalf("BareHostname(%q, %q) = %q, want %q", name, u, got, h)
	}
}

func TestBareHostname(t *testing.T) {
	tests := []struct {
		name   string
		vmName string
		owner  string
		want   string
	}{
		{"strips owner prefix", "alice.web", "alice", "web"},
		{"hyphenated owner and hostname", "alice-bob.web-1", "alice-bob", "web-1"},
		{"trimmed owner", "alice.web", "  alice  ", "web"},
		{"empty owner returns full name", "alice.web", "", "alice.web"},
		{"mismatched owner returns full name", "alice.web", "bob", "alice.web"},
		{"legacy hyphen name returns full name", "alice-web", "alice", "alice-web"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := BareHostname(tc.vmName, tc.owner); got != tc.want {
				t.Fatalf("BareHostname(%q, %q) = %q, want %q", tc.vmName, tc.owner, got, tc.want)
			}
		})
	}
}

func TestHasOwnerPrefix(t *testing.T) {
	tests := []struct {
		name     string
		vmName   string
		username string
		want     bool
	}{
		{"matching prefix", "alice.web", "alice", true},
		{"trimmed username", "alice.web", "  alice  ", true},
		{"different owner", "bob.web", "alice", false},
		{"prefix without separator is not a match", "aliceweb", "alice", false},
		{"empty username", "alice.web", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasOwnerPrefix(tc.vmName, tc.username); got != tc.want {
				t.Fatalf("HasOwnerPrefix(%q, %q) = %v, want %v", tc.vmName, tc.username, got, tc.want)
			}
		})
	}
}
