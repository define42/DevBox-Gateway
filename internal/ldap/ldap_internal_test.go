package ldap

import (
	"errors"
	"reflect"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"

	"github.com/go-ldap/ldap/v3"
)

func TestAuthenticateAccessRejectsEmptyPassword(t *testing.T) {
	// Point at a reserved, non-resolvable host so that if the empty-password
	// guard were ever removed the test fails fast on a dial error rather than
	// authenticating or hanging.
	t.Setenv(config.LDAP_URL, "ldaps://ldap.invalid:636")
	settings := config.NewSettingType(false)

	user, err := AuthenticateAccess("johndoe", "", settings)
	if user != nil {
		t.Fatalf("expected no user for empty password, got %#v", user)
	}
	if !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
}

func TestAuthenticateAccessRejectsEmptyIdentifier(t *testing.T) {
	// Point at a reserved, non-resolvable host to verify the identifier is
	// rejected before any LDAP connection is attempted.
	t.Setenv(config.LDAP_URL, "ldaps://ldap.invalid:636")
	t.Setenv(config.LDAP_USER_DOMAIN, "")
	settings := config.NewSettingType(false)

	user, err := AuthenticateAccess("", "nonempty-password", settings)
	if user != nil {
		t.Fatalf("expected no user for empty identifier, got %#v", user)
	}
	if !errors.Is(err, ErrEmptyIdentifier) {
		t.Fatalf("expected ErrEmptyIdentifier, got %v", err)
	}
}

func TestConfigured(t *testing.T) {
	t.Setenv(config.LDAP_URL, "ldaps://ldap:389")
	if !Configured(config.NewSettingType(false)) {
		t.Fatal("expected Configured=true when LDAP_URL is set")
	}

	t.Setenv(config.LDAP_URL, "   ")
	if Configured(config.NewSettingType(false)) {
		t.Fatal("expected Configured=false when LDAP_URL is blank")
	}
}

func TestLoginIdentifierAppendsDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice@example.test" {
		t.Fatalf("expected alice@example.test, got %q", got)
	}
}

func TestLoginIdentifierAppendsDomainWithAtPrefix(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "@example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice@example.test" {
		t.Fatalf("expected alice@example.test, got %q", got)
	}
}

func TestLoginIdentifierKeepsExistingDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice@other.test", settings); got != "alice@other.test" {
		t.Fatalf("expected unmodified address, got %q", got)
	}
}

func TestLoginIdentifierWithoutDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice" {
		t.Fatalf("expected unmodified username, got %q", got)
	}
}

func TestSearchFilterEscapesIdentifier(t *testing.T) {
	cases := []struct {
		name       string
		identifier string
		want       string
	}{
		{"plain", "alice@example.test", "(mail=alice@example.test)"},
		{"wildcard", "*", `(mail=\2a)`},
		{"filter injection", "*)(uid=*", `(mail=\2a\29\28uid=\2a)`},
		{"backslash", `a\b`, `(mail=a\5cb)`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := searchFilter("(mail=%s)", tc.identifier); got != tc.want {
				t.Fatalf("searchFilter(%q) = %q, want %q", tc.identifier, got, tc.want)
			}
		})
	}
}

func TestRequiredGroupsParsing(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"blank", "  ", nil},
		{"single name", "vdi-users", []string{"vdi-users"}},
		{"comma names", "vdi-users, admins", []string{"vdi-users", "admins"}},
		{"semicolon names", "vdi-users; admins;", []string{"vdi-users", "admins"}},
		{"single dn", "cn=vdi-users,ou=groups,dc=example,dc=com", []string{"cn=vdi-users,ou=groups,dc=example,dc=com"}},
		{"semicolon dns", "cn=a,dc=x; cn=b,dc=y", []string{"cn=a,dc=x", "cn=b,dc=y"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.LDAP_REQUIRED_GROUPS, tc.raw)
			settings := config.NewSettingType(false)

			got := requiredGroups(settings)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("requiredGroups(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestMemberOfAny(t *testing.T) {
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{
		Name:   "memberOf",
		Values: []string{"cn=VDI-Users,ou=groups,dc=example,dc=com", "ou=team10_r,ou=groups,dc=glauth,dc=com"},
	}}}

	cases := []struct {
		name   string
		groups []string
		want   bool
	}{
		{"full dn", []string{"cn=vdi-users,ou=groups,dc=example,dc=com"}, true},
		{"bare name case-insensitive", []string{"vdi-users"}, true},
		{"bare name ou-format", []string{"team10_r"}, true},
		{"one of several", []string{"nope", "team10_r"}, true},
		{"no match", []string{"other-group", "cn=other,dc=example,dc=com"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := memberOfAny(entry, tc.groups); got != tc.want {
				t.Fatalf("memberOfAny(entry, %#v) = %v, want %v", tc.groups, got, tc.want)
			}
		})
	}
}

func TestMemberOfAnyWithoutMemberOfAttribute(t *testing.T) {
	if memberOfAny(&ldap.Entry{}, []string{"vdi-users"}) {
		t.Fatal("expected entry without memberOf to match no groups")
	}
}
