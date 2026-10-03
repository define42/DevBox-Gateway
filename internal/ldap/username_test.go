package ldap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	ber "github.com/go-asn1-ber/asn1-ber"
	ldapclient "github.com/go-ldap/ldap/v3"
)

func TestCanonicalUsername(t *testing.T) {
	tests := []struct {
		name      string
		attribute string
		values    map[string][]string
		want      string
	}{
		{name: "mail", values: map[string][]string{"mail": {"Alice@example.com"}}, want: "Alice"},
		{name: "case insensitive domain", values: map[string][]string{"mail": {"Alice@EXAMPLE.COM"}}, want: "Alice"},
		{name: "case insensitive attribute", values: map[string][]string{"MAIL": {"Alice@example.com"}}, want: "Alice"},
		{name: "upn", attribute: "userPrincipalName", values: map[string][]string{"userPrincipalName": {"Alice@example.com"}}, want: "Alice"},
		{name: "uid", attribute: "uid", values: map[string][]string{"uid": {"Alice"}}, want: "Alice"},
		{name: "account name", attribute: "sAMAccountName", values: map[string][]string{"sAMAccountName": {"Alice"}}, want: "Alice"},
		{name: "distinct case sensitive account", attribute: "uid", values: map[string][]string{"uid": {"alice"}}, want: "alice"},
		{name: "configured attribute only", attribute: "uid", values: map[string][]string{"uid": {"Alice"}, "mail": {"alias@example.com"}}, want: "Alice"},
		{name: "missing attribute", values: map[string][]string{"uid": {"Alice"}}},
		{name: "no values", values: map[string][]string{"mail": {}}},
		{name: "empty value", values: map[string][]string{"mail": {""}}},
		{name: "ambiguous aliases", values: map[string][]string{"mail": {"alice@example.com", "alias@example.com"}}},
		{name: "duplicate values", values: map[string][]string{"mail": {"alice@example.com", "alice@example.com"}}},
		{name: "duplicate attribute names", values: map[string][]string{"mail": {"alice@example.com"}, "MAIL": {"other@example.com"}}},
		{name: "foreign domain", values: map[string][]string{"mail": {"alice@other.example"}}},
		{name: "empty domain", values: map[string][]string{"mail": {"alice@"}}},
		{name: "empty local name", values: map[string][]string{"mail": {"@example.com"}}},
		{name: "multiple separators", values: map[string][]string{"mail": {"alice@other@example.com"}}},
		{name: "leading whitespace", values: map[string][]string{"mail": {" alice@example.com"}}},
		{name: "trailing whitespace", values: map[string][]string{"mail": {"alice@example.com "}}},
		{name: "path separator", values: map[string][]string{"mail": {"../alice@example.com"}}},
		{name: "control character", values: map[string][]string{"mail": {"alice\n@example.com"}}},
		{name: "too long", values: map[string][]string{"mail": {strings.Repeat("a", 129) + "@example.com"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := canonicalUsernameSettings(t, test.attribute)
			entry := ldapclient.NewEntry("uid=alice,dc=example,dc=com", test.values)
			got, err := canonicalUsername(entry, settings)
			if test.want == "" {
				if err == nil || got != "" {
					t.Fatalf("canonicalUsername() = %q, %v; want rejection", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("canonicalUsername() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestAuthenticateAccessCanonicalDirectoryIdentity(t *testing.T) {
	for _, spelling := range []string{"alice", "ALICE", "alias"} {
		t.Run(spelling, func(t *testing.T) {
			entry := ldapclient.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
				"mail": {"Alice@example.com"},
			})
			server := newDirectoryIdentityServer(t, "mail", []*ldapclient.Entry{entry})
			settings := ldapStallSettings(t, server, ldapStallPhase{scheme: "ldap"}, time.Second)
			user, err := AuthenticateAccess(t.Context(), spelling, "test-password", settings)
			if err != nil || user == nil || user.Name != "Alice" {
				t.Fatalf("AuthenticateAccess(%q) = %#v, %v; want directory identity Alice", spelling, user, err)
			}
			server.waitReady(t)
			server.waitClosed(t)
		})
	}
}

func TestAuthenticateAccessCanonicalAttributeSelection(t *testing.T) {
	entry := ldapclient.NewEntry("CN=Alice,DC=example,DC=com", map[string][]string{
		"userPrincipalName": {"Alice@example.com"},
		"mail":              {"a.smith@example.com", "alias@example.com"},
	})
	server := newDirectoryIdentityServer(t, "userPrincipalName", []*ldapclient.Entry{entry})
	settings := ldapStallSettings(t, server, ldapStallPhase{scheme: "ldap"}, time.Second)
	if err := settings.OverwriteForTestString(config.LDAP_USERNAME_ATTRIBUTE, "userPrincipalName"); err != nil {
		t.Fatal(err)
	}
	user, err := AuthenticateAccess(t.Context(), "ALICE", "test-password", settings)
	if err != nil || user == nil || user.Name != "Alice" {
		t.Fatalf("AuthenticateAccess() = %#v, %v; want directory UPN identity Alice", user, err)
	}
}

func TestAuthenticateAccessRejectsAmbiguousDirectoryIdentity(t *testing.T) {
	tests := []struct {
		name    string
		entries []*ldapclient.Entry
	}{
		{name: "missing attribute", entries: []*ldapclient.Entry{ldapclient.NewEntry("uid=alice,dc=example,dc=com", nil)}},
		{name: "multiple values", entries: []*ldapclient.Entry{ldapclient.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
			"mail": {"alice@example.com", "alias@example.com"},
		})}},
		{name: "multiple entries", entries: []*ldapclient.Entry{
			ldapclient.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{"mail": {"alice@example.com"}}),
			ldapclient.NewEntry("uid=other,dc=example,dc=com", map[string][]string{"mail": {"other@example.com"}}),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newDirectoryIdentityServer(t, "mail", test.entries)
			settings := ldapStallSettings(t, server, ldapStallPhase{scheme: "ldap"}, time.Second)
			user, err := AuthenticateAccess(t.Context(), "alice", "test-password", settings)
			if err == nil || user != nil {
				t.Fatalf("AuthenticateAccess() = %#v, %v; want rejection", user, err)
			}
		})
	}
}

func TestAuthenticateAccessRejectsInvalidUsernameAttributeBeforeDial(t *testing.T) {
	settings := canonicalUsernameSettings(t, "mail;binary")
	if err := settings.OverwriteForTestString(config.LDAP_URL, "ldaps://ldap.invalid:636"); err != nil {
		t.Fatal(err)
	}
	user, err := AuthenticateAccess(t.Context(), "alice", "test-password", settings)
	if user != nil || err == nil || !strings.Contains(err.Error(), config.LDAP_USERNAME_ATTRIBUTE) {
		t.Fatalf("AuthenticateAccess() = %#v, %v; want attribute validation before dialing", user, err)
	}
}

func canonicalUsernameSettings(t *testing.T, attribute string) *config.Settings {
	t.Helper()
	if attribute == "" {
		attribute = "mail"
	}
	settings := config.NewSettings(false)
	for key, value := range map[string]string{config.LDAP_USER_DOMAIN: "@example.com", config.LDAP_USERNAME_ATTRIBUTE: attribute} {
		if err := settings.OverwriteForTestString(key, value); err != nil {
			t.Fatal(err)
		}
	}
	return settings
}

func newDirectoryIdentityServer(t *testing.T, attribute string, entries []*ldapclient.Entry) *ldapStallServer {
	t.Helper()
	return newLDAPStallServer(t, func(_ context.Context, conn net.Conn) error {
		bind, err := readLDAPRequest(conn, ldapclient.ApplicationBindRequest)
		if err != nil {
			return err
		}
		if err := writeLDAPSuccess(conn, bind, ldapclient.ApplicationBindResponse); err != nil {
			return err
		}
		request, err := readLDAPRequest(conn, ldapclient.ApplicationSearchRequest)
		if err != nil {
			return err
		}
		requested := request.Children[1].Children[7].Children
		if len(requested) != 2 || requested[0].Value != "memberOf" || requested[1].Value != attribute {
			return fmt.Errorf("search did not request memberOf and canonical attribute %q", attribute)
		}
		for _, entry := range entries {
			if err := writeDirectoryIdentityEntry(conn, request, entry); err != nil {
				return err
			}
		}
		return writeLDAPSuccess(conn, request, ldapclient.ApplicationSearchResultDone)
	})
}

func writeDirectoryIdentityEntry(conn net.Conn, request *ber.Packet, entry *ldapclient.Entry) error {
	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "message")
	message.AppendChild(request.Children[0])
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapclient.ApplicationSearchResultEntry, nil, "entry")
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, entry.DN, "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, attr := range entry.Attributes {
		field := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		field.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr.Name, "name"))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		for _, value := range attr.Values {
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "value"))
		}
		field.AppendChild(values)
		attributes.AppendChild(field)
	}
	result.AppendChild(attributes)
	message.AppendChild(result)
	_, err := conn.Write(message.Bytes())
	return err
}
