// Package ldap authenticates users against the configured LDAP directory.
package ldap

import (
	"crypto/tls"
	"devboxgateway/internal/config"
	"devboxgateway/internal/types"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ErrEmptyPassword rejects a login with a zero-length password before any LDAP
// bind. Per RFC 4513 §5.1.2 a bind with a populated DN but an empty password is
// an "unauthenticated authentication" that many directories accept as an
// anonymous bind, which would let an empty password succeed against any
// account. The HTTP layer already rejects empty credentials, so this is the
// authoritative backstop guaranteeing the bypass cannot reappear via any caller.
var ErrEmptyPassword = errors.New("password must not be empty")

// Configured reports whether an LDAP directory is configured. When LDAP_URL is
// empty the gateway runs in local-users-only mode (see internal/localauth) and
// callers should skip LDAP entirely rather than attempt a dial.
func Configured(settings *config.SettingsType) bool {
	return strings.TrimSpace(settings.Get(config.LDAP_URL)) != ""
}

// AuthenticateAccess authenticates a user against LDAP and returns the gateway user model.
func AuthenticateAccess(username, password string, settings *config.SettingsType) (*types.User, error) {
	// Reject empty passwords before dialing or binding so an empty-password
	// anonymous bind can never authenticate a user. See ErrEmptyPassword.
	if password == "" {
		return nil, ErrEmptyPassword
	}

	conn, err := dialLDAP(settings)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	mail := loginIdentifier(username, settings)

	// Bind as the user using only the mail/UPN form.
	bindIDs := []string{mail}

	var bindErr error
	for _, id := range bindIDs {
		if id == "" {
			continue
		}
		if err := conn.Bind(id, password); err == nil {
			bindErr = nil
			break
		}
		bindErr = err
	}
	if bindErr != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", bindErr)
	}

	userFilter := settings.Get(config.LDAP_USER_FILTER)
	baseDN := settings.Get(config.LDAP_BASE_DN)

	filter := fmt.Sprintf(userFilter, mail)
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 0, false,
		filter,
		// memberOf is operational in some directories (e.g. OpenLDAP's memberof
		// overlay) and only returned when requested explicitly.
		[]string{"memberOf"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", mail)
	}

	if groups := requiredGroups(settings); len(groups) > 0 && !memberOfAny(sr.Entries[0], groups) {
		return nil, fmt.Errorf("user %s is not a member of any required group", mail)
	}

	return types.NewUser(username)
}

// requiredGroups parses LDAP_REQUIRED_GROUPS into a list of group DNs or bare
// group names. When only ';' delimiters appear (or none), entries are split on
// ';' so full DNs — which contain commas — survive intact; a list without any
// ';' is split on ',' too, which suits bare group names. An empty setting
// yields no groups, meaning everyone with a matching directory entry may log in.
func requiredGroups(settings *config.SettingsType) []string {
	raw := settings.Get(config.LDAP_REQUIRED_GROUPS)
	separator := ";"
	if !strings.Contains(raw, ";") && !strings.Contains(raw, "=") {
		separator = ","
	}
	fields := strings.Split(raw, separator)
	groups := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			groups = append(groups, field)
		}
	}
	return groups
}

// memberOfAny reports whether the entry's memberOf attribute contains at least
// one of the required groups. Each required group may be a full group DN or a
// bare group name, which is compared against the first RDN value of the
// memberOf DN (e.g. "vdi-users" matches "cn=vdi-users,ou=groups,dc=..."). All
// comparisons are case-insensitive per RFC 4517; nested group membership is
// not resolved.
func memberOfAny(entry *ldap.Entry, groups []string) bool {
	for _, member := range entry.GetAttributeValues("memberOf") {
		member = strings.TrimSpace(member)
		name := firstRDNValue(member)
		for _, group := range groups {
			if strings.EqualFold(member, group) || (name != "" && strings.EqualFold(name, group)) {
				return true
			}
		}
	}
	return false
}

// RequiredGroupNames returns human-readable names of the groups listed in
// LDAP_REQUIRED_GROUPS, for display on the login page: bare entries as-is, DN
// entries reduced to their first RDN value ("cn=vdi-users,ou=groups,dc=..." →
// "vdi-users"). Empty when LDAP is not configured or no groups are required.
func RequiredGroupNames(settings *config.SettingsType) []string {
	if !Configured(settings) {
		return nil
	}
	groups := requiredGroups(settings)
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		if name := firstRDNValue(group); name != "" {
			group = name
		}
		names = append(names, group)
	}
	return names
}

// firstRDNValue extracts the value of the leading RDN of a DN ("vdi-users"
// from "cn=vdi-users,ou=groups,dc=example,dc=com"), or "" if dn is not
// parseable as a DN.
func firstRDNValue(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return ""
	}
	return parsed.RDNs[0].Attributes[0].Value
}

func loginIdentifier(username string, settings *config.SettingsType) string {
	userMailDomain := settings.Get(config.LDAP_USER_DOMAIN)

	mail := username
	if !strings.Contains(username, "@") && userMailDomain != "" {
		domain := userMailDomain
		if !strings.HasPrefix(domain, "@") {
			domain = "@" + domain
		}
		mail = username + domain
	}

	return mail
}

func dialLDAP(settings *config.SettingsType) (*ldap.Conn, error) {
	// #nosec G402 -- skip TLS verification if configured
	ldapURL := settings.Get(config.LDAP_URL)
	insecureSkipVerify := settings.IsTrue(config.LDAP_SKIP_TLS_VERIFY)
	startTLS := settings.IsTrue(config.LDAP_STARTTLS)

	conn, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: insecureSkipVerify}))
	if err != nil {
		return nil, err
	}

	if startTLS && strings.HasPrefix(ldapURL, "ldap://") {
		// #nosec G402 -- skip TLS verification if configured
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: insecureSkipVerify}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	return conn, nil
}
