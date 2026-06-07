// Package ldap authenticates users against the configured LDAP directory.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Configured reports whether an LDAP directory is configured. When LDAP_URL is
// empty the gateway runs in local-users-only mode (see internal/localauth) and
// callers should skip LDAP entirely rather than attempt a dial.
func Configured(settings *config.SettingsType) bool {
	return strings.TrimSpace(settings.Get(config.LDAP_URL)) != ""
}

// AuthenticateAccess authenticates a user against LDAP and returns the gateway user model.
func AuthenticateAccess(username, password string, settings *config.SettingsType) (*types.User, error) {
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
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", mail)
	}

	return types.NewUser(username, password)
}

// ValidateSessionAccess revalidates a stored session against LDAP without rebuilding
// the user model. A false,nil result means the user is no longer authorized.
func ValidateSessionAccess(username, password string, settings *config.SettingsType) (bool, error) {
	conn, err := dialLDAP(settings)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	mail := loginIdentifier(username, settings)
	if err := conn.Bind(mail, password); err != nil {
		if isLDAPCredentialError(err) {
			return false, nil
		}
		return false, fmt.Errorf("ldap bind failed: %w", err)
	}

	userFilter := settings.Get(config.LDAP_USER_FILTER)
	baseDN := settings.Get(config.LDAP_BASE_DN)

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf(userFilter, mail),
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return false, fmt.Errorf("ldap search: %w", err)
	}
	return len(sr.Entries) > 0, nil
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

func isLDAPCredentialError(err error) bool {
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		return false
	}

	switch ldapErr.ResultCode {
	case ldap.LDAPResultInvalidCredentials,
		ldap.LDAPResultInappropriateAuthentication,
		ldap.LDAPResultInsufficientAccessRights,
		ldap.LDAPResultAuthorizationDenied,
		ldap.ErrorEmptyPassword:
		return true
	default:
		return false
	}
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
