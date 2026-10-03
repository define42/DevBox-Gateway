package ldap

import (
	"fmt"
	"strings"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/vmname"
	"github.com/go-ldap/ldap/v3"
)

// canonicalUsername derives the application identity solely from the directory
// entry. Preserve its spelling: folding caller input, or comparing every owner
// case-insensitively, could conflate distinct accounts in a case-sensitive
// directory. A multi-valued attribute is ambiguous even if one value happens to
// match the submitted login, because aliases must not create separate owners.
func canonicalUsername(entry *ldap.Entry, settings *config.Settings) (string, error) {
	attribute := settings.Get(config.LDAP_USERNAME_ATTRIBUTE)
	var values []string
	if entry != nil {
		for _, attr := range entry.Attributes {
			if strings.EqualFold(attr.Name, attribute) {
				values = append(values, attr.Values...)
			}
		}
	}
	if len(values) != 1 || values[0] == "" {
		return "", fmt.Errorf("ldap: canonical username attribute %s must contain exactly one non-empty value", attribute)
	}
	name := values[0]
	if name != strings.TrimSpace(name) {
		return "", fmt.Errorf("ldap: canonical username contains surrounding whitespace")
	}
	if local, domain, qualified := strings.Cut(name, "@"); qualified {
		configuredDomain := strings.TrimPrefix(strings.TrimSpace(settings.Get(config.LDAP_USER_DOMAIN)), "@")
		if domain == "" || !strings.EqualFold(domain, configuredDomain) {
			return "", fmt.Errorf("ldap: canonical username domain does not match %s", config.LDAP_USER_DOMAIN)
		}
		name = local
	}
	validated, err := vmname.ValidateUsername(name)
	if err != nil || validated != name || strings.ContainsRune(name, '@') {
		return "", fmt.Errorf("ldap: canonical username is invalid")
	}
	return validated, nil
}
