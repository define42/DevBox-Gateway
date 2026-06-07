// Package vmname builds and validates the gateway's VDI (VM) names.
//
// Every VDI name is "<username>-<hostname>": the owning user's validated login
// name, a hyphen, and the user-chosen hostname. This package is the single
// source of truth for that invariant, and Compose is the one place a VDI name
// is constructed, so the HTTP layer and the libvirt boot path cannot drift
// apart or bypass the rule.
package vmname

import (
	"fmt"
	"strings"
)

const (
	// MaxUsernameLength bounds the owning user's login name. The username
	// becomes a libvirt domain-name prefix, an on-disk volume/socket path
	// component, XML data in the domain definition, and a field in generated
	// .rdp files, so it must stay short and safe.
	MaxUsernameLength = 128

	// MaxHostnameLength bounds the user-chosen hostname, which is a single DNS
	// label (RFC 1035 limits a label to 63 octets).
	MaxHostnameLength = 63
)

// ValidateUsername normalizes and constrains the owning user's login name. It
// allows the identifier and email/UPN characters real directories use and
// rejects path separators, XML metacharacters, whitespace, and control
// characters. It returns the trimmed value so callers propagate the validated
// form everywhere.
func ValidateUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	if len(username) > MaxUsernameLength {
		return "", fmt.Errorf("username is too long")
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '+', r == '@':
		default:
			return "", fmt.Errorf("username contains unsupported characters")
		}
	}
	return username, nil
}

// ValidateHostname normalizes and constrains the user-chosen hostname: a
// non-empty lowercase DNS label of letters, digits, and interior hyphens. It
// returns the trimmed value.
func ValidateHostname(hostname string) (string, error) {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", fmt.Errorf("vm name is required")
	}
	if len(hostname) > MaxHostnameLength {
		return "", fmt.Errorf("vm name must be %d characters or fewer", MaxHostnameLength)
	}
	if strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return "", fmt.Errorf("vm name cannot start or end with a hyphen")
	}
	for _, r := range hostname {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return "", fmt.Errorf("vm name must use lowercase letters, numbers, or hyphens")
		}
	}
	return hostname, nil
}

// Compose validates the owning username and the user-chosen hostname and returns
// the canonical "<username>-<hostname>" VDI name. It is the single point that
// builds a VDI name, so the naming invariant cannot be bypassed by any caller.
// Because both parts are validated non-empty, the result always starts with the
// "<username>-" owner prefix that HasOwnerPrefix checks for.
func Compose(username, hostname string) (string, error) {
	owner, err := ValidateUsername(username)
	if err != nil {
		return "", fmt.Errorf("invalid vm owner: %w", err)
	}
	host, err := ValidateHostname(hostname)
	if err != nil {
		return "", err
	}
	return owner + "-" + host, nil
}

// HasOwnerPrefix reports whether vmName begins with the "<username>-" owner
// prefix that Compose guarantees for every VDI it builds.
func HasOwnerPrefix(vmName, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	return strings.HasPrefix(vmName, username+"-")
}
