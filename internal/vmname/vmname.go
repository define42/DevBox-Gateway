// Package vmname builds and validates the gateway's VDI (VM) names.
//
// Every VDI name is "<username><Separator><hostname>": the owning user's
// validated login name, the Separator byte, and the user-chosen hostname. This
// package is the single source of truth for that invariant, and Compose is the
// one place a VDI name is constructed, so the HTTP layer and the libvirt boot
// path cannot drift apart or bypass the rule.
//
// Separator is a byte the hostname half can never contain (ValidateHostname
// forbids it), so the final Separator in a VDI name is always the
// owner/hostname boundary. That makes Compose injective: two distinct
// (username, hostname) pairs can never map to the same VDI name. An earlier
// scheme joined the two halves with '-', which both halves allow, so
// Compose("alice", "bob-x") and Compose("alice-bob", "x") both produced
// "alice-bob-x" — letting one user squat on another user's VDI names, turning
// the "already exists" 409 into a cross-user existence oracle, and letting two
// users' concurrent creates collide on one libvirt domain. The unambiguous
// Separator closes all three.
package vmname

import (
	"fmt"
	"strings"
)

// Separator joins the owning username and the user-chosen hostname in a VDI
// name. It must be a byte ValidateHostname rejects (the hostname half is a DNS
// label, and '.' separates labels, so a single-label hostname never contains
// one) — that is what guarantees the boundary is unambiguous and Compose is
// injective. It need not be excluded from usernames: because the hostname can
// never contain it, the LAST Separator in a composed name is always the join,
// regardless of how many the username contributes.
const Separator = "."

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
// returns the trimmed value. The allowed set deliberately excludes Separator,
// which is what lets Compose treat the final Separator as the unambiguous
// owner/hostname boundary.
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
// the canonical "<username><Separator><hostname>" VDI name. It is the single
// point that builds a VDI name, so the naming invariant cannot be bypassed by
// any caller. Because both parts are validated non-empty, the result always
// starts with the "<username><Separator>" owner prefix that HasOwnerPrefix
// checks for. Because the hostname half can never contain Separator, distinct
// (username, hostname) pairs always yield distinct names — no user can compose
// a name that lands inside another user's namespace.
func Compose(username, hostname string) (string, error) {
	owner, err := ValidateUsername(username)
	if err != nil {
		return "", fmt.Errorf("invalid vm owner: %w", err)
	}
	host, err := ValidateHostname(hostname)
	if err != nil {
		return "", err
	}
	return owner + Separator + host, nil
}

// HasOwnerPrefix reports whether vmName begins with the "<username><Separator>"
// owner prefix that Compose guarantees for every VDI it builds. It is a
// display/heuristic check only and must never gate authorization: because a
// username may itself contain Separator, it yields a false positive when the
// queried username is a Separator-boundary prefix of the true owner (e.g.
// HasOwnerPrefix("alice.b.web", "alice") is true though the owner is "alice.b").
// Ownership is authorized from libvirt domain metadata (see virt.UserOwnsVM).
func HasOwnerPrefix(vmName, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	return strings.HasPrefix(vmName, username+Separator)
}

// BareHostname returns the hostname the owner typed at creation time, i.e.
// vmName with the leading "<owner><Separator>" removed. It returns vmName
// unchanged when that prefix is absent — an owner-less name, a name built under
// the older "-" scheme, or a mismatched owner — so callers always get a
// non-empty display value. Ownership itself is authorized from libvirt domain
// metadata, never from this string, so a mismatch here is only cosmetic.
func BareHostname(vmName, owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return vmName
	}
	if bare, ok := strings.CutPrefix(vmName, owner+Separator); ok && bare != "" {
		return bare
	}
	return vmName
}
