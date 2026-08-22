// Package hash provides password hashing helpers used by the gateway.
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

// routingLabelLen is the number of hex characters kept for an SNI routing
// label. 32 hex chars = 128 bits, which is ample collision resistance for the
// handful of VMs on a gateway while staying well under the 63-octet DNS label
// limit (a full SHA-256 hex string would be 64 chars and not fit a label).
const routingLabelLen = 32

// RoutingLabel derives the opaque DNS label used to route a VM over the
// cleartext TLS SNI without leaking its name. It is HMAC-SHA256(secret, vmName)
// truncated to a valid DNS label, so an on-path observer cannot recompute or
// confirm the label without the server-side secret.
func RoutingLabel(secret []byte, vmName string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(vmName))
	return hex.EncodeToString(mac.Sum(nil))[:routingLabelLen]
}

// CloudInitPassword generates a /etc/shadow compatible
// SHA-512 ($6$) password hash for cloud-init.
func CloudInitPassword(password string) (string, error) {
	saltGen := sha512_crypt.GetSalt()
	salt := saltGen.GenerateWRounds(16, 5000)
	c := sha512_crypt.New()
	hash, err := c.Generate([]byte(password), salt)
	if err != nil {
		return "", err
	}

	return hash, nil
}
