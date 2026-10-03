// Package hash provides password hashing for cloud-init.
package hash

import "github.com/tredoe/osutil/user/crypt/sha512_crypt"

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
