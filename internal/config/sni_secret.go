package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sniHashSecretFile is the persisted location (below the data root) of the
// auto-generated SNI routing secret, used when SNI_HASH_SECRET is not set.
const sniHashSecretFile = "sni_hash.secret"

// sniHashSecretBytes is the size of an auto-generated SNI routing secret.
const sniHashSecretBytes = 32

// EnsureSNIHashSecret resolves the SNI routing secret and stores it back into
// settings so later lookups are pure in-memory reads. Resolution order:
//  1. an explicit SNI_HASH_SECRET value (env/config) is used as-is;
//  2. otherwise a persisted secret under the data root is loaded;
//  3. otherwise a fresh random secret is generated and persisted.
//
// Persisting keeps the secret stable across restarts so previously issued
// .rdp files keep routing to the right VM.
func EnsureSNIHashSecret(settings *SettingsType) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}

	if explicit := strings.TrimSpace(settings.Get(SNI_HASH_SECRET)); explicit != "" {
		return nil
	}

	secret, err := loadOrCreateSNIHashSecret(DataRootDir(settings))
	if err != nil {
		return err
	}

	st, ok := settings.m[SNI_HASH_SECRET]
	if !ok {
		return &SettingNotFoundError{ID: SNI_HASH_SECRET}
	}
	st.S = secret
	st.Raw = secret
	return nil
}

func loadOrCreateSNIHashSecret(dataRoot string) (string, error) {
	path := filepath.Join(dataRoot, sniHashSecretFile)

	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- fixed filename below the operator-configured data root
		if secret := strings.TrimSpace(string(data)); secret != "" {
			return secret, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read SNI hash secret %s: %w", path, err)
	}

	buf := make([]byte, sniHashSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate SNI hash secret: %w", err)
	}
	secret := hex.EncodeToString(buf)

	// #nosec G301 -- the data root is traversed by libvirt/qemu (VM images and sockets live below it); the secret file itself is 0600.
	if err := os.MkdirAll(dataRoot, 0o755); err != nil {
		return "", fmt.Errorf("create data root %s: %w", dataRoot, err)
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("persist SNI hash secret %s: %w", path, err)
	}

	return secret, nil
}
