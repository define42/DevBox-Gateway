package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSNIHashSecretRespectsExplicitValue(t *testing.T) {
	t.Setenv(DATA_ROOT_DIR, t.TempDir())
	t.Setenv(SNI_HASH_SECRET, "explicit-secret")
	s := NewSettings(false)

	if err := EnsureSNIHashSecret(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := s.Get(SNI_HASH_SECRET); got != "explicit-secret" {
		t.Fatalf("expected explicit secret to be preserved, got %q", got)
	}
	if _, err := os.Stat(filepath.Join(DataRootDir(s), sniHashSecretFile)); !os.IsNotExist(err) {
		t.Fatal("expected no secret file to be persisted when value is explicit")
	}
}

func TestEnsureSNIHashSecretGeneratesAndPersists(t *testing.T) {
	dataRoot := t.TempDir()
	t.Setenv(DATA_ROOT_DIR, dataRoot)
	s := NewSettings(false)

	if err := EnsureSNIHashSecret(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	generated := s.Get(SNI_HASH_SECRET)
	if generated == "" {
		t.Fatal("expected a generated secret")
	}

	persisted, err := os.ReadFile(filepath.Join(dataRoot, sniHashSecretFile))
	if err != nil {
		t.Fatalf("expected secret to be persisted: %v", err)
	}
	if string(persisted) != generated+"\n" {
		t.Fatalf("persisted secret %q does not match in-memory secret %q", string(persisted), generated)
	}

	// A fresh settings instance over the same data root reuses the secret.
	s2 := NewSettings(false)
	if err := EnsureSNIHashSecret(s2); err != nil {
		t.Fatalf("unexpected error on reload: %v", err)
	}
	if got := s2.Get(SNI_HASH_SECRET); got != generated {
		t.Fatalf("expected reload to reuse persisted secret %q, got %q", generated, got)
	}
}

func TestEnsureSNIHashSecretNilSettings(t *testing.T) {
	if err := EnsureSNIHashSecret(nil); err == nil {
		t.Fatal("expected an error for nil settings")
	}
}
