package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCovxLoadConfigFileOpenError(t *testing.T) {
	// A path whose parent is a regular file fails open with ENOTDIR, which is
	// not fs.ErrNotExist, so the error must surface (works as root and in CI).
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}

	if err := LoadConfigFile(filepath.Join(parent, "gateway.conf")); err == nil {
		t.Fatal("expected an open error when the config path traverses a file")
	}
}

func TestCovxLoadConfigFileSetenvError(t *testing.T) {
	// A key containing a NUL byte parses fine but is rejected by Setenv.
	path := filepath.Join(t.TempDir(), "bad-key.conf")
	if err := os.WriteFile(path, []byte("BAD\x00KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := LoadConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "set ") {
		t.Fatalf("expected a setenv error for an invalid key, got %v", err)
	}
}

func TestCovxEnsureSNIHashSecretReadError(t *testing.T) {
	// Point the data root at a regular file: reading <root>/sni_hash.secret
	// then fails with ENOTDIR, which is not IsNotExist.
	rootAsFile := filepath.Join(t.TempDir(), "data-root")
	if err := os.WriteFile(rootAsFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write data root file: %v", err)
	}

	t.Setenv(DATA_ROOT_DIR, rootAsFile)
	t.Setenv(SNI_HASH_SECRET, "")
	s := NewSettingType(false)

	err := EnsureSNIHashSecret(s)
	if err == nil || !strings.Contains(err.Error(), "read SNI hash secret") {
		t.Fatalf("expected a secret read error, got %v", err)
	}
}

func TestCovxEnsureSNIHashSecretMissingSetting(t *testing.T) {
	dataRoot := t.TempDir()
	s := &SettingsType{m: map[string]*Setting{
		DATA_ROOT_DIR: {Kind: KindString, S: dataRoot, Raw: dataRoot},
	}}

	err := EnsureSNIHashSecret(s)
	var notFound *SettingNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected SettingNotFoundError when SNI_HASH_SECRET is unregistered, got %v", err)
	}
	if notFound.ID != SNI_HASH_SECRET {
		t.Fatalf("expected the missing setting to be %s, got %s", SNI_HASH_SECRET, notFound.ID)
	}
}

func TestCovxLoadOrCreateSNIHashSecretMkdirError(t *testing.T) {
	// A dangling symlink as data root: the secret read reports IsNotExist, but
	// MkdirAll then fails because the name exists as a non-directory.
	base := t.TempDir()
	dataRoot := filepath.Join(base, "root-link")
	if err := os.Symlink(filepath.Join(base, "missing-target"), dataRoot); err != nil {
		t.Fatalf("symlink data root: %v", err)
	}

	_, err := loadOrCreateSNIHashSecret(dataRoot)
	if err == nil || !strings.Contains(err.Error(), "create data root") {
		t.Fatalf("expected a data root creation error, got %v", err)
	}
}

func TestCovxLoadOrCreateSNIHashSecretWriteError(t *testing.T) {
	// The secret file is a symlink dangling into a missing directory: reading
	// reports IsNotExist and MkdirAll succeeds, but creating the file fails.
	dataRoot := t.TempDir()
	link := filepath.Join(dataRoot, sniHashSecretFile)
	if err := os.Symlink(filepath.Join(dataRoot, "missing-dir", "secret"), link); err != nil {
		t.Fatalf("symlink secret file: %v", err)
	}

	_, err := loadOrCreateSNIHashSecret(dataRoot)
	if err == nil || !strings.Contains(err.Error(), "persist SNI hash secret") {
		t.Fatalf("expected a secret persist error, got %v", err)
	}
}

func TestCovxNewSettingTypePrintMasksSecrets(t *testing.T) {
	const secretValue = "covx-secret-value"
	t.Setenv(SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE, secretValue)

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	outCh := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		outCh <- string(data)
	}()

	s := NewSettingType(true)
	_ = w.Close()
	os.Stdout = oldStdout
	out := <-outCh

	if got := s.Get(SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE); got != secretValue {
		t.Fatalf("expected the real secret from Get, got %q", got)
	}
	if !strings.Contains(out, "***") {
		t.Fatal("expected the printed table to mask the secret with ***")
	}
	if strings.Contains(out, secretValue) {
		t.Fatal("expected the secret value not to appear in the printed table")
	}
}

func TestCovxOverwriteForTestStringMissingAndHappy(t *testing.T) {
	s := &SettingsType{m: map[string]*Setting{}}

	err := s.OverwriteForTestString("MISSING", "value")
	var notFound *SettingNotFoundError
	if !errors.As(err, &notFound) || notFound.ID != "MISSING" {
		t.Fatalf("expected SettingNotFoundError for a missing key, got %v", err)
	}

	s.SetString("PRESENT", "test", "before")
	if err := s.OverwriteForTestString("PRESENT", "after"); err != nil {
		t.Fatalf("overwrite string: %v", err)
	}
	if got := s.Get("PRESENT"); got != "after" {
		t.Fatalf("expected overwritten value %q, got %q", "after", got)
	}
}

func TestCovxKindToStringAllKinds(t *testing.T) {
	cases := map[Kind]string{
		KindString:   "string",
		KindInt:      "int",
		KindBool:     "bool",
		KindDuration: "duration",
		Kind(200):    "unknown",
	}
	for kind, want := range cases {
		if got := kindToString(kind); got != want {
			t.Fatalf("kindToString(%d) = %q, want %q", kind, got, want)
		}
	}
}
