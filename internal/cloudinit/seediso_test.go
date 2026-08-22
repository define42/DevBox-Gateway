package cloudinit

import (
	"path/filepath"
	"strings"
	"testing"
)

func testUserData() *UserData {
	return &UserData{Users: []User{{Name: "cvbtguest", Shell: "/bin/bash"}}}
}

func testMetaData() *MetaData {
	return &MetaData{InstanceID: "cvbt-instance", LocalHostname: "cvbt-host"}
}

// breakTempDir points TMPDIR at a missing directory so iso9660.NewWriter,
// which stages into os.TempDir, fails deterministically for this test.
func breakTempDir(t *testing.T) {
	t.Helper()

	missing := filepath.Join(t.TempDir(), "missing-tmp")
	t.Setenv("TMPDIR", missing)
}

func requireErrContains(t *testing.T, err error, substring, operation string) {
	t.Helper()

	if err == nil || !strings.Contains(err.Error(), substring) {
		t.Fatalf("%s: got error %v, want one containing %q", operation, err, substring)
	}
}

func TestCreateSeedISOWriterFailure(t *testing.T) {
	breakTempDir(t)

	_, err := CreateSeedISO(testUserData(), testMetaData(), nil)
	requireErrContains(t, err, "create iso writer", "CreateSeedISO with broken TMPDIR")
}

func TestCreateSeedISOWithoutNetworkConfig(t *testing.T) {
	t.Run("nil network config", func(t *testing.T) {
		data, err := CreateSeedISO(testUserData(), testMetaData(), nil)
		if err != nil {
			t.Fatalf("CreateSeedISO without network config: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("expected non-empty iso without network config")
		}
	})

	t.Run("zero network config", func(t *testing.T) {
		data, err := CreateSeedISO(testUserData(), testMetaData(), &NetworkConfig{})
		if err != nil {
			t.Fatalf("CreateSeedISO with zero network config: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("expected non-empty iso with zero network config")
		}
	})
}

func TestSeedISOYAMLBytes(t *testing.T) {
	t.Run("nil optional doc yields nothing", func(t *testing.T) {
		data, err := seedISOYAMLBytes("network-config", (*NetworkConfig)(nil), false, "#cloud-config\n")
		if err != nil || data != nil {
			t.Fatalf("seedISOYAMLBytes(nil, optional) = %q, %v; want nil, nil", data, err)
		}
	})

	t.Run("nil required doc fails", func(t *testing.T) {
		_, err := seedISOYAMLBytes("user-data", (*UserData)(nil), true, "#cloud-config\n")
		requireErrContains(t, err, "user-data is required", "seedISOYAMLBytes with nil required doc")
	})

	t.Run("zero required doc fails", func(t *testing.T) {
		_, err := seedISOYAMLBytes("user-data", &UserData{}, true, "#cloud-config\n")
		requireErrContains(t, err, "user-data is required", "seedISOYAMLBytes with zero required doc")
	})

	t.Run("zero optional doc yields nothing", func(t *testing.T) {
		data, err := seedISOYAMLBytes("network-config", &NetworkConfig{}, false, "#cloud-config\n")
		if err != nil || data != nil {
			t.Fatalf("seedISOYAMLBytes(zero, optional) = %q, %v; want nil, nil", data, err)
		}
	})

	t.Run("unmarshalable doc fails", func(t *testing.T) {
		fn := func() {}
		_, err := seedISOYAMLBytes("cvbt-doc", &fn, true, "")
		requireErrContains(t, err, "marshal cvbt-doc", "seedISOYAMLBytes with func value")
	})

	t.Run("prefix is prepended", func(t *testing.T) {
		data, err := seedISOYAMLBytes("meta-data", testMetaData(), true, "#prefix\n")
		if err != nil {
			t.Fatalf("seedISOYAMLBytes with prefix: %v", err)
		}
		if !strings.HasPrefix(string(data), "#prefix\n") {
			t.Fatalf("expected data to start with prefix, got %q", data)
		}
	})
}
