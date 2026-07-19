package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNewSettingTypeDefaults(t *testing.T) {
	s := NewSettingType(false)

	if got := s.GetString(DATA_ROOT_DIR); got != DefaultDataRootDir {
		t.Fatalf("expected default DATA_ROOT_DIR %q, got %q", DefaultDataRootDir, got)
	}
	if got := s.GetString(LDAP_URL); got != "ldaps://ldap:389" {
		t.Fatalf("expected default LDAP_URL, got %q", got)
	}
	if got := s.GetString(LDAP_BASE_DN); got != "dc=glauth,dc=com" {
		t.Fatalf("expected default LDAP_BASE_DN, got %q", got)
	}
	if got := s.GetBool(ACME_ENABLE); got != false {
		t.Fatalf("expected default ACME_ENABLE=false, got %v", got)
	}
	if got := s.GetDuration(TIMEOUT); got != 10*time.Second {
		t.Fatalf("expected default TIMEOUT=10s, got %v", got)
	}
	if got := s.GetInt(LOGIN_RATE_LIMIT_MAX_ATTEMPTS); got != 5 {
		t.Fatalf("expected default LOGIN_RATE_LIMIT_MAX_ATTEMPTS=5, got %d", got)
	}
	if got := s.GetDuration(LOGIN_RATE_LIMIT_WINDOW); got != 5*time.Minute {
		t.Fatalf("expected default LOGIN_RATE_LIMIT_WINDOW=5m, got %v", got)
	}
	if got := s.GetDuration(LOGIN_RATE_LIMIT_LOCKOUT); got != 15*time.Minute {
		t.Fatalf("expected default LOGIN_RATE_LIMIT_LOCKOUT=15m, got %v", got)
	}
	if got := s.GetInt(MAX_VDI_PER_USER); got != DefaultMaxVDIPerUser {
		t.Fatalf("expected default MAX_VDI_PER_USER=%d, got %d", DefaultMaxVDIPerUser, got)
	}
}

func TestMaxVDIPerUserDefault(t *testing.T) {
	s := NewSettingType(false)

	if got := MaxVDIPerUser(s); got != DefaultMaxVDIPerUser {
		t.Fatalf("expected default limit %d, got %d", DefaultMaxVDIPerUser, got)
	}
}

func TestMaxVDIPerUserConfigured(t *testing.T) {
	t.Setenv(MAX_VDI_PER_USER, "3")
	s := NewSettingType(false)

	if got := MaxVDIPerUser(s); got != 3 {
		t.Fatalf("expected configured limit 3, got %d", got)
	}
}

func TestMaxVDIPerUserDisabled(t *testing.T) {
	t.Setenv(MAX_VDI_PER_USER, "0")
	s := NewSettingType(false)

	if got := MaxVDIPerUser(s); got != 0 {
		t.Fatalf("expected disabled limit (0) for 0, got %d", got)
	}

	if err := s.OverwriteForTestInt(MAX_VDI_PER_USER, -5); err != nil {
		t.Fatalf("overwrite MAX_VDI_PER_USER: %v", err)
	}
	if got := MaxVDIPerUser(s); got != 0 {
		t.Fatalf("expected disabled limit (0) for negative value, got %d", got)
	}
}

func TestMaxVDIPerUserNilSettings(t *testing.T) {
	if got := MaxVDIPerUser(nil); got != DefaultMaxVDIPerUser {
		t.Fatalf("expected default limit %d for nil settings, got %d", DefaultMaxVDIPerUser, got)
	}
}

func TestDerivedDataPathsDefault(t *testing.T) {
	s := NewSettingType(false)

	if got := DataRootDir(s); got != filepath.Clean(DefaultDataRootDir) {
		t.Fatalf("expected data root %q, got %q", filepath.Clean(DefaultDataRootDir), got)
	}
	if got := ACMEStorageDir(s); got != filepath.Join(filepath.Clean(DefaultDataRootDir), "acme") {
		t.Fatalf("expected ACME storage dir under default root, got %q", got)
	}
	if got := ImageDir(s); got != filepath.Join(filepath.Clean(DefaultDataRootDir), "image") {
		t.Fatalf("expected image dir under default root, got %q", got)
	}
	if got := BaseImageDir(s); got != filepath.Join(filepath.Clean(DefaultDataRootDir), "baseimages") {
		t.Fatalf("expected base image dir under default root, got %q", got)
	}
	if got := SerialSocketDir(s); got != filepath.Join(filepath.Clean(DefaultDataRootDir), "serial") {
		t.Fatalf("expected serial dir under default root, got %q", got)
	}
	if got := VNCSocketDir(s); got != filepath.Join(filepath.Clean(DefaultDataRootDir), "vnc") {
		t.Fatalf("expected VNC dir under default root, got %q", got)
	}
	if got := VirtStoragePoolPath(s); got != filepath.Join(filepath.Clean(DefaultDataRootDir), "image") {
		t.Fatalf("expected storage pool path under default root, got %q", got)
	}
}

func TestDerivedDataPathsCustomRoot(t *testing.T) {
	t.Setenv(DATA_ROOT_DIR, " /srv/gateway/../gateway-data/ ")

	s := NewSettingType(false)
	root := filepath.Clean("/srv/gateway-data")

	if got := DataRootDir(s); got != root {
		t.Fatalf("expected cleaned data root %q, got %q", root, got)
	}
	if got := ACMEStorageDir(s); got != filepath.Join(root, "acme") {
		t.Fatalf("expected ACME storage dir %q, got %q", filepath.Join(root, "acme"), got)
	}
	if got := ImageDir(s); got != filepath.Join(root, "image") {
		t.Fatalf("expected image dir %q, got %q", filepath.Join(root, "image"), got)
	}
	if got := BaseImageDir(s); got != filepath.Join(root, "baseimages") {
		t.Fatalf("expected base image dir %q, got %q", filepath.Join(root, "baseimages"), got)
	}
	if got := SerialSocketDir(s); got != filepath.Join(root, "serial") {
		t.Fatalf("expected serial dir %q, got %q", filepath.Join(root, "serial"), got)
	}
	if got := VNCSocketDir(s); got != filepath.Join(root, "vnc") {
		t.Fatalf("expected VNC dir %q, got %q", filepath.Join(root, "vnc"), got)
	}
	if got := VirtStoragePoolPath(s); got != filepath.Join(root, "image") {
		t.Fatalf("expected storage pool path %q, got %q", filepath.Join(root, "image"), got)
	}
}

func TestDerivedDataPathsNilSettings(t *testing.T) {
	root := filepath.Clean(DefaultDataRootDir)

	if got := DataRootDir(nil); got != root {
		t.Fatalf("expected nil-settings root %q, got %q", root, got)
	}
	if got := ACMEStorageDir(nil); got != filepath.Join(root, "acme") {
		t.Fatalf("expected nil-settings ACME dir %q, got %q", filepath.Join(root, "acme"), got)
	}
	if got := ImageDir(nil); got != filepath.Join(root, "image") {
		t.Fatalf("expected nil-settings image dir %q, got %q", filepath.Join(root, "image"), got)
	}
	if got := BaseImageDir(nil); got != filepath.Join(root, "baseimages") {
		t.Fatalf("expected nil-settings base image dir %q, got %q", filepath.Join(root, "baseimages"), got)
	}
	if got := SerialSocketDir(nil); got != filepath.Join(root, "serial") {
		t.Fatalf("expected nil-settings serial dir %q, got %q", filepath.Join(root, "serial"), got)
	}
	if got := VNCSocketDir(nil); got != filepath.Join(root, "vnc") {
		t.Fatalf("expected nil-settings VNC dir %q, got %q", filepath.Join(root, "vnc"), got)
	}
	if got := VirtStoragePoolPath(nil); got != filepath.Join(root, "image") {
		t.Fatalf("expected nil-settings storage pool path %q, got %q", filepath.Join(root, "image"), got)
	}
}

func TestBaseImageDirExplicitOverride(t *testing.T) {
	t.Setenv(DATA_ROOT_DIR, "/srv/gateway-data")
	t.Setenv(BASE_IMAGE_DIR, " /mnt/images/ ")

	s := NewSettingType(false)

	// An explicit BASE_IMAGE_DIR wins over the data-root default and is cleaned.
	if got := BaseImageDir(s); got != filepath.Clean("/mnt/images") {
		t.Fatalf("expected explicit base image dir %q, got %q", filepath.Clean("/mnt/images"), got)
	}
	// The storage pool path is unaffected by BASE_IMAGE_DIR.
	if got := VirtStoragePoolPath(s); got != filepath.Join(filepath.Clean("/srv/gateway-data"), "image") {
		t.Fatalf("expected storage pool path under data root, got %q", got)
	}
}

func TestNewSettingTypePrint(t *testing.T) {
	// Exercise the print=true path; just ensure it doesn't panic.
	s := NewSettingType(true)
	if s == nil {
		t.Fatal("expected non-nil SettingsType")
	}
}

func TestSetStringDefault(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("TEST_KEY", "test description", "default_value")

	if got := s.GetString("TEST_KEY"); got != "default_value" {
		t.Fatalf("expected %q, got %q", "default_value", got)
	}
}

func TestSetStringFromEnv(t *testing.T) {
	t.Setenv("TEST_KEY_ENV", "  from_env  ")
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("TEST_KEY_ENV", "test", "fallback")

	if got := s.GetString("TEST_KEY_ENV"); got != "from_env" {
		t.Fatalf("expected trimmed env value %q, got %q", "from_env", got)
	}
}

func TestSetIntDefault(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetInt("MY_INT", "an integer", 42)

	if got := s.GetInt("MY_INT"); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
}

func TestSetIntFromEnv(t *testing.T) {
	t.Setenv("MY_INT_ENV", " 99 ")
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetInt("MY_INT_ENV", "integer from env", 0)

	if got := s.GetInt("MY_INT_ENV"); got != 99 {
		t.Fatalf("expected 99, got %d", got)
	}
}

func TestSetIntInvalidEnv(t *testing.T) {
	t.Setenv("MY_INT_BAD", "not_a_number")
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetInt("MY_INT_BAD", "bad integer", 7)

	if got := s.GetInt("MY_INT_BAD"); got != 7 {
		t.Fatalf("expected default 7 for invalid env, got %d", got)
	}
}

func TestSetBoolDefault(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetBool("MY_BOOL", "a boolean", true)

	if got := s.GetBool("MY_BOOL"); got != true {
		t.Fatalf("expected true, got %v", got)
	}
}

func TestSetBoolFromEnv(t *testing.T) {
	t.Setenv("MY_BOOL_ENV", " true ")
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetBool("MY_BOOL_ENV", "bool from env", false)

	if got := s.GetBool("MY_BOOL_ENV"); got != true {
		t.Fatalf("expected true, got %v", got)
	}
}

func TestSetBoolInvalidEnv(t *testing.T) {
	t.Setenv("MY_BOOL_BAD", "nope")
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetBool("MY_BOOL_BAD", "bad bool", true)

	if got := s.GetBool("MY_BOOL_BAD"); got != true {
		t.Fatalf("expected default true for invalid env, got %v", got)
	}
}

func TestSetDurationDefault(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetDuration("MY_DUR", "a duration", 5*time.Minute)

	if got := s.GetDuration("MY_DUR"); got != 5*time.Minute {
		t.Fatalf("expected 5m, got %v", got)
	}
}

func TestSetDurationFromEnv(t *testing.T) {
	t.Setenv("MY_DUR_ENV", " 30s ")
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetDuration("MY_DUR_ENV", "dur from env", time.Second)

	if got := s.GetDuration("MY_DUR_ENV"); got != 30*time.Second {
		t.Fatalf("expected 30s, got %v", got)
	}
}

func TestSetDurationInvalidEnv(t *testing.T) {
	t.Setenv("MY_DUR_BAD", "nope")
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetDuration("MY_DUR_BAD", "bad dur", 2*time.Hour)

	if got := s.GetDuration("MY_DUR_BAD"); got != 2*time.Hour {
		t.Fatalf("expected default 2h for invalid env, got %v", got)
	}
}

func TestHas(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("EXISTS", "exists", "v")

	if !s.Has("EXISTS") {
		t.Fatal("expected Has to return true for existing key")
	}
	if s.Has("NOT_EXISTS") {
		t.Fatal("expected Has to return false for missing key")
	}
}

func TestGetMissing(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}

	if got := s.GetString("MISSING"); got != "" {
		t.Fatalf("expected empty string for missing key, got %q", got)
	}
	if got := s.GetInt("MISSING"); got != 0 {
		t.Fatalf("expected 0 for missing key, got %d", got)
	}
	if got := s.GetBool("MISSING"); got != false {
		t.Fatalf("expected false for missing key, got %v", got)
	}
	if got := s.GetDuration("MISSING"); got != 0 {
		t.Fatalf("expected 0 for missing key, got %v", got)
	}
}

func TestGetStringReturnsFormattedValues(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetInt("INT_KEY", "int", 42)
	s.SetBool("BOOL_KEY", "bool", true)
	s.SetDuration("DUR_KEY", "dur", 5*time.Second)

	if got := s.GetString("INT_KEY"); got != "42" {
		t.Fatalf("expected %q, got %q", "42", got)
	}
	if got := s.GetString("BOOL_KEY"); got != "true" {
		t.Fatalf("expected %q, got %q", "true", got)
	}
	if got := s.GetString("DUR_KEY"); got != "5s" {
		t.Fatalf("expected %q, got %q", "5s", got)
	}
}

func TestGetIntFromStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_INT", "string that is int", "123")

	if got := s.GetInt("STR_INT"); got != 123 {
		t.Fatalf("expected 123, got %d", got)
	}
}

func TestGetIntFromStringKindInvalid(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_BAD", "not an int string", "abc")

	if got := s.GetInt("STR_BAD"); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestGetIntFromEmptyStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_EMPTY", "empty string", "")

	if got := s.GetInt("STR_EMPTY"); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestGetBoolFromStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_BOOL", "string that is bool", "true")

	if got := s.GetBool("STR_BOOL"); got != true {
		t.Fatalf("expected true, got %v", got)
	}
}

func TestGetBoolFromEmptyStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_EMPTY", "empty string", "")

	if got := s.GetBool("STR_EMPTY"); got != false {
		t.Fatalf("expected false, got %v", got)
	}
}

func TestGetBoolFromInvalidStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_BAD", "not a bool string", "maybe")

	if got := s.GetBool("STR_BAD"); got != false {
		t.Fatalf("expected false, got %v", got)
	}
}

func TestGetDurationFromStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_DUR", "string that is dur", "15s")

	if got := s.GetDuration("STR_DUR"); got != 15*time.Second {
		t.Fatalf("expected 15s, got %v", got)
	}
}

func TestGetDurationFromEmptyStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_EMPTY", "empty string", "")

	if got := s.GetDuration("STR_EMPTY"); got != 0 {
		t.Fatalf("expected 0, got %v", got)
	}
}

func TestGetDurationFromInvalidStringKind(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("STR_BAD", "bad dur string", "nope")

	if got := s.GetDuration("STR_BAD"); got != 0 {
		t.Fatalf("expected 0, got %v", got)
	}
}

func TestGetAlias(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetString("ALIAS", "alias test", "hello")

	if got := s.Get("ALIAS"); got != "hello" {
		t.Fatalf("expected %q, got %q", "hello", got)
	}
}

func TestIsTrue(t *testing.T) {
	s := &SettingsType{m: make(map[string]*Setting)}
	s.SetBool("TRUE_KEY", "true bool", true)
	s.SetBool("FALSE_KEY", "false bool", false)

	if !s.IsTrue("TRUE_KEY") {
		t.Fatal("expected IsTrue to return true")
	}
	if s.IsTrue("FALSE_KEY") {
		t.Fatal("expected IsTrue to return false")
	}
}

func TestOverwriteForTestHelpers(t *testing.T) {
	s := NewSettingType(false)

	if err := s.OverwriteForTestInt(TIMEOUT, 1); err == nil {
		t.Fatal("expected type mismatch when overwriting duration with int")
	}
	if err := s.OverwriteForTestBool(LDAP_URL, true); err == nil {
		t.Fatal("expected type mismatch when overwriting string with bool")
	}
	if err := s.OverwriteForTestDuration(LDAP_URL, time.Second); err == nil {
		t.Fatal("expected type mismatch when overwriting string with duration")
	}

	if err := s.OverwriteForTestInt("MISSING", 1); err == nil {
		t.Fatal("expected missing setting error for int overwrite")
	}
	if err := s.OverwriteForTestBool("MISSING", true); err == nil {
		t.Fatal("expected missing setting error for bool overwrite")
	}
	if err := s.OverwriteForTestDuration("MISSING", time.Second); err == nil {
		t.Fatal("expected missing setting error for duration overwrite")
	}

	if err := s.OverwriteForTestInt(VIRT_STORAGE_POOL_NAME, 1); err == nil {
		t.Fatal("expected type mismatch when overwriting string with int")
	}

	if err := s.OverwriteForTestInt(TIMEOUT, 1); err == nil {
		t.Fatal("expected type mismatch when overwriting duration with int")
	}
}

func TestOverwriteForTestSettersAndErrors(t *testing.T) {
	s := NewSettingType(false)
	s.SetInt("TEST_INT", "int", 1)
	s.SetBool("TEST_BOOL", "bool", false)
	s.SetDuration("TEST_DURATION", "duration", time.Second)

	if err := s.OverwriteForTestInt("TEST_INT", 42); err != nil {
		t.Fatalf("overwrite int: %v", err)
	}
	if got := s.GetInt("TEST_INT"); got != 42 {
		t.Fatalf("expected overwritten int 42, got %d", got)
	}

	if err := s.OverwriteForTestBool("TEST_BOOL", true); err != nil {
		t.Fatalf("overwrite bool: %v", err)
	}
	if got := s.GetBool("TEST_BOOL"); !got {
		t.Fatal("expected overwritten bool true")
	}

	if err := s.OverwriteForTestDuration("TEST_DURATION", 45*time.Second); err != nil {
		t.Fatalf("overwrite duration: %v", err)
	}
	if got := s.GetDuration("TEST_DURATION"); got != 45*time.Second {
		t.Fatalf("expected overwritten duration 45s, got %v", got)
	}

	if got := (&SettingTypeMismatchError{ID: "X", Expected: KindString, Actual: KindInt}).Error(); got == "" {
		t.Fatal("expected non-empty mismatch error message")
	}
	if got := (&SettingNotFoundError{ID: "Y"}).Error(); got == "" {
		t.Fatal("expected non-empty not found error message")
	}
	if got := kindToString(KindDuration); got != "duration" {
		t.Fatalf("expected duration kind string, got %q", got)
	}
}
