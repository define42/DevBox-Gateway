// Package config defines the gateway's environment-backed runtime settings.
package config

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

// Kind identifies the underlying value type stored in a setting.
type Kind uint8

// Kind values supported by SettingsType.
const (
	// KindString stores plain string values.
	KindString Kind = iota
	// KindInt stores integer values.
	KindInt
	// KindBool stores boolean values.
	KindBool
	// KindDuration stores time.Duration values.
	KindDuration
)

// Setting stores a single configuration entry and its parsed value.
type Setting struct {
	Description string
	Kind        Kind

	Raw string // effective value as string (nice for printing)

	S string
	I int
	B bool
	D time.Duration
}

// SettingsType holds the process configuration keyed by environment-backed setting ID.
type SettingsType struct {
	m map[string]*Setting
}

const (
	// DefaultDataRootDir is the default root directory for gateway-managed data.
	DefaultDataRootDir = "/data"
	// DefaultVirtStoragePoolName is the default libvirt storage pool name.
	DefaultVirtStoragePoolName = "desktop"
)

const (
	acmeDataSubdir   = "acme"
	imageDataSubdir  = "image"
	serialDataSubdir = "serial"
	vncDataSubdir    = "vnc"
)

// NewSettingType builds the gateway settings from defaults and environment overrides.
func NewSettingType(printSettings bool) *SettingsType {
	s := &SettingsType{m: make(map[string]*Setting)}

	s.SetString(DATA_ROOT_DIR, "Root directory for gateway-managed data", DefaultDataRootDir)
	s.SetString(VIRT_STORAGE_POOL_NAME, "Libvirt storage pool name for VM volumes", DefaultVirtStoragePoolName)
	s.SetString(LDAP_URL, "LDAP server url", "ldaps://ldap:389")
	s.SetString(LDAP_BASE_DN, "LDAP base DN", "dc=glauth,dc=com")
	s.SetString(LDAP_USER_FILTER, "LDAP user filter", "(mail=%s)")
	s.SetString(LDAP_USER_DOMAIN, "LDAP user mail domain", "@example.com")
	s.SetBool(LDAP_STARTTLS, "Use StartTLS when connecting to LDAP", false)
	s.SetBool(LDAP_SKIP_TLS_VERIFY, "Skip TLS verification when connecting to LDAP", true)

	s.SetString(BASE_IMAGE_URL, "URL to download base VDI image if not found locally",
		"https://github.com/define42/ubuntu-resolute-desktop-cloud-image/releases/download/v0.0.1/resolute-desktop-cloudimg-amd64-v0.0.1.img")

	s.SetString(LISTEN_ADDR, "listen address", ":443")
	s.SetString(CERT_FILE, "TLS certificate PEM for clients (front side)", "")
	s.SetString(KEY_FILE, "TLS private key PEM for clients (front side, unencrypted)", "")

	// Duration-typed setting
	s.SetDuration(TIMEOUT, "handshake/dial/read timeout for setup", 10*time.Second)

	s.SetBool(ACME_ENABLE, "enable ACME certificate management with certmagic for front TLS", false)
	s.SetString(ACME_EMAIL, "ACME account email (recommended)", "")
	s.SetString(ACME_CA, "ACME CA directory URL or 'staging'", "")
	s.SetString(FRONT_DOMAIN, "Front domain to serve front page on HTTPS requests and also the prefix for vm names", "desktop.local.gd")

	if printSettings {
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("KEY", "Description", "Value")

		keys := make([]string, 0, len(s.m))
		for k := range s.m {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			st := s.m[key]
			_ = table.Append([]string{key, st.Description, st.Raw})
		}
		_ = table.Render()
	}

	return s
}

// DataRootDir resolves the root directory for gateway-managed data.
func DataRootDir(settings *SettingsType) string {
	rootDir := DefaultDataRootDir
	if settings != nil {
		if configuredRoot := strings.TrimSpace(settings.Get(DATA_ROOT_DIR)); configuredRoot != "" {
			rootDir = configuredRoot
		}
	}
	return filepath.Clean(rootDir)
}

// ACMEStorageDir resolves the ACME storage directory below the data root.
func ACMEStorageDir(settings *SettingsType) string {
	return filepath.Join(DataRootDir(settings), acmeDataSubdir)
}

// ImageDir resolves the VM image directory below the data root.
func ImageDir(settings *SettingsType) string {
	return filepath.Join(DataRootDir(settings), imageDataSubdir)
}

// SerialSocketDir resolves the VM serial socket directory below the data root.
func SerialSocketDir(settings *SettingsType) string {
	return filepath.Join(DataRootDir(settings), serialDataSubdir)
}

// VNCSocketDir resolves the VM VNC socket directory below the data root.
func VNCSocketDir(settings *SettingsType) string {
	return filepath.Join(DataRootDir(settings), vncDataSubdir)
}

// VirtStoragePoolPath resolves the libvirt storage pool path below the data root.
func VirtStoragePoolPath(settings *SettingsType) string {
	return ImageDir(settings)
}

// ---- Setters ----

// SetString registers a string setting and resolves its effective value.
func (s *SettingsType) SetString(id, description, defaultValue string) {
	raw := defaultValue
	if v, ok := os.LookupEnv(id); ok {
		raw = v
	}
	raw = strings.TrimSpace(raw)

	s.m[id] = &Setting{
		Description: description,
		Kind:        KindString,
		Raw:         raw,
		S:           raw,
	}
}

// SetInt registers an integer setting and resolves its effective value.
func (s *SettingsType) SetInt(id, description string, defaultValue int) {
	value := defaultValue
	rawUsed := strconv.Itoa(defaultValue)

	if v, ok := os.LookupEnv(id); ok {
		rawEnv := strings.TrimSpace(v)
		if parsed, err := strconv.Atoi(rawEnv); err == nil {
			value = parsed
			rawUsed = rawEnv
		}
	}

	s.m[id] = &Setting{
		Description: description,
		Kind:        KindInt,
		Raw:         rawUsed,
		I:           value,
	}
}

// SetBool registers a boolean setting and resolves its effective value.
func (s *SettingsType) SetBool(id, description string, defaultValue bool) {
	value := defaultValue
	rawUsed := strconv.FormatBool(defaultValue)

	if v, ok := os.LookupEnv(id); ok {
		rawEnv := strings.TrimSpace(v)
		if parsed, err := strconv.ParseBool(rawEnv); err == nil {
			value = parsed
			rawUsed = rawEnv
		}
	}

	s.m[id] = &Setting{
		Description: description,
		Kind:        KindBool,
		Raw:         rawUsed,
		B:           value,
	}
}

// SetDuration registers a duration setting and resolves its effective value.
func (s *SettingsType) SetDuration(id, description string, defaultValue time.Duration) {
	value := defaultValue
	rawUsed := defaultValue.String()

	if v, ok := os.LookupEnv(id); ok {
		rawEnv := strings.TrimSpace(v)
		if parsed, err := time.ParseDuration(rawEnv); err == nil {
			value = parsed
			rawUsed = rawEnv
		}
	}

	s.m[id] = &Setting{
		Description: description,
		Kind:        KindDuration,
		Raw:         rawUsed,
		D:           value,
	}
}

// ---- Getters (no fallbacks) ----

// Has reports whether the named setting exists.
func (s *SettingsType) Has(id string) bool {
	_, ok := s.m[id]
	return ok
}

// Get returns the setting value as a string.
func (s *SettingsType) Get(id string) string { return s.GetString(id) }

// GetString returns the setting value as a string.
func (s *SettingsType) GetString(id string) string {
	st, ok := s.m[id]
	if !ok {
		return ""
	}
	switch st.Kind {
	case KindString:
		return st.S
	case KindInt:
		return strconv.Itoa(st.I)
	case KindBool:
		return strconv.FormatBool(st.B)
	case KindDuration:
		return st.D.String()
	default:
		return st.Raw
	}
}

// GetInt returns the setting value as an int.
func (s *SettingsType) GetInt(id string) int {
	st, ok := s.m[id]
	if !ok {
		return 0
	}
	if st.Kind == KindInt {
		return st.I
	}

	v := strings.TrimSpace(st.Raw)
	if v == "" {
		return 0
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return parsed
}

// GetBool returns the setting value as a bool.
func (s *SettingsType) GetBool(id string) bool {
	st, ok := s.m[id]
	if !ok {
		return false
	}
	if st.Kind == KindBool {
		return st.B
	}

	v := strings.TrimSpace(st.Raw)
	if v == "" {
		return false
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return parsed
}

// IsTrue reports whether the named setting resolves to true.
func (s *SettingsType) IsTrue(id string) bool {
	return s.GetBool(id)
}

// GetDuration returns the setting value as a duration.
func (s *SettingsType) GetDuration(id string) time.Duration {
	st, ok := s.m[id]
	if !ok {
		return 0
	}
	if st.Kind == KindDuration {
		return st.D
	}

	v := strings.TrimSpace(st.Raw)
	if v == "" {
		return 0
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return parsed
}

// ---- Keys ----

// Environment-backed configuration keys.
const (
	ACME_EMAIL             = "ACME_EMAIL"
	ACME_CA                = "ACME_CA"
	ACME_ENABLE            = "ACME_ENABLE"
	CERT_FILE              = "CERT_FILE"
	DATA_ROOT_DIR          = "DATA_ROOT_DIR"
	FRONT_DOMAIN           = "FRONT_DOMAIN"
	KEY_FILE               = "KEY_FILE"
	LDAP_URL               = "LDAP_URL"
	LDAP_BASE_DN           = "LDAP_BASE_DN"
	LDAP_USER_FILTER       = "LDAP_USER_FILTER"
	LDAP_USER_DOMAIN       = "LDAP_USER_DOMAIN"
	LDAP_STARTTLS          = "LDAP_STARTTLS"
	LDAP_SKIP_TLS_VERIFY   = "LDAP_SKIP_TLS_VERIFY"
	LISTEN_ADDR            = "LISTEN_ADDR"
	VIRT_STORAGE_POOL_NAME = "VIRT_STORAGE_POOL_NAME"
	BASE_IMAGE_URL         = "BASE_IMAGE_URL"
	TIMEOUT                = "TIMEOUT"
)

// OverwriteForTestString replaces a string setting value for tests.
func (s *SettingsType) OverwriteForTestString(id, value string) error {
	if st, ok := s.m[id]; ok {
		if st.Kind != KindString {
			return &SettingTypeMismatchError{ID: id, Expected: KindString, Actual: st.Kind}
		}
		st.S = value
		st.Raw = value
		return nil
	}
	return &SettingNotFoundError{ID: id}
}

// OverwriteForTestInt replaces an int setting value for tests.
func (s *SettingsType) OverwriteForTestInt(id string, value int) error {
	if st, ok := s.m[id]; ok {
		if st.Kind != KindInt {
			return &SettingTypeMismatchError{ID: id, Expected: KindInt, Actual: st.Kind}
		}
		st.I = value
		st.Raw = strconv.Itoa(value)
		return nil
	}
	return &SettingNotFoundError{ID: id}
}

// OverwriteForTestBool replaces a bool setting value for tests.
func (s *SettingsType) OverwriteForTestBool(id string, value bool) error {
	if st, ok := s.m[id]; ok {
		if st.Kind != KindBool {
			return &SettingTypeMismatchError{ID: id, Expected: KindBool, Actual: st.Kind}
		}
		st.B = value
		st.Raw = strconv.FormatBool(value)
		return nil
	}
	return &SettingNotFoundError{ID: id}
}

// OverwriteForTestDuration replaces a duration setting value for tests.
func (s *SettingsType) OverwriteForTestDuration(id string, value time.Duration) error {
	if st, ok := s.m[id]; ok {
		if st.Kind != KindDuration {
			return &SettingTypeMismatchError{ID: id, Expected: KindDuration, Actual: st.Kind}
		}
		st.D = value
		st.Raw = value.String()
		return nil
	}
	return &SettingNotFoundError{ID: id}
}

// SettingNotFoundError reports an attempt to access a missing setting.
type SettingNotFoundError struct {
	ID string
}

func (e *SettingNotFoundError) Error() string {
	return "setting not found: " + e.ID
}

// SettingTypeMismatchError reports a test override using the wrong setting kind.
type SettingTypeMismatchError struct {
	ID       string
	Expected Kind
	Actual   Kind
}

func (e *SettingTypeMismatchError) Error() string {
	return "setting type mismatch for " + e.ID + ": expected " + kindToString(e.Expected) + ", got " + kindToString(e.Actual)
}

func kindToString(k Kind) string {
	switch k {
	case KindString:
		return "string"
	case KindInt:
		return "int"
	case KindBool:
		return "bool"
	case KindDuration:
		return "duration"
	default:
		return "unknown"
	}
}
