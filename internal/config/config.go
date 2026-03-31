package config

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

type Kind uint8

const (
	KindString Kind = iota
	KindInt
	KindBool
	KindDuration
)

type Setting struct {
	Description string
	Kind        Kind

	Raw string // effective value as string (nice for printing)

	S string
	I int
	B bool
	D time.Duration
}

type SettingsType struct {
	m map[string]*Setting
}

const (
	DefaultVDIImageDir         = "/data/desktop/"
	DefaultVirtStoragePoolName = "desktop"
	DefaultVirtStoragePoolPath = DefaultVDIImageDir
)

func NewSettingType(print bool) *SettingsType {
	s := &SettingsType{m: make(map[string]*Setting)}

	s.SetString(ACME_DATA_DIR, "ACME data directory", "/data/acme/")

	s.SetString(VDI_IMAGE_DIR, "Directory for VDI images", DefaultVDIImageDir)
	s.SetString(VIRT_STORAGE_POOL_NAME, "Libvirt storage pool name for VM volumes", DefaultVirtStoragePoolName)
	s.SetString(VIRT_STORAGE_POOL_PATH, "Filesystem path for the libvirt storage pool", DefaultVirtStoragePoolPath)
	s.SetString(VIRT_SERIAL_SOCKET_DIR, "Filesystem path for VM serial UNIX sockets (defaults to <storage pool path>/serial when empty)", "")
	s.SetString(VIRT_VNC_SOCKET_DIR, "Filesystem path for VM VNC UNIX sockets (defaults to <storage pool path>/vnc when empty)", "")
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

	if print {
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

// ---- Setters ----

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

func (s *SettingsType) Has(id string) bool {
	_, ok := s.m[id]
	return ok
}

// String form (useful for printing/logging / backwards compat)
func (s *SettingsType) Get(id string) string { return s.GetString(id) }

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

func (s *SettingsType) IsTrue(id string) bool {
	return s.GetBool(id)
}

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

const (
	ACME_DATA_DIR          = "ACME_DATA_DIR"          //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	ACME_EMAIL             = "ACME_EMAIL"             //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	ACME_CA                = "ACME_CA"                //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	ACME_ENABLE            = "ACME_ENABLE"            //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	CERT_FILE              = "CERT_FILE"              //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	FRONT_DOMAIN           = "FRONT_DOMAIN"           //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	KEY_FILE               = "KEY_FILE"               //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	LDAP_URL               = "LDAP_URL"               //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	LDAP_BASE_DN           = "LDAP_BASE_DN"           //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	LDAP_USER_FILTER       = "LDAP_USER_FILTER"       //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	LDAP_USER_DOMAIN       = "LDAP_USER_DOMAIN"       //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	LDAP_STARTTLS          = "LDAP_STARTTLS"          //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	LDAP_SKIP_TLS_VERIFY   = "LDAP_SKIP_TLS_VERIFY"   //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	LISTEN_ADDR            = "LISTEN_ADDR"            //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	VDI_IMAGE_DIR          = "VDI_IMAGE_DIR"          //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	VIRT_STORAGE_POOL_NAME = "VIRT_STORAGE_POOL_NAME" //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	VIRT_STORAGE_POOL_PATH = "VIRT_STORAGE_POOL_PATH" //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	VIRT_SERIAL_SOCKET_DIR = "VIRT_SERIAL_SOCKET_DIR" //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	VIRT_VNC_SOCKET_DIR    = "VIRT_VNC_SOCKET_DIR"    //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	BASE_IMAGE_URL         = "BASE_IMAGE_URL"         //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
	TIMEOUT                = "TIMEOUT"                //nolint:stylecheck // configuration key identifiers intentionally match environment variable names
)

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

type SettingNotFoundError struct {
	ID string
}

func (e *SettingNotFoundError) Error() string {
	return "setting not found: " + e.ID
}

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

// ---- Global instance (for convenience, but consider using your own in libraries) ----

// NOTE: prints at init-time (like your original). Consider false in libraries.
//var Settings = NewSettingType(true)
