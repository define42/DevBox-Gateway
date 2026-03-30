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
	ACME_DATA_DIR          = "ACME_DATA_DIR"
	ACME_EMAIL             = "ACME_EMAIL"
	ACME_CA                = "ACME_CA"
	ACME_ENABLE            = "ACME_ENABLE"
	CERT_FILE              = "CERT_FILE"
	FRONT_DOMAIN           = "FRONT_DOMAIN"
	KEY_FILE               = "KEY_FILE"
	LDAP_URL               = "LDAP_URL"
	LDAP_BASE_DN           = "LDAP_BASE_DN"
	LDAP_USER_FILTER       = "LDAP_USER_FILTER"
	LDAP_USER_DOMAIN       = "LDAP_USER_DOMAIN"
	LDAP_STARTTLS          = "LDAP_STARTTLS"
	LDAP_SKIP_TLS_VERIFY   = "LDAP_SKIP_TLS_VERIFY"
	LISTEN_ADDR            = "LISTEN_ADDR"
	VDI_IMAGE_DIR          = "VDI_IMAGE_DIR"
	VIRT_STORAGE_POOL_NAME = "VIRT_STORAGE_POOL_NAME"
	VIRT_STORAGE_POOL_PATH = "VIRT_STORAGE_POOL_PATH"
	VIRT_SERIAL_SOCKET_DIR = "VIRT_SERIAL_SOCKET_DIR"
	BASE_IMAGE_URL         = "BASE_IMAGE_URL"
	TIMEOUT                = "TIMEOUT"
)

// NOTE: prints at init-time (like your original). Consider false in libraries.
//var Settings = NewSettingType(true)
