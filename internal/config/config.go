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

	// Secret masks the value in the printed settings table so credentials such
	// as passphrases are not written to logs.
	Secret bool
}

// SettingsType holds the process configuration keyed by environment-backed setting ID.
type SettingsType struct {
	m map[string]*Setting
}

const (
	// DefaultDataRootDir is the default root directory for gateway-managed data.
	// It lives under /var/lib/libvirt so VM disk images and sockets sit in a tree
	// libvirt/QEMU can use under SELinux (svirt) without relabeling a custom path
	// such as /data. Override with DATA_ROOT_DIR.
	DefaultDataRootDir = "/var/lib/libvirt/devbox-gateway"
	// DefaultVirtStoragePoolName is the default libvirt storage pool name.
	DefaultVirtStoragePoolName = "desktop"
	// DefaultVMDiskSizeGB is the default virtual disk capacity, in GiB, for newly
	// created VM volumes. Used when VM_DISK_SIZE_GB is unset or non-positive.
	DefaultVMDiskSizeGB = 200
	// DefaultMaxVDIPerUser is the default maximum number of VDIs (VMs) each user
	// may own at once. Override with MAX_VDI_PER_USER.
	DefaultMaxVDIPerUser = 10
)

const (
	acmeDataSubdir      = "acme"
	imageDataSubdir     = "image"
	baseImageDataSubdir = "baseimages"
	serialDataSubdir    = "serial"
	vncDataSubdir       = "vnc"
)

// NewSettingType builds the gateway settings from defaults and environment overrides.
func NewSettingType(printSettings bool) *SettingsType {
	s := &SettingsType{m: make(map[string]*Setting)}

	s.SetString(DATA_ROOT_DIR, "Root directory for gateway-managed data", DefaultDataRootDir)
	s.SetString(VIRT_STORAGE_POOL_NAME, "Libvirt storage pool name for VM volumes", DefaultVirtStoragePoolName)

	s.SetString(BASE_IMAGE_DIR, "Directory of selectable base VDI images (.img/.qcow2/.raw); must contain at least one image at boot. Empty -> <DATA_ROOT_DIR>/baseimages", "")
	s.SetInt(VM_DISK_SIZE_GB, "Virtual disk capacity in GiB for newly created VM qcow2 volumes; the base image is grown to this size (qcow2 is thin-provisioned, so the host file only consumes written data). Values <=0 fall back to the default", DefaultVMDiskSizeGB)
	s.SetInt(MAX_VDI_PER_USER, "Maximum number of VDIs (VMs) each user may own at once; creating another VM is refused once the user owns this many. Values <=0 disable the per-user limit", DefaultMaxVDIPerUser)

	s.SetString(LISTEN_ADDR, "listen address", ":443")
	s.SetInt(MAX_CONCURRENT_CONNECTIONS, "Maximum number of simultaneously accepted front connections (RDP + HTTPS); Accept blocks once this many are open and resumes as connections close, bounding memory/FD use under a connection flood or slow pre-TLS clients. Values <=0 disable the cap", 1024)
	s.SetString(CERT_FILE, "TLS certificate PEM for clients (front side)", "")
	s.SetString(KEY_FILE, "TLS private key PEM for clients (front side, unencrypted)", "")

	// Duration-typed setting
	s.SetDuration(TIMEOUT, "handshake/dial/read timeout for setup", 10*time.Second)

	s.SetBool(ACME_ENABLE, "enable ACME certificate management with certmagic for front TLS", false)
	s.SetString(ACME_EMAIL, "ACME account email (recommended)", "")
	s.SetString(ACME_CA, "ACME CA directory URL or 'staging'", "")
	s.SetString(FRONT_DOMAIN, "Front domain to serve front page on HTTPS requests and also the prefix for vm names", "desktop.local.gd")
	s.SetSecretString(SNI_HASH_SECRET, "Secret keying the HMAC that turns VM names into opaque SNI routing labels; auto-generated and persisted under the data root when empty", "")

	s.SetBool(RDP_DISABLE_CLIPBOARD, "Strip clipboard (cliprdr) channel from RDP sessions so the gateway prevents clipboard redirection regardless of client/VM policy", false)
	s.SetBool(RDP_DISABLE_DRIVES, "Strip drive redirection (rdpdr) channel from RDP sessions so the gateway prevents local drive mapping regardless of client/VM policy", false)

	s.SetBool(DEBUG_CONNECTIONS, "Verbose debug logging of every accepted front connection and HTTP/WebSocket request (type, source address, method, path); use to trace connectivity, e.g. through the SSH reverse tunnel", false)

	s.setAuthDefaults()
	s.setSSHTunnelDefaults()

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
			value := st.Raw
			if st.Secret && value != "" {
				value = "***"
			}
			_ = table.Append([]string{key, st.Description, value})
		}
		_ = table.Render()
	}

	return s
}

func (s *SettingsType) setAuthDefaults() {
	s.SetString(LDAP_URL, "LDAP server url", "ldaps://ldap:389")
	s.SetString(LDAP_BASE_DN, "LDAP base DN", "dc=glauth,dc=com")
	s.SetString(LDAP_USER_FILTER, "LDAP user filter", "(mail=%s)")
	s.SetString(LDAP_USER_DOMAIN, "LDAP user mail domain", "@example.com")
	s.SetBool(LDAP_STARTTLS, "Use StartTLS when connecting to LDAP", false)
	s.SetBool(LDAP_SKIP_TLS_VERIFY, "Skip TLS verification when connecting to LDAP", false)
	s.SetSecretString(LOCAL_USER_SHA256, "';'-delimited list of sha256(\"username:password\") hex digests for local users authenticated without LDAP", "")
	s.SetInt(LOGIN_RATE_LIMIT_MAX_ATTEMPTS, "Maximum failed login attempts allowed per username or client IP within LOGIN_RATE_LIMIT_WINDOW; <=0 disables login throttling", 5)
	s.SetDuration(LOGIN_RATE_LIMIT_WINDOW, "Rolling window for failed login attempt counting", 5*time.Minute)
	s.SetDuration(LOGIN_RATE_LIMIT_LOCKOUT, "How long to reject login attempts after LOGIN_RATE_LIMIT_MAX_ATTEMPTS failures", 15*time.Minute)
}

// setSSHTunnelDefaults registers the SSH reverse-tunnel settings. Instead of
// binding the front listener locally, the gateway can dial out to a public
// relay over SSH and have it listen on the gateway's behalf, so a gateway behind
// NAT can publish its :443 service on a reachable host.
func (s *SettingsType) setSSHTunnelDefaults() {
	s.SetBool(SSH_TUNNEL_ENABLE, "Publish the front listener through an SSH reverse tunnel to a public relay instead of binding locally; lets the gateway run behind NAT", false)
	s.SetString(SSH_TUNNEL_SERVER, "Relay SSH endpoint as <ip>:<port> (literal IP required so DNS cannot redirect the outbound dial)", "")
	s.SetString(SSH_TUNNEL_USER, "SSH username used to authenticate to the relay", "")
	s.SetString(SSH_TUNNEL_PRIVATE_KEY, "Path to the PEM SSH private key used to authenticate to the relay", "/etc/devbox-gateway/ssh/id_ed25519")
	s.SetSecretString(SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE, "Passphrase for the SSH private key; leave empty for an unencrypted key", "")
	s.SetString(SSH_TUNNEL_KNOWN_HOSTS, "Path to a known_hosts file pinning the relay's SSH host key", "/etc/devbox-gateway/ssh/known_hosts")
	s.SetString(SSH_TUNNEL_REMOTE_ADDR, "Address the relay listens on and forwards back through the tunnel", ":443")
	s.SetDuration(SSH_TUNNEL_KEEPALIVE_INTERVAL, "Interval between SSH keepalive probes that detect a dead tunnel", 15*time.Second)
	s.SetDuration(SSH_TUNNEL_KEEPALIVE_TIMEOUT, "Time to wait for an SSH keepalive reply before treating the tunnel as dead", 10*time.Second)
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

// BaseImageDir resolves the directory holding selectable base VDI images. An
// explicit BASE_IMAGE_DIR overrides the default <DATA_ROOT_DIR>/baseimages so
// operators can bind-mount an image library wherever they like.
func BaseImageDir(settings *SettingsType) string {
	if settings != nil {
		if configured := strings.TrimSpace(settings.Get(BASE_IMAGE_DIR)); configured != "" {
			return filepath.Clean(configured)
		}
	}
	return filepath.Join(DataRootDir(settings), baseImageDataSubdir)
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

// MaxVDIPerUser resolves the maximum number of VDIs (VMs) a single user may
// own at once. A missing setting falls back to DefaultMaxVDIPerUser; a
// configured value <=0 disables the limit, reported as 0.
func MaxVDIPerUser(settings *SettingsType) int {
	limit := DefaultMaxVDIPerUser
	if settings != nil && settings.Has(MAX_VDI_PER_USER) {
		limit = settings.GetInt(MAX_VDI_PER_USER)
	}
	if limit <= 0 {
		return 0
	}
	return limit
}

// VMDiskCapacityBytes resolves the virtual disk capacity, in bytes, for newly
// created VM volumes. A non-positive or missing VM_DISK_SIZE_GB falls back to
// DefaultVMDiskSizeGB.
func VMDiskCapacityBytes(settings *SettingsType) uint64 {
	sizeGB := DefaultVMDiskSizeGB
	if settings != nil {
		if configured := settings.GetInt(VM_DISK_SIZE_GB); configured > 0 {
			sizeGB = configured
		}
	}
	return uint64(sizeGB) * 1024 * 1024 * 1024
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

// SetSecretString registers a string setting whose value is masked in the
// printed settings table. Use it for credentials so secrets do not leak into
// process logs; Get/GetString still return the real value to feature code.
func (s *SettingsType) SetSecretString(id, description, defaultValue string) {
	s.SetString(id, description, defaultValue)
	s.m[id].Secret = true
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
	ACME_EMAIL                    = "ACME_EMAIL"
	ACME_CA                       = "ACME_CA"
	ACME_ENABLE                   = "ACME_ENABLE"
	CERT_FILE                     = "CERT_FILE"
	DATA_ROOT_DIR                 = "DATA_ROOT_DIR"
	FRONT_DOMAIN                  = "FRONT_DOMAIN"
	KEY_FILE                      = "KEY_FILE"
	LDAP_URL                      = "LDAP_URL"
	LDAP_BASE_DN                  = "LDAP_BASE_DN"
	LDAP_USER_FILTER              = "LDAP_USER_FILTER"
	LDAP_USER_DOMAIN              = "LDAP_USER_DOMAIN"
	LDAP_STARTTLS                 = "LDAP_STARTTLS"
	LDAP_SKIP_TLS_VERIFY          = "LDAP_SKIP_TLS_VERIFY"
	LOCAL_USER_SHA256             = "LOCAL_USER_SHA256"
	LOGIN_RATE_LIMIT_MAX_ATTEMPTS = "LOGIN_RATE_LIMIT_MAX_ATTEMPTS"
	LOGIN_RATE_LIMIT_WINDOW       = "LOGIN_RATE_LIMIT_WINDOW"
	LOGIN_RATE_LIMIT_LOCKOUT      = "LOGIN_RATE_LIMIT_LOCKOUT"
	LISTEN_ADDR                   = "LISTEN_ADDR"
	MAX_CONCURRENT_CONNECTIONS    = "MAX_CONCURRENT_CONNECTIONS"
	MAX_VDI_PER_USER              = "MAX_VDI_PER_USER"
	RDP_DISABLE_CLIPBOARD         = "RDP_DISABLE_CLIPBOARD"
	RDP_DISABLE_DRIVES            = "RDP_DISABLE_DRIVES"
	SNI_HASH_SECRET               = "SNI_HASH_SECRET"
	VIRT_STORAGE_POOL_NAME        = "VIRT_STORAGE_POOL_NAME"
	BASE_IMAGE_DIR                = "BASE_IMAGE_DIR"
	VM_DISK_SIZE_GB               = "VM_DISK_SIZE_GB"
	TIMEOUT                       = "TIMEOUT"
	DEBUG_CONNECTIONS             = "DEBUG_CONNECTIONS"

	SSH_TUNNEL_ENABLE                 = "SSH_TUNNEL_ENABLE"
	SSH_TUNNEL_SERVER                 = "SSH_TUNNEL_SERVER"
	SSH_TUNNEL_USER                   = "SSH_TUNNEL_USER"
	SSH_TUNNEL_PRIVATE_KEY            = "SSH_TUNNEL_PRIVATE_KEY"
	SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE = "SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE"
	SSH_TUNNEL_KNOWN_HOSTS            = "SSH_TUNNEL_KNOWN_HOSTS"
	SSH_TUNNEL_REMOTE_ADDR            = "SSH_TUNNEL_REMOTE_ADDR"
	SSH_TUNNEL_KEEPALIVE_INTERVAL     = "SSH_TUNNEL_KEEPALIVE_INTERVAL"
	SSH_TUNNEL_KEEPALIVE_TIMEOUT      = "SSH_TUNNEL_KEEPALIVE_TIMEOUT"
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
