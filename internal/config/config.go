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

// Kind values supported by Settings.
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

// Settings holds the process configuration keyed by environment-backed setting ID.
type Settings struct {
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
	// DefaultVMVCPUCount is the default number of virtual CPUs assigned to every
	// VM. Used when VM_VCPU_COUNT is unset or non-positive.
	DefaultVMVCPUCount = 4
	// DefaultVMMemoryMiB is the default memory, in MiB, assigned to every VM.
	// Used when VM_MEMORY_MIB is unset or non-positive.
	DefaultVMMemoryMiB = 4096
	// DefaultMaxVDIPerUser is the default maximum number of VDIs (VMs) each user
	// may own at once. Override with MAX_VDI_PER_USER.
	DefaultMaxVDIPerUser = 10
	// DefaultVDIAutoShutdownHours is the default number of hours a running VDI
	// may go unused before the gateway shuts it down. 0 disables auto-shutdown;
	// override with VDI_AUTO_SHUTDOWN_HOURS.
	DefaultVDIAutoShutdownHours = 0
	// DefaultMaxConcurrentConnections is the default cap on simultaneously open
	// front connections. Sized for ~100 active users: browsers hold up to 6
	// HTTP/1.1 keep-alive connections each, and every dashboard, console, and
	// VNC websocket plus every proxied RDP session holds one slot for its whole
	// lifetime, so organic bursts (a mass reconnect after a gateway restart)
	// need several times the steady-state count. Override with
	// MAX_CONCURRENT_CONNECTIONS.
	DefaultMaxConcurrentConnections = 4096
	// DefaultMaxConnectionsPerUser is the default cap on concurrently open
	// authenticated long-lived connections (dashboard control, serial console,
	// and VNC websockets, plus proxied RDP sessions) per user. Generous for
	// humans with many tabs, while keeping one scripted user from occupying a
	// meaningful share of the front-connection budget. Override with
	// MAX_CONNECTIONS_PER_USER.
	DefaultMaxConnectionsPerUser = 32
	// DefaultMaxConnectionsPerSource is the default cap on simultaneously open
	// front connections from one source address (one IPv4 address, or one /64
	// prefix for IPv6, since a single host commonly controls an entire /64).
	// Enforced before the TLS handshake, it keeps a single unauthenticated
	// source from exhausting the shared MAX_CONCURRENT_CONNECTIONS budget while
	// still leaving room for a few dozen users behind one NAT or proxy address.
	// Override with MAX_CONNECTIONS_PER_SOURCE.
	DefaultMaxConnectionsPerSource = 256
)

const (
	acmeDataSubdir      = "acme"
	imageDataSubdir     = "image"
	baseImageDataSubdir = "baseimages"
	serialDataSubdir    = "serial"
	vncDataSubdir       = "vnc"
)

// NewSettings builds the gateway settings from defaults and environment overrides.
func NewSettings(printSettings bool) *Settings {
	s := &Settings{m: make(map[string]*Setting)}

	s.SetString(DATA_ROOT_DIR, "Root directory for gateway-managed data", DefaultDataRootDir)
	s.SetString(VIRT_STORAGE_POOL_NAME, "Libvirt storage pool name for VM volumes", DefaultVirtStoragePoolName)

	s.SetString(BASE_IMAGE_DIR, "Directory of selectable base VDI images (.img/.qcow2/.raw); must contain at least one image at boot. Empty -> <DATA_ROOT_DIR>/baseimages", "")
	s.SetInt(VM_DISK_SIZE_GB, "Virtual disk capacity in GiB for newly created VM qcow2 volumes; the base image is grown to this size (qcow2 is thin-provisioned, so the host file only consumes written data). Values <=0 fall back to the default", DefaultVMDiskSizeGB)
	s.SetInt(VM_VCPU_COUNT, "Number of virtual CPUs assigned to every VM; users cannot choose or change this per VM. Values <=0 fall back to the default", DefaultVMVCPUCount)
	s.SetInt(VM_MEMORY_MIB, "Memory in MiB assigned to every VM; users cannot choose or change this per VM. Values <=0 fall back to the default", DefaultVMMemoryMiB)
	s.SetInt(MAX_VDI_PER_USER, "Maximum number of VDIs (VMs) each user may own at once; creating another VM is refused once the user owns this many. Values <=0 disable the per-user limit", DefaultMaxVDIPerUser)
	s.SetInt(VDI_AUTO_SHUTDOWN_HOURS, "Shut down a running VDI after this many hours without use; a VDI counts as used when it is created or started and whenever its owner opens RDP, serial, or noVNC from the dashboard. The guest is first asked to power off (ACPI) and is force-stopped if still running a few minutes later. Values <=0 disable auto-shutdown", DefaultVDIAutoShutdownHours)

	s.SetString(LISTEN_ADDR, "listen address", ":443")
	s.SetInt(MAX_CONCURRENT_CONNECTIONS, "Maximum number of simultaneously open front connections (RDP + HTTPS); connections beyond the cap are accepted and immediately closed (fail fast, logged) so clients see an error instead of hanging, bounding memory/FD use under a connection flood or slow pre-TLS clients. Values <=0 disable the cap", DefaultMaxConcurrentConnections)
	s.SetInt(MAX_CONNECTIONS_PER_USER, "Maximum number of concurrently open authenticated long-lived connections (dashboard/serial/VNC websockets and proxied RDP sessions) per user; connections beyond the cap are closed immediately so one scripted user cannot exhaust the shared front-connection budget. Values <=0 disable the cap", DefaultMaxConnectionsPerUser)
	s.SetInt(MAX_CONNECTIONS_PER_SOURCE, "Maximum number of simultaneously open front connections per source address (per IPv4 address, per /64 prefix for IPv6), enforced before authentication and the TLS handshake; connections beyond the cap are accepted and immediately closed (fail fast, logged) so one source cannot exhaust the shared MAX_CONCURRENT_CONNECTIONS budget. Raise it when many users share one NAT or proxy address. Values <=0 disable the cap", DefaultMaxConnectionsPerSource)
	s.SetString(CERT_FILE, "TLS certificate PEM for clients (front side)", "")
	s.SetString(KEY_FILE, "TLS private key PEM for clients (front side, unencrypted)", "")

	// Duration-typed setting
	s.SetDuration(TIMEOUT, "handshake/dial/read timeout for setup", 10*time.Second)

	s.SetBool(ACME_ENABLE, "enable ACME certificate management with certmagic for front TLS", false)
	s.SetString(ACME_EMAIL, "ACME account email (recommended)", "")
	s.SetString(ACME_CA, "ACME CA directory URL or 'staging'", "")
	s.SetString(FRONT_DOMAIN, "Front domain to serve front page on HTTPS requests and also the prefix for vm names", "desktop.local.gd")
	s.SetSecretString(SNI_HASH_SECRET, "Secret keying the HMAC that turns VM names into opaque SNI routing labels; auto-generated and persisted under the data root when empty", "")

	s.SetBool(DEBUG_CONNECTIONS, "Verbose debug logging of every accepted front connection and HTTP/WebSocket request (type, source address, method, path); use to trace connectivity", false)

	s.setAuthDefaults()

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

func (s *Settings) setAuthDefaults() {
	s.SetString(LDAP_URL, "LDAP server url", "ldaps://ldap:389")
	s.SetString(LDAP_BASE_DN, "LDAP base DN", "dc=glauth,dc=com")
	s.SetString(LDAP_USER_FILTER, "LDAP user filter", "(mail=%s)")
	s.SetString(LDAP_REQUIRED_GROUPS, "List of groups (bare names or full DNs, DNs must be ';'-delimited, bare names may use ',' too); when non-empty, LDAP login also requires the user's memberOf attribute to contain at least one listed group", "")
	s.SetString(LDAP_USER_DOMAIN, "LDAP user mail domain", "@example.com")
	s.SetBool(LDAP_STARTTLS, "Use StartTLS when connecting to LDAP", false)
	s.SetBool(LDAP_SKIP_TLS_VERIFY, "Skip TLS verification when connecting to LDAP", false)
	s.SetSecretString(LOCAL_USER_SHA256, "';'-delimited list of sha256(\"username:password\") hex digests for local users authenticated without LDAP", "")
	s.SetInt(LOGIN_RATE_LIMIT_MAX_ATTEMPTS, "Maximum failed login attempts allowed per username-and-client-IP pair within LOGIN_RATE_LIMIT_WINDOW; <=0 disables login throttling", 5)
	s.SetInt(LOGIN_RATE_LIMIT_IP_MAX_ATTEMPTS, "Maximum failed login attempts allowed across all usernames from one client IP within LOGIN_RATE_LIMIT_WINDOW; <=0 disables the IP-wide limit", 50)
	s.SetDuration(LOGIN_RATE_LIMIT_WINDOW, "Rolling window for failed login attempt counting", 5*time.Minute)
	s.SetDuration(LOGIN_RATE_LIMIT_LOCKOUT, "How long to reject login attempts after either login failure limit is reached", 15*time.Minute)
}

// DataRootDir resolves the root directory for gateway-managed data.
func DataRootDir(settings *Settings) string {
	rootDir := DefaultDataRootDir
	if settings != nil {
		if configuredRoot := strings.TrimSpace(settings.Get(DATA_ROOT_DIR)); configuredRoot != "" {
			rootDir = configuredRoot
		}
	}
	return filepath.Clean(rootDir)
}

// ACMEStorageDir resolves the ACME storage directory below the data root.
func ACMEStorageDir(settings *Settings) string {
	return filepath.Join(DataRootDir(settings), acmeDataSubdir)
}

// ImageDir resolves the VM image directory below the data root.
func ImageDir(settings *Settings) string {
	return filepath.Join(DataRootDir(settings), imageDataSubdir)
}

// BaseImageDir resolves the directory holding selectable base VDI images. An
// explicit BASE_IMAGE_DIR overrides the default <DATA_ROOT_DIR>/baseimages so
// operators can bind-mount an image library wherever they like.
func BaseImageDir(settings *Settings) string {
	if settings != nil {
		if configured := strings.TrimSpace(settings.Get(BASE_IMAGE_DIR)); configured != "" {
			return filepath.Clean(configured)
		}
	}
	return filepath.Join(DataRootDir(settings), baseImageDataSubdir)
}

// SerialSocketDir resolves the VM serial socket directory below the data root.
func SerialSocketDir(settings *Settings) string {
	return filepath.Join(DataRootDir(settings), serialDataSubdir)
}

// VNCSocketDir resolves the VM VNC socket directory below the data root.
func VNCSocketDir(settings *Settings) string {
	return filepath.Join(DataRootDir(settings), vncDataSubdir)
}

// VirtStoragePoolPath resolves the libvirt storage pool path below the data root.
func VirtStoragePoolPath(settings *Settings) string {
	return ImageDir(settings)
}

// MaxVDIPerUser resolves the maximum number of VDIs (VMs) a single user may
// own at once. A missing setting falls back to DefaultMaxVDIPerUser; a
// configured value <=0 disables the limit, reported as 0.
func MaxVDIPerUser(settings *Settings) int {
	limit := DefaultMaxVDIPerUser
	if settings != nil && settings.Has(MAX_VDI_PER_USER) {
		limit = settings.Int(MAX_VDI_PER_USER)
	}
	if limit <= 0 {
		return 0
	}
	return limit
}

// VDIAutoShutdownAfter resolves how long a running VDI may go unused before
// the gateway shuts it down, from VDI_AUTO_SHUTDOWN_HOURS. A missing or
// non-positive setting disables auto-shutdown, reported as 0.
func VDIAutoShutdownAfter(settings *Settings) time.Duration {
	if settings == nil {
		return 0
	}
	hours := settings.Int(VDI_AUTO_SHUTDOWN_HOURS)
	if hours <= 0 {
		return 0
	}
	return time.Duration(hours) * time.Hour
}

// VMDiskCapacityBytes resolves the virtual disk capacity, in bytes, for newly
// created VM volumes. A non-positive or missing VM_DISK_SIZE_GB falls back to
// DefaultVMDiskSizeGB.
func VMDiskCapacityBytes(settings *Settings) uint64 {
	sizeGB := DefaultVMDiskSizeGB
	if settings != nil {
		if configured := settings.Int(VM_DISK_SIZE_GB); configured > 0 {
			sizeGB = configured
		}
	}
	return uint64(sizeGB) * 1024 * 1024 * 1024
}

// VMVCPUCount resolves the number of virtual CPUs assigned to every VM. VM
// resources are operator-defined only: users cannot choose or change them. A
// non-positive or missing VM_VCPU_COUNT falls back to DefaultVMVCPUCount.
func VMVCPUCount(settings *Settings) int {
	if settings != nil {
		if configured := settings.Int(VM_VCPU_COUNT); configured > 0 {
			return configured
		}
	}
	return DefaultVMVCPUCount
}

// VMMemoryMiB resolves the memory, in MiB, assigned to every VM. VM resources
// are operator-defined only: users cannot choose or change them. A
// non-positive or missing VM_MEMORY_MIB falls back to DefaultVMMemoryMiB.
func VMMemoryMiB(settings *Settings) int {
	if settings != nil {
		if configured := settings.Int(VM_MEMORY_MIB); configured > 0 {
			return configured
		}
	}
	return DefaultVMMemoryMiB
}

// ---- Setters ----

// SetString registers a string setting and resolves its effective value.
func (s *Settings) SetString(id, description, defaultValue string) {
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
// process logs; Get/String still return the real value to feature code.
func (s *Settings) SetSecretString(id, description, defaultValue string) {
	s.SetString(id, description, defaultValue)
	s.m[id].Secret = true
}

// SetInt registers an integer setting and resolves its effective value.
func (s *Settings) SetInt(id, description string, defaultValue int) {
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
func (s *Settings) SetBool(id, description string, defaultValue bool) {
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
func (s *Settings) SetDuration(id, description string, defaultValue time.Duration) {
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
func (s *Settings) Has(id string) bool {
	_, ok := s.m[id]
	return ok
}

// Get returns the setting value as a string.
func (s *Settings) Get(id string) string { return s.String(id) }

// String returns the setting value as a string.
func (s *Settings) String(id string) string {
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

// Int returns the setting value as an int.
func (s *Settings) Int(id string) int {
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

// Bool returns the setting value as a bool.
func (s *Settings) Bool(id string) bool {
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
func (s *Settings) IsTrue(id string) bool {
	return s.Bool(id)
}

// Duration returns the setting value as a duration.
func (s *Settings) Duration(id string) time.Duration {
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
	ACME_EMAIL                       = "ACME_EMAIL"
	ACME_CA                          = "ACME_CA"
	ACME_ENABLE                      = "ACME_ENABLE"
	CERT_FILE                        = "CERT_FILE"
	DATA_ROOT_DIR                    = "DATA_ROOT_DIR"
	FRONT_DOMAIN                     = "FRONT_DOMAIN"
	KEY_FILE                         = "KEY_FILE"
	LDAP_URL                         = "LDAP_URL"
	LDAP_BASE_DN                     = "LDAP_BASE_DN"
	LDAP_USER_FILTER                 = "LDAP_USER_FILTER"
	LDAP_REQUIRED_GROUPS             = "LDAP_REQUIRED_GROUPS"
	LDAP_USER_DOMAIN                 = "LDAP_USER_DOMAIN"
	LDAP_STARTTLS                    = "LDAP_STARTTLS"
	LDAP_SKIP_TLS_VERIFY             = "LDAP_SKIP_TLS_VERIFY"
	LOCAL_USER_SHA256                = "LOCAL_USER_SHA256"
	LOGIN_RATE_LIMIT_MAX_ATTEMPTS    = "LOGIN_RATE_LIMIT_MAX_ATTEMPTS"
	LOGIN_RATE_LIMIT_IP_MAX_ATTEMPTS = "LOGIN_RATE_LIMIT_IP_MAX_ATTEMPTS"
	LOGIN_RATE_LIMIT_WINDOW          = "LOGIN_RATE_LIMIT_WINDOW"
	LOGIN_RATE_LIMIT_LOCKOUT         = "LOGIN_RATE_LIMIT_LOCKOUT"
	LISTEN_ADDR                      = "LISTEN_ADDR"
	MAX_CONCURRENT_CONNECTIONS       = "MAX_CONCURRENT_CONNECTIONS"
	MAX_VDI_PER_USER                 = "MAX_VDI_PER_USER"
	MAX_CONNECTIONS_PER_USER         = "MAX_CONNECTIONS_PER_USER"
	MAX_CONNECTIONS_PER_SOURCE       = "MAX_CONNECTIONS_PER_SOURCE"
	SNI_HASH_SECRET                  = "SNI_HASH_SECRET" // #nosec G101 -- setting key name, not a credential
	VDI_AUTO_SHUTDOWN_HOURS          = "VDI_AUTO_SHUTDOWN_HOURS"
	VIRT_STORAGE_POOL_NAME           = "VIRT_STORAGE_POOL_NAME"
	BASE_IMAGE_DIR                   = "BASE_IMAGE_DIR"
	VM_DISK_SIZE_GB                  = "VM_DISK_SIZE_GB"
	VM_VCPU_COUNT                    = "VM_VCPU_COUNT"
	VM_MEMORY_MIB                    = "VM_MEMORY_MIB"
	TIMEOUT                          = "TIMEOUT"
	DEBUG_CONNECTIONS                = "DEBUG_CONNECTIONS"
)

// OverwriteForTestString replaces a string setting value for tests.
func (s *Settings) OverwriteForTestString(id, value string) error {
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
func (s *Settings) OverwriteForTestInt(id string, value int) error {
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
func (s *Settings) OverwriteForTestBool(id string, value bool) error {
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
func (s *Settings) OverwriteForTestDuration(id string, value time.Duration) error {
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
