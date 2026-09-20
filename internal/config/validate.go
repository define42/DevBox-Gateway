package config

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

// ValidateLDAPURL ensures the required LDAP authentication backend is set.
// Without another authentication mechanism, starting with an empty LDAP_URL
// would leave every user unable to log in, so reject that configuration at
// boot instead of serving a permanently unusable login page.
func ValidateLDAPURL(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	if strings.TrimSpace(settings.Get(LDAP_URL)) == "" {
		return fmt.Errorf("%s must be set; LDAP is the required authentication backend", LDAP_URL)
	}
	return nil
}

// ValidateLDAPUserDomain ensures every accepted bare username can be converted
// to the authoritative mail/UPN form used for LDAP bind and search. Missing or
// malformed suffixes violate that identity contract, so fail during startup.
func ValidateLDAPUserDomain(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	domain := strings.TrimPrefix(strings.TrimSpace(settings.Get(LDAP_USER_DOMAIN)), "@")
	if domain == "" || strings.ContainsRune(domain, '@') || strings.ContainsAny(domain, " \t\r\n") {
		return fmt.Errorf("%s must contain one non-empty domain suffix for bare usernames", LDAP_USER_DOMAIN)
	}
	return nil
}

// ValidateFrontDomain ensures FRONT_DOMAIN is set. It is required for RDP SNI
// routing: every VM is reached at an opaque "<label>.<FRONT_DOMAIN>" host, and
// the RDP front handler resolves a connection by stripping that suffix to
// recover the routing label. With FRONT_DOMAIN empty, the front handler's SNI
// validation rejects every RDP connection even though the dashboard would still
// hand out .rdp files — leaving the gateway in a state where RDP can never
// succeed. Fail fast at boot instead of starting in that broken state.
func ValidateFrontDomain(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	if strings.TrimSpace(settings.Get(FRONT_DOMAIN)) == "" {
		return fmt.Errorf("%s must be set; it is the required domain suffix for rdp sni routing and the front page, and without it every rdp connection is rejected", FRONT_DOMAIN)
	}
	return nil
}

// ValidateRDPPort rejects invalid advertised-port overrides. Empty derives the
// port from LISTEN_ADDR; an explicit override must name a usable numeric TCP port.
func ValidateRDPPort(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	raw := strings.TrimSpace(settings.Get(RDP_PORT))
	if raw == "" {
		return nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s must be empty or a TCP port between 1 and 65535", RDP_PORT)
	}
	return nil
}

// ValidateSplunkHEC rejects a partial Splunk HEC configuration. Forwarding is
// enabled by SPLUNK_HEC_ENDPOINT, which then requires SPLUNK_HEC_TOKEN. A token,
// index or enabled indexer acknowledgement without an endpoint indicates an
// incomplete forwarding configuration, so startup fails.
func ValidateSplunkHEC(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	if err := validateHECSettings(settings, SPLUNK_HEC_ENDPOINT, SPLUNK_HEC_TOKEN, SPLUNK_HEC_INDEX, SPLUNK_HEC_ACK_ENABLED, "audit events"); err != nil {
		return err
	}
	if mib := settings.Int(DEVBOX_GATEWAY_SPOOL_MAX_MIB); mib > 0 && int64(mib) > math.MaxInt64>>20 {
		return fmt.Errorf("%s is too large to represent as a byte limit", DEVBOX_GATEWAY_SPOOL_MAX_MIB)
	}
	return nil
}

// ValidateSauron requires an event output for the mandatory guest collector
// and rejects partial Splunk HEC settings.
func ValidateSauron(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	endpointSet := strings.TrimSpace(settings.Get(SAURON_SPLUNK_HEC_ENDPOINT)) != ""
	if err := validateHECSettings(settings, SAURON_SPLUNK_HEC_ENDPOINT, SAURON_SPLUNK_HEC_TOKEN, SAURON_SPLUNK_HEC_INDEX, SAURON_SPLUNK_HEC_ACK_ENABLED, "SauronAgent guest events"); err != nil {
		return err
	}
	if !endpointSet && strings.TrimSpace(settings.Get(SAURON_EVENT_LOG_FILE)) == "" {
		return fmt.Errorf("SauronAgent collection is mandatory but both %s and %s are empty; set at least one so guest events are kept somewhere", SAURON_EVENT_LOG_FILE, SAURON_SPLUNK_HEC_ENDPOINT)
	}
	return nil
}

// validateHECSettings rejects a partial set of Splunk HEC settings: an
// endpoint needs a token, and a token, index or enabled acknowledgement
// without an endpoint means forwarding was intended but would never happen.
func validateHECSettings(settings *Settings, endpointKey, tokenKey, indexKey, ackKey, forwarded string) error {
	endpointSet := strings.TrimSpace(settings.Get(endpointKey)) != ""
	tokenSet := strings.TrimSpace(settings.Get(tokenKey)) != ""
	indexSet := strings.TrimSpace(settings.Get(indexKey)) != ""
	switch {
	case endpointSet && !tokenSet:
		return fmt.Errorf("%s is set but %s is empty; splunk hec forwarding requires a token", endpointKey, tokenKey)
	case !endpointSet && settings.Bool(ackKey):
		return fmt.Errorf("%s is true but %s is empty; splunk hec acknowledgement requires an endpoint", ackKey, endpointKey)
	case !endpointSet && (tokenSet || indexSet):
		return fmt.Errorf("%s or %s is set but %s is empty; set the endpoint to forward %s to splunk hec, or remove the other %s settings", tokenKey, indexKey, endpointKey, forwarded, strings.TrimSuffix(endpointKey, "ENDPOINT")+"*")
	}
	return nil
}

// removedSSHTunnelEnableKey is the boot switch of the removed SSH reverse-tunnel
// mode. It is no longer a registered setting; it is recognized only to refuse
// booting a configuration that still expects the tunnel.
const removedSSHTunnelEnableKey = "SSH_TUNNEL_ENABLE"

// ValidateRemovedSSHTunnelMode fails the boot when the environment — including
// a config file merged into it by LoadConfigFile, such as one preserved across
// a package upgrade — still enables the removed SSH reverse-tunnel mode. Such a
// gateway used to publish itself only through an outbound SSH connection;
// silently binding LISTEN_ADDR instead would expose a local listener the
// operator never intended, or collide with whatever now owns the port. Values
// that do not parse as a bool are ignored, matching how the setting was
// resolved when it existed. Call after LoadConfigFile.
func ValidateRemovedSSHTunnelMode() error {
	raw, ok := os.LookupEnv(removedSSHTunnelEnableKey)
	if !ok {
		return nil
	}
	enabled, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil || !enabled {
		return nil
	}
	return fmt.Errorf("%s=true is set, but the ssh reverse-tunnel mode has been removed; remove the SSH_TUNNEL_* settings and expose LISTEN_ADDR directly instead", removedSSHTunnelEnableKey)
}
