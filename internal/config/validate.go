package config

import (
	"fmt"
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

// ValidateSplunkHEC rejects a partial Splunk HEC configuration. Forwarding is
// enabled by SPLUNK_HEC_ENDPOINT, which then requires SPLUNK_HEC_TOKEN; a token
// or index without an endpoint means forwarding was intended but would
// silently never happen, so the boot fails instead of dropping audit events.
func ValidateSplunkHEC(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	endpointSet := strings.TrimSpace(settings.Get(SPLUNK_HEC_ENDPOINT)) != ""
	tokenSet := strings.TrimSpace(settings.Get(SPLUNK_HEC_TOKEN)) != ""
	indexSet := strings.TrimSpace(settings.Get(SPLUNK_HEC_INDEX)) != ""
	switch {
	case endpointSet && !tokenSet:
		return fmt.Errorf("%s is set but %s is empty; splunk hec forwarding requires a token", SPLUNK_HEC_ENDPOINT, SPLUNK_HEC_TOKEN)
	case !endpointSet && (tokenSet || indexSet):
		return fmt.Errorf("%s or %s is set but %s is empty; set the endpoint to forward audit events to splunk hec, or remove the other SPLUNK_HEC_* settings", SPLUNK_HEC_TOKEN, SPLUNK_HEC_INDEX, SPLUNK_HEC_ENDPOINT)
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
