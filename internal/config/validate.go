package config

import (
	"fmt"
	"strings"
)

// ValidateFrontDomain ensures FRONT_DOMAIN is set. It is required for RDP SNI
// routing: every VM is reached at an opaque "<label>.<FRONT_DOMAIN>" host, and
// the RDP front handler resolves a connection by stripping that suffix to
// recover the routing label. With FRONT_DOMAIN empty, the front handler's SNI
// validation rejects every RDP connection even though the dashboard would still
// hand out .rdp files — leaving the gateway in a state where RDP can never
// succeed. Fail fast at boot instead of starting in that broken state.
func ValidateFrontDomain(settings *SettingsType) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	if strings.TrimSpace(settings.Get(FRONT_DOMAIN)) == "" {
		return fmt.Errorf("%s must be set; it is the required domain suffix for RDP SNI routing and the front page, and without it every RDP connection is rejected", FRONT_DOMAIN)
	}
	return nil
}
