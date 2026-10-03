package rdp

import (
	"log"
	"net"
	"strings"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
)

// resolveFrontRoute selects a VM exclusively from its loadbalanceinfo token.
// TLS SNI, when present, identifies the shared gateway domain, never a VM.
func resolveFrontRoute(token, sni string, remoteAddr net.Addr, settings *config.Settings, sessionManager *session.Manager) (string, bool) {
	if token == "" {
		log.Printf("missing RDP routing token from %s", remoteAddr)
		return "", false
	}
	if !validRoutingToken(token) {
		log.Printf("invalid RDP routing token from %s", remoteAddr)
		return "", false
	}
	domain := strings.ToLower(strings.TrimSpace(settings.Get(config.FRONT_DOMAIN)))
	if sni != "" && sni != domain {
		log.Printf("client SNI=%q does not match front domain %q from %s", sni, domain, remoteAddr)
		return "", false
	}
	clientIP, ok := session.CanonicalClientIP(remoteAddr.String())
	if !ok || sessionManager == nil {
		log.Printf("RDP routing denied from %s: invalid client IP or session manager unavailable", remoteAddr)
		return "", false
	}
	hostname, ok := sessionManager.RDPConnectTarget(token, clientIP)
	if !ok {
		log.Printf("unknown, expired, or unauthorized RDP routing token from %s", remoteAddr)
		return "", false
	}
	debugf("resolved RDP routing token to vm=%q", hostname)
	return hostname, true
}
