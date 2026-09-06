package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/go-ldap/ldap/v3"
)

type connection struct {
	*ldap.Conn

	transport  net.Conn
	stopCancel func() bool
}

func (c *connection) Close() error {
	c.stopCancel()
	// LDAP Close waits for its message loop before closing the socket. Close the
	// transport first so a blocked write cannot prevent that loop from exiting.
	_ = c.transport.Close()
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func dialLDAP(ctx context.Context, settings *config.Settings) (*connection, error) {
	u, err := parseLDAPURL(settings.Get(config.LDAP_URL))
	if err != nil {
		return nil, err
	}
	network, address, err := ldapAddress(u)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	// StartTLS replaces ldap.Conn's internal transport. Always close the original
	// socket on cancellation to avoid racing that replacement and to interrupt
	// every LDAP operation, including TLS negotiation and blocked writes.
	c := &connection{transport: raw, stopCancel: context.AfterFunc(ctx, func() { _ = raw.Close() })}
	if err := c.start(ctx, u, settings); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (c *connection) start(ctx context.Context, u *url.URL, settings *config.Settings) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.transport.SetDeadline(deadline); err != nil {
			return err
		}
	}
	// #nosec G402 -- InsecureSkipVerify is an explicit operator opt-in via LDAP_SKIP_TLS_VERIFY (default off).
	tlsConfig := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: settings.IsTrue(config.LDAP_SKIP_TLS_VERIFY),
		MinVersion:         tls.VersionTLS12,
	}
	transport := c.transport
	isTLS := u.Scheme == "ldaps"
	if isTLS {
		tlsConn := tls.Client(transport, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return err
		}
		transport = tlsConn
	}
	c.Conn = ldap.NewConn(transport, isTLS)
	c.Start()
	if settings.IsTrue(config.LDAP_STARTTLS) && u.Scheme == "ldap" {
		return c.StartTLS(tlsConfig)
	}
	return nil
}

// parseLDAPURL preserves go-ldap's encoded-host and legacy-path Unix socket URLs;
// net/url rejects percent-encoded slashes in a host.
func parseLDAPURL(rawURL string) (*url.URL, error) {
	rest, ok := strings.CutPrefix(rawURL, "ldapi://")
	if !ok {
		return url.Parse(rawURL)
	}
	host, path, _ := strings.Cut(rest, "/")
	socketPath := "/" + path
	if host != "" {
		decoded, err := url.PathUnescape(host)
		if err != nil {
			return nil, fmt.Errorf("ldapi: invalid socket path: %w", err)
		}
		socketPath = decoded
	}
	if socketPath == "/" {
		socketPath = "/var/run/slapd/ldapi"
	}
	return &url.URL{Scheme: "ldapi", Path: socketPath}, nil
}

func ldapAddress(u *url.URL) (string, string, error) {
	network, defaultPort := "tcp", ldap.DefaultLdapPort
	switch u.Scheme {
	case "ldap":
	case "ldaps":
		defaultPort = ldap.DefaultLdapsPort
	case "cldap":
		network = "udp"
	case "ldapi":
		return "unix", u.Path, nil
	default:
		return "", "", fmt.Errorf("unsupported LDAP scheme %q", u.Scheme)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	return network, net.JoinHostPort(u.Hostname(), port), nil
}
