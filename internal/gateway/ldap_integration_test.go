package gateway

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/ldap"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPAuthenticateWithGlauthConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	settings := config.NewSettings(false)
	u, err := ldap.AuthenticateAccess(ctx, "testuser", "dogood", settings)
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}
}

func TestLDAPAuthenticateJohndoeSingleNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	settings := config.NewSettings(false)

	u, err := ldap.AuthenticateAccess(ctx, "johndoe", "dogood", settings)
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}
}

func startGlauth(ctx context.Context, t *testing.T, network string) (string, func()) {
	t.Helper()

	cfg := pathRelative(t, "testldap", "default-config.cfg")
	cert := pathRelative(t, "testldap", "cert.pem")
	key := pathRelative(t, "testldap", "key.pem")

	req := testcontainers.ContainerRequest{
		Image:        "glauth/glauth:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"GLAUTH_CONFIG": "/app/config/config.cfg",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfg, ContainerFilePath: "/app/config/config.cfg", FileMode: 0o644},
			{HostFilePath: cert, ContainerFilePath: "/app/config/cert.pem", FileMode: 0o644},
			{HostFilePath: key, ContainerFilePath: "/app/config/key.pem", FileMode: 0o600},
		},
		Networks:       nil,
		NetworkAliases: nil,
		WaitingFor: wait.ForLog("LDAPS server listening").
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
	}
	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"ldap"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start glauth container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("ldaps://%s:%s", host, port.Port())

	return url, func() {
		_ = container.Terminate(context.Background())
	}
}

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{"..", ".."}, elems...)...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}
