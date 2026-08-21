package ldap

import (
	"context"
	"devboxgateway/internal/config"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestDialLDAPInvalidURL(t *testing.T) {
	t.Setenv(config.LDAP_URL, "://bad-url")
	settings := config.NewSettingType(false)

	if _, err := dialLDAP(settings); err == nil {
		t.Fatal("expected invalid LDAP URL to fail")
	}
}

func TestDialLDAPWithGlauth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
	defer cleanup()

	applyLDAPSettings(t, ldapURL)
	settings := config.NewSettingType(false)

	conn, err := dialLDAP(settings)
	if err != nil {
		t.Fatalf("dialLDAP(): %v", err)
	}
	defer func() { _ = conn.Close() }()
}

func TestAuthenticateAccessWithUserDomainSuffix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
	defer cleanup()

	applyLDAPSettings(t, ldapURL)
	settings := config.NewSettingType(false)

	user, err := AuthenticateAccess("johndoe", "dogood", settings)
	if err != nil {
		t.Fatalf("AuthenticateAccess(): %v", err)
	}
	if user == nil || user.Name != "johndoe" {
		t.Fatalf("expected johndoe user, got %#v", user)
	}
}

func TestAuthenticateAccessWithExplicitEmail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
	defer cleanup()

	applyLDAPSettings(t, ldapURL)
	t.Setenv(config.LDAP_USER_DOMAIN, "")
	settings := config.NewSettingType(false)

	user, err := AuthenticateAccess("johndoe@example.com", "dogood", settings)
	if err != nil {
		t.Fatalf("AuthenticateAccess(): %v", err)
	}
	if user == nil || user.Name != "johndoe@example.com" {
		t.Fatalf("expected explicit email user, got %#v", user)
	}
}

func TestAuthenticateAccessRejectsUnexpectedDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
	defer cleanup()

	applyLDAPSettings(t, ldapURL)
	t.Setenv(config.LDAP_USER_DOMAIN, "@wrong.test")
	settings := config.NewSettingType(false)

	_, err := AuthenticateAccess("johndoe", "dogood", settings)
	if err == nil {
		t.Fatal("expected authentication to fail")
	}
	if !strings.Contains(err.Error(), "ldap search") && !strings.Contains(err.Error(), "ldap bind failed") {
		t.Fatalf("expected LDAP auth failure, got %v", err)
	}
}

func TestAuthenticateAccessUserNotFoundAfterBind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
	defer cleanup()

	applyLDAPSettings(t, ldapURL)
	t.Setenv(config.LDAP_USER_FILTER, "(&(mail=%s)(cn=does-not-exist))")
	settings := config.NewSettingType(false)

	_, err := AuthenticateAccess("johndoe", "dogood", settings)
	if err == nil {
		t.Fatal("expected search with no entries to fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestAuthenticateAccessRequiredGroupMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
	defer cleanup()

	applyLDAPSettings(t, ldapURL)
	t.Setenv(config.LDAP_REQUIRED_GROUPS, "some-other-group, team10_r")
	settings := config.NewSettingType(false)

	user, err := AuthenticateAccess("johndoe", "dogood", settings)
	if err != nil {
		t.Fatalf("AuthenticateAccess(): %v", err)
	}
	if user == nil || user.Name != "johndoe" {
		t.Fatalf("expected johndoe user, got %#v", user)
	}
}

func TestAuthenticateAccessRequiredGroupNotMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
	defer cleanup()

	applyLDAPSettings(t, ldapURL)
	t.Setenv(config.LDAP_REQUIRED_GROUPS, "svcaccts")
	settings := config.NewSettingType(false)

	_, err := AuthenticateAccess("johndoe", "dogood", settings)
	if err == nil {
		t.Fatal("expected authentication to fail for user outside required groups")
	}
	if !strings.Contains(err.Error(), "not a member of any required group") {
		t.Fatalf("expected group membership error, got %v", err)
	}
}

func applyLDAPSettings(t *testing.T, ldapURL string) {
	t.Helper()
	t.Setenv(config.LDAP_URL, ldapURL)
	t.Setenv(config.LDAP_SKIP_TLS_VERIFY, "true")
	t.Setenv(config.LDAP_STARTTLS, "false")
	t.Setenv(config.LDAP_USER_DOMAIN, "@example.com")
}

func startGlauth(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()

	cfg := pathRelative(t, "..", "..", "testldap", "default-config.cfg")
	cert := pathRelative(t, "..", "..", "testldap", "cert.pem")
	key := pathRelative(t, "..", "..", "testldap", "key.pem")

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
		WaitingFor: wait.ForLog("LDAPS server listening").
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
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
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}

	return fmt.Sprintf("ldaps://%s:%s", host, port.Port()), func() {
		_ = container.Terminate(context.Background())
	}
}

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()

	p := filepath.Join(elems...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}
