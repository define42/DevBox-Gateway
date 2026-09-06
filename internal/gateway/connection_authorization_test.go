package gateway

import (
	"testing"

	"github.com/define42/devbox-gateway/internal/session"
)

func testConnectionAuthorization(t *testing.T, manager *session.Manager, username string) session.ConnectionAuthorization {
	t.Helper()
	cookie := issueSessionCookie(t, manager, username)
	ctx, err := manager.Load(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("load connection session: %v", err)
	}
	authorization, ok := manager.AuthorizeConnection(ctx)
	if !ok {
		t.Fatal("expected stored session to authorize a connection")
	}
	return authorization
}
