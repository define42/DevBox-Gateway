package gateway

import (
	"net/http"

	"github.com/define42/devbox-gateway/internal/dashboard"
	"github.com/gorilla/websocket"
)

// auditAdmissionMiddleware refuses new mutations and upgraded streams before
// session/login middleware or handlers perform work. Rejections deliberately
// avoid the saturated audit destination. Logout remains available for session
// revocation, and ordinary reads and probes remain available for recovery.
func auditAdmissionMiddleware(check func() error) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if check == nil || !requiresAuditAdmission(r) || check() == nil {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Retry-After", "5")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Connection", "close")
			dashboard.WriteJSON(w, http.StatusServiceUnavailable, dashboard.ActionResponse{
				OK:    false,
				Error: "The gateway cannot safely record new activity right now. Try again shortly.",
			})
		})
	}
}

func requiresAuditAdmission(r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == "/logout" {
		return false
	}
	if websocket.IsWebSocketUpgrade(r) {
		return true
	}
	return r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
}
