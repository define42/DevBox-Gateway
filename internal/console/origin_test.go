package console

import (
	"net/http"
	"testing"
)

func TestSameOriginWebsocketRequest(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{name: "empty origin", host: "example.test", origin: "", want: true},
		{name: "same origin", host: "example.test", origin: "https://example.test", want: true},
		{name: "different origin", host: "example.test", origin: "https://other.test", want: false},
		{name: "invalid origin", host: "example.test", origin: "://bad-origin", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://"+tc.host+"/api/dashboard/console", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			if got := sameOriginWebsocketRequest(req); got != tc.want {
				t.Fatalf("sameOriginWebsocketRequest() = %v, want %v", got, tc.want)
			}
		})
	}
}
