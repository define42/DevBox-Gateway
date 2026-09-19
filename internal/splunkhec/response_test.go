package splunkhec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPostRequiresHECSuccess(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "success", body: `{"text":"Success","code":0}`, want: true},
		{name: "additional fields", body: `{"code":0,"text":"Success","ackId":42}`, want: true},
		{name: "empty"},
		{name: "html", body: `<html>Please sign in</html>`},
		{name: "malformed", body: `{"code":0`},
		{name: "missing code", body: `{"text":"Success"}`},
		{name: "null code", body: `{"code":null}`},
		{name: "string code", body: `{"code":"0"}`},
		{name: "nonzero code", body: `{"text":"Invalid data format","code":6}`},
		{name: "unknown code", body: `{"code":999}`},
		{name: "multiple documents", body: `{"code":0}{"code":6}`},
		{name: "oversized", body: `{"code":0,"padding":"` + strings.Repeat("x", successBodyLimit) + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			client, err := New(Config{Endpoint: server.URL, Token: "token"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			err = client.Post(context.Background(), []byte(`{"event":{"message":"evidence"}}`))
			if (err == nil) != test.want {
				t.Fatalf("Post() = %v, want success=%t", err, test.want)
			}
			if IsRejected(err) || IsInvalidEvent(err) {
				t.Fatalf("unconfirmed acceptance must remain retryable: %v", err)
			}
		})
	}
}

func TestPostRejectsRedirectsWithoutFollowingThem(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var redirected atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				redirected.Add(1)
				_, _ = io.WriteString(w, `{"code":0}`)
			}))
			t.Cleanup(target.Close)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, status)
			}))
			t.Cleanup(server.Close)
			client, err := New(Config{Endpoint: server.URL, Token: "token"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			if err := client.Post(context.Background(), []byte(`{"event":{}}`)); err == nil || IsRejected(err) {
				t.Fatalf("Post() = %v, want retryable redirect error", err)
			}
			if got := redirected.Load(); got != 0 {
				t.Fatalf("redirect target received %d requests, want none", got)
			}
		})
	}
}

func TestPostRetriesIncompleteSuccessResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, `{"code":0}`)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{Endpoint: server.URL, Token: "token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	if err := client.Post(context.Background(), []byte(`{"event":{}}`)); err == nil || IsRejected(err) {
		t.Fatalf("Post() = %v, want retryable incomplete-response error", err)
	}
}
