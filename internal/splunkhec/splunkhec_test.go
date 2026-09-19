package splunkhec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
		wantErr  bool
	}{
		{name: "host only gets event path", endpoint: "https://splunk.example.test:8088", want: "https://splunk.example.test:8088/services/collector/event"},
		{name: "root path gets event path", endpoint: " https://splunk.example.test:8088/ ", want: "https://splunk.example.test:8088/services/collector/event"},
		{name: "explicit path is kept", endpoint: "https://splunk.example.test/services/collector/event/1.0", want: "https://splunk.example.test/services/collector/event/1.0"},
		{name: "query is kept", endpoint: "https://splunk.example.test:8088?channel=abc", want: "https://splunk.example.test:8088/services/collector/event?channel=abc"},
		{name: "plain http is allowed", endpoint: "HTTP://splunk.example.test:8088", want: "http://splunk.example.test:8088/services/collector/event"},
		{name: "other scheme", endpoint: "ftp://splunk.example.test", wantErr: true},
		{name: "missing scheme", endpoint: "splunk.example.test:8088", wantErr: true},
		{name: "missing host", endpoint: "https:///services/collector", wantErr: true},
		{name: "unparsable", endpoint: "https://splunk example.test", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := EventURL(test.endpoint)
			if test.wantErr {
				if err == nil {
					t.Fatalf("EventURL(%q) = %v, want error", test.endpoint, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("EventURL(%q) error = %v", test.endpoint, err)
			}
			if got.String() != test.want {
				t.Fatalf("EventURL(%q) = %q, want %q", test.endpoint, got, test.want)
			}
		})
	}
}

func TestRetryableStatus(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{status: http.StatusMovedPermanently, want: true},
		{status: http.StatusFound, want: true},
		{status: http.StatusTemporaryRedirect, want: true},
		{status: http.StatusBadRequest, want: false},
		{status: http.StatusUnauthorized, want: true},
		{status: http.StatusForbidden, want: true},
		{status: http.StatusNotFound, want: false},
		{status: http.StatusRequestTimeout, want: true},
		{status: http.StatusRequestEntityTooLarge, want: false},
		{status: http.StatusTooManyRequests, want: true},
		{status: http.StatusInternalServerError, want: true},
		{status: http.StatusServiceUnavailable, want: true},
	}
	for _, test := range tests {
		if got := retryableStatus(test.status); got != test.want {
			t.Errorf("retryableStatus(%d) = %t, want %t", test.status, got, test.want)
		}
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{name: "empty token", config: Config{Endpoint: "https://splunk.example.test", Token: " "}},
		{name: "bad endpoint", config: Config{Endpoint: "splunk.example.test", Token: "token"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.config); err == nil {
				t.Fatal("New() error = nil, want non-nil")
			}
		})
	}
}

func TestClientAccessors(t *testing.T) {
	client, err := New(Config{Endpoint: "http://user:secret@splunk.example.test:8088", Token: " token ", Index: " sauron "})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !client.PlainHTTP() {
		t.Error("PlainHTTP() = false for an http endpoint")
	}
	if got := client.Index(); got != "sauron" {
		t.Errorf("Index() = %q, want the trimmed index", got)
	}
	if got := client.Endpoint(); strings.Contains(got, "secret") || !strings.HasSuffix(got, EventPath) {
		t.Errorf("Endpoint() = %q, want the redacted event URL", got)
	}
}

func TestPostSendsAuthenticatedJSON(t *testing.T) {
	type seen struct{ path, authorization, contentType, body string }
	requests := make(chan seen, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- seen{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(body)}
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	t.Cleanup(server.Close)

	client, err := New(Config{Endpoint: server.URL, Token: "hec-token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := client.Post(context.Background(), []byte(`{"event":{}}`)); err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	got := <-requests
	want := seen{EventPath, "Splunk hec-token", "application/json", `{"event":{}}`}
	if got != want {
		t.Errorf("request = %+v, want %+v", got, want)
	}
}

func TestPostClassifiesFailures(t *testing.T) {
	tests := []struct {
		status       int
		wantRejected bool
	}{
		{status: http.StatusBadRequest, wantRejected: true},
		{status: http.StatusServiceUnavailable, wantRejected: false},
		{status: http.StatusForbidden, wantRejected: false},
	}
	for _, test := range tests {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, `{"text":"Incorrect index","code":7}`)
			}))
			t.Cleanup(server.Close)

			client, err := New(Config{Endpoint: server.URL, Token: "hec-token"})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			err = client.Post(context.Background(), []byte(`{}`))
			if err == nil {
				t.Fatal("Post() error = nil, want the collector's refusal")
			}
			if got := IsRejected(err); got != test.wantRejected {
				t.Errorf("IsRejected(%v) = %t, want %t", err, got, test.wantRejected)
			}
			if !strings.Contains(err.Error(), "Incorrect index") {
				t.Errorf("error %q does not carry the collector's explanation", err)
			}
		})
	}
}

func TestPostVerifiesTLSByDefault(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	t.Cleanup(server.Close)

	strict, err := New(Config{Endpoint: server.URL, Token: "hec-token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := strict.Post(context.Background(), []byte(`{}`)); err == nil || IsRejected(err) {
		t.Fatalf("Post() to an untrusted certificate = %v, want a retryable TLS error", err)
	}

	lax, err := New(Config{Endpoint: server.URL, Token: "hec-token", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := lax.Post(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("Post() with verification disabled = %v, want nil", err)
	}
	lax.CloseIdleConnections()
}

func TestTime(t *testing.T) {
	got := Time(time.Unix(1789752345, 312_900_000))
	if got != "1789752345.312" {
		t.Errorf("Time() = %q, want epoch seconds with milliseconds", got)
	}
}

func TestIsInvalidEvent(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{name: "invalid data format", status: http.StatusBadRequest, body: `{"text":"Invalid data format","code":6,"invalid-event-number":1}`, want: true},
		{name: "event field required", status: http.StatusBadRequest, body: `{"text":"Event field is required","code":12}`, want: true},
		{name: "event field blank", status: http.StatusBadRequest, body: `{"text":"Event field cannot be blank","code":13}`, want: true},
		{name: "indexed fields", status: http.StatusBadRequest, body: `{"text":"Error in handling indexed fields","code":15}`, want: true},
		{name: "too large", status: http.StatusRequestEntityTooLarge, body: `Content-Length of 9999999 too large (maximum is 1000000)`, want: true},
		{name: "incorrect index", status: http.StatusBadRequest, body: `{"text":"Incorrect index","code":7}`},
		{name: "data channel missing", status: http.StatusBadRequest, body: `{"text":"Data channel is missing","code":10}`},
		{name: "no code", status: http.StatusBadRequest, body: `<html>bad request</html>`},
		{name: "not found", status: http.StatusNotFound, body: `{"text":"The requested URL was not found on this server.","code":404}`},
		{name: "server busy", status: http.StatusServiceUnavailable, body: `{"text":"Server is busy","code":9}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			client, err := New(Config{Endpoint: server.URL, Token: "hec-token"})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			err = client.Post(context.Background(), []byte(`{}`))
			if got := IsInvalidEvent(err); got != test.want {
				t.Errorf("IsInvalidEvent(%v) = %t, want %t", err, got, test.want)
			}
		})
	}
	if IsInvalidEvent(nil) {
		t.Error("IsInvalidEvent(nil) = true")
	}
}
