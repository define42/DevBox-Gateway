package splunkhec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newACKTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	client, err := New(Config{Endpoint: endpoint, Token: "hec-token", ACKEnabled: true})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	client.ackPollInterval = time.Millisecond
	client.ackTimeout = time.Second
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func newACKTestServer(t *testing.T, eventReply string, acknowledge http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EventPath:
			_, _ = io.WriteString(w, eventReply)
		case "/services/collector/ack":
			acknowledge(w, r)
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func requireRetryableACKError(t *testing.T, err error) {
	t.Helper()
	if err == nil || IsRejected(err) || IsInvalidEvent(err) {
		t.Fatalf("Post() = %v, want an error that retains events for retry", err)
	}
}

func TestPostWithoutACKDoesNotPoll(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/custom-ingestion" || r.URL.Query().Get("channel") != "legacy" {
			t.Errorf("ACK-disabled request URL = %s, want original custom endpoint", r.URL)
		}
		if channel := r.Header.Get("X-Splunk-Request-Channel"); channel != "" {
			t.Errorf("ACK-disabled request channel = %q, want empty", channel)
		}
		_, _ = io.WriteString(w, `{"code":0,"ackId":42}`)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{Endpoint: server.URL + "/custom-ingestion?channel=legacy", Token: "token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	if err := client.Post(t.Context(), []byte(`{"event":{}}`)); err != nil {
		t.Fatalf("Post() = %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("request count = %d, want one ingestion and no ACK poll", got)
	}
}

func TestACKRejectsUnrelatedCustomEndpoint(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/custom", "/services/collector/ack", "/services/collector/events"} {
		t.Run(path, func(t *testing.T) {
			_, err := New(Config{Endpoint: "https://splunk.example.test" + path, Token: "token", ACKEnabled: true})
			if err == nil {
				t.Fatal("New() = nil, want an error for an unknown acknowledgement route")
			}
		})
	}
}

func TestACKEndpointPaths(t *testing.T) {
	t.Parallel()
	paths := []string{
		"/services/collector", "/services/collector/", "/services/collector/event",
		"/services/collector/event/", "/services/collector/event/1.0",
		"/services/collector/raw", "/services/collector/raw/", "/services/collector/raw/1.0",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			var ingestions, polls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/proxy" + path:
					ingestions.Add(1)
					_, _ = io.WriteString(w, `{"code":0,"ackId":42}`)
				case "/proxy/services/collector/ack":
					polls.Add(1)
					_, _ = io.WriteString(w, `{"acks":{"42":true}}`)
				default:
					t.Errorf("unexpected request path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			client := newACKTestClient(t, server.URL+"/proxy"+path)
			if err := client.Post(t.Context(), []byte(`{"event":{}}`)); err != nil {
				t.Fatalf("Post() = %v", err)
			}
			if ingestions.Load() != 1 || polls.Load() != 1 {
				t.Fatalf("requests = %d ingestions, %d polls; want one each", ingestions.Load(), polls.Load())
			}
		})
	}
}

func TestACKAcceptsExactIntegerIDs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		json string
		id   int64
	}{
		{name: "zero", json: "0"},
		{name: "string zero", json: `"0"`},
		{name: "integer", json: "42", id: 42},
		{name: "string integer", json: `"42"`, id: 42},
		{name: "maximum integer", json: "9223372036854775807", id: 9223372036854775807},
		{name: "maximum string integer", json: `"9223372036854775807"`, id: 9223372036854775807},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newACKTestServer(t, `{"code":0,"ackId":`+test.json+`}`, func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					ACKs []int64 `json:"acks"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode ACK request: %v", err)
				}
				if len(body.ACKs) != 1 || body.ACKs[0] != test.id {
					t.Errorf("ACK request ids = %v, want [%d]", body.ACKs, test.id)
				}
				_, _ = fmt.Fprintf(w, `{"acks":{"%d":true}}`, test.id)
			})
			client := newACKTestClient(t, server.URL)
			if err := client.Post(t.Context(), []byte(`{"event":{}}`)); err != nil {
				t.Fatalf("Post() = %v", err)
			}
		})
	}
}

func TestACKRequiresValidIngestionReceipt(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, body string }{
		{name: "missing", body: `{"code":0}`},
		{name: "null", body: `{"code":0,"ackId":null}`},
		{name: "negative", body: `{"code":0,"ackId":-1}`},
		{name: "fractional", body: `{"code":0,"ackId":1.5}`},
		{name: "overflow", body: `{"code":0,"ackId":9223372036854775808}`},
		{name: "negative string", body: `{"code":0,"ackId":"-1"}`},
		{name: "fractional string", body: `{"code":0,"ackId":"1.5"}`},
		{name: "overflow string", body: `{"code":0,"ackId":"9223372036854775808"}`},
		{name: "empty string", body: `{"code":0,"ackId":""}`},
		{name: "boolean", body: `{"code":0,"ackId":true}`},
		{name: "array", body: `{"code":0,"ackId":[42]}`},
		{name: "nonzero code", body: `{"code":6,"ackId":42}`},
		{name: "missing code", body: `{"ackId":42}`},
		{name: "null code", body: `{"code":null,"ackId":42}`},
		{name: "multiple documents", body: `{"code":0,"ackId":42}{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var polls atomic.Int64
			server := newACKTestServer(t, test.body, func(w http.ResponseWriter, _ *http.Request) {
				polls.Add(1)
				_, _ = io.WriteString(w, `{"acks":{"42":true}}`)
			})
			client := newACKTestClient(t, server.URL)
			requireRetryableACKError(t, client.Post(t.Context(), []byte(`{"event":{}}`)))
			if got := polls.Load(); got != 0 {
				t.Fatalf("polled %d times without a valid ingestion receipt", got)
			}
		})
	}
}

func TestACKRequiresExplicitTrueForMatchingID(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, body string }{
		{name: "pending", body: `{"acks":{"42":false}}`},
		{name: "other ID", body: `{"acks":{"41":true}}`},
		{name: "pending and other ID", body: `{"acks":{"42":false,"41":true}}`},
		{name: "missing ID", body: `{"acks":{}}`},
		{name: "missing acks", body: `{"code":0}`},
		{name: "null", body: `{"acks":{"42":null}}`},
		{name: "string true", body: `{"acks":{"42":"true"}}`},
		{name: "numeric true", body: `{"acks":{"42":1}}`},
		{name: "malformed", body: `{"acks":{"42":true}`},
		{name: "multiple documents", body: `{"acks":{"42":true}}{}`},
		{name: "oversized", body: `{"acks":{"42":true},"padding":"` + strings.Repeat("x", successBodyLimit) + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var polls atomic.Int64
			server := newACKTestServer(t, `{"code":0,"ackId":42}`, func(w http.ResponseWriter, _ *http.Request) {
				polls.Add(1)
				_, _ = io.WriteString(w, test.body)
			})
			client := newACKTestClient(t, server.URL)
			client.ackTimeout = 30 * time.Millisecond
			err := client.Post(t.Context(), []byte(`{"event":{}}`))
			requireRetryableACKError(t, err)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Post() = %v, want acknowledgement deadline exceeded", err)
			}
			if polls.Load() == 0 {
				t.Fatal("Post() did not poll for its acknowledgement")
			}
		})
	}
}

func TestACKRetriesPollingWithoutResubmittingEvents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "pending", status: 200, body: `{"acks":{"42":false}}`},
		{name: "malformed", status: 200, body: `<html>proxy error</html>`},
		{name: "bad request", status: 400, body: `{"code":6}`},
		{name: "unauthorized", status: 401, body: `{"code":4}`},
		{name: "forbidden", status: 403, body: `{"code":4}`},
		{name: "too large", status: 413, body: `request too large`},
		{name: "throttled", status: 429, body: `{"code":9}`},
		{name: "unavailable", status: 503, body: `{"code":9}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkACKPollingRetry(t, test.status, test.body)
		})
	}
}

func checkACKPollingRetry(t *testing.T, status int, body string) {
	t.Helper()
	var ingestions, polls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == EventPath {
			ingestions.Add(1)
			_, _ = io.WriteString(w, `{"code":0,"ackId":42}`)
			return
		}
		if polls.Add(1) == 1 {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
			return
		}
		_, _ = io.WriteString(w, `{"acks":{"42":true}}`)
	}))
	t.Cleanup(server.Close)
	client := newACKTestClient(t, server.URL)
	if err := client.Post(t.Context(), []byte(`{"event":{}}`)); err != nil {
		t.Fatalf("Post() = %v", err)
	}
	if ingestions.Load() != 1 || polls.Load() != 2 {
		t.Errorf("requests = %d ingestions, %d polls; want 1 and 2", ingestions.Load(), polls.Load())
	}
}

func TestACKPollingRefusalsRemainRetryable(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := newACKTestServer(t, `{"code":0,"ackId":42}`, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"code":6,"text":"invalid data"}`)
			})
			client := newACKTestClient(t, server.URL)
			client.ackTimeout = 30 * time.Millisecond
			err := client.Post(t.Context(), []byte(`{"event":{}}`))
			requireRetryableACKError(t, err)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Post() = %v, want acknowledgement deadline exceeded", err)
			}
		})
	}
}

func TestACKCancellationInterruptsPolling(t *testing.T) {
	t.Parallel()
	for _, inFlight := range []bool{false, true} {
		t.Run(fmt.Sprintf("in flight %t", inFlight), func(t *testing.T) {
			polled := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			server := newACKTestServer(t, `{"code":0,"ackId":42}`, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(polled)
				if inFlight {
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				_, _ = io.WriteString(w, `{"acks":{"42":false}}`)
			})
			client := newACKTestClient(t, server.URL)
			client.ackTimeout = time.Hour
			client.ackPollInterval = time.Hour
			checkACKCancellation(t, client, polled)
		})
	}
}

func checkACKCancellation(t *testing.T, client *Client, polled <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- client.Post(ctx, []byte(`{"event":{}}`)) }()
	select {
	case <-polled:
	case <-time.After(time.Second):
		t.Fatal("Post() never began polling")
	}
	cancel()
	select {
	case err := <-result:
		requireRetryableACKError(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Post() = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Post() did not stop after context cancellation")
	}
}

func TestACKUsesStableIsolatedRequestChannels(t *testing.T) {
	t.Parallel()
	channels := make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		channels <- r.Header.Get("X-Splunk-Request-Channel")
		checkACKRequest(t, r)
		if r.URL.Path == EventPath {
			_, _ = io.WriteString(w, `{"code":0,"ackId":42}`)
		} else {
			_, _ = io.WriteString(w, `{"acks":{"42":true}}`)
		}
	}))
	t.Cleanup(server.Close)
	endpoint := server.URL + "?tenant=one&channel=user-selected&channel=other"
	first, second := newACKTestClient(t, endpoint), newACKTestClient(t, endpoint)
	var previous string
	for _, client := range []*Client{first, second} {
		for range 2 {
			if err := client.Post(t.Context(), []byte(`{"event":{}}`)); err != nil {
				t.Fatalf("Post() = %v", err)
			}
		}
		previous = checkACKChannel(t, channels, previous)
	}
}

func checkACKRequest(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Splunk hec-token" {
		t.Errorf("request method/auth = %s/%q", r.Method, r.Header.Get("Authorization"))
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content type = %q", r.Header.Get("Content-Type"))
	}
	if query := r.URL.Query(); query.Has("channel") || query.Get("tenant") != "one" {
		t.Errorf("request query = %s, want tenant=one without a user channel", r.URL.RawQuery)
	}
}

func checkACKChannel(t *testing.T, channels <-chan string, previous string) string {
	t.Helper()
	channel := <-channels
	id, err := uuid.Parse(channel)
	if err != nil || id == uuid.Nil || len(channel) != 36 || channel == previous {
		t.Fatalf("channel = %q, want a distinct nonzero GUID; previous = %q", channel, previous)
	}
	for range 3 {
		if got := <-channels; got != channel {
			t.Fatalf("channel changed between requests: %q != %q", got, channel)
		}
	}
	return channel
}

func TestACKPreservesLoadBalancerAffinityCookie(t *testing.T) {
	t.Parallel()
	var polls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == EventPath {
			http.SetCookie(w, &http.Cookie{Name: "backend", Value: "indexer-one", Path: "/"})
			_, _ = io.WriteString(w, `{"code":0,"ackId":42}`)
			return
		}
		polls.Add(1)
		cookie, err := r.Cookie("backend")
		if err != nil || cookie.Value != "indexer-one" {
			t.Errorf("ACK affinity cookie = %v, error = %v", cookie, err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"acks":{"42":true}}`)
	}))
	t.Cleanup(server.Close)
	client := newACKTestClient(t, server.URL)
	if err := client.Post(t.Context(), []byte(`{"event":{}}`)); err != nil {
		t.Fatalf("Post() = %v", err)
	}
	if got := polls.Load(); got != 1 {
		t.Fatalf("ACK polls = %d, want one", got)
	}
}

func TestACKDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var redirected atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				redirected.Add(1)
				_, _ = io.WriteString(w, `{"acks":{"42":true}}`)
			}))
			t.Cleanup(target.Close)
			server := newACKTestServer(t, `{"code":0,"ackId":42}`, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, status)
			})
			client := newACKTestClient(t, server.URL)
			client.ackTimeout = 30 * time.Millisecond
			requireRetryableACKError(t, client.Post(t.Context(), []byte(`{"event":{}}`)))
			if got := redirected.Load(); got != 0 {
				t.Fatalf("redirect target received %d requests, want none", got)
			}
		})
	}
}
