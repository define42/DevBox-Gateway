// Package splunkhec posts JSON events to a Splunk HTTP Event Collector. It
// owns the wire format, authentication, and the classification of collector
// responses; queueing and retry policy belong to the callers, which differ in
// what a failed delivery may cost.
package splunkhec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config selects a collector and how events are addressed to it.
type Config struct {
	// Endpoint is the collector URL. A URL without a path, such as
	// https://splunk.example.com:8088, is completed with the JSON event
	// endpoint /services/collector/event.
	Endpoint string
	// Token is the HEC token, sent as "Authorization: Splunk <token>".
	Token string
	// Index is the destination index; empty uses the token's default index.
	Index string
	// InsecureSkipVerify disables verification of the collector's TLS certificate.
	InsecureSkipVerify bool
	// ACKEnabled requires indexer acknowledgement before Post reports success.
	// Enable it only for a HEC token configured to return acknowledgement IDs.
	ACKEnabled bool
}

const (
	// EventPath is the JSON event endpoint used when Config.Endpoint has no path.
	EventPath = "/services/collector/event"

	requestTimeout   = 10 * time.Second
	errorBodyLimit   = 512
	successBodyLimit = 64 << 10
)

// Envelope is the HEC JSON event format. Several marshaled envelopes
// concatenated into one request body form a batch.
type Envelope struct {
	Time       json.Number     `json:"time"`
	Host       string          `json:"host,omitempty"`
	Source     string          `json:"source"`
	Sourcetype string          `json:"sourcetype"`
	Index      string          `json:"index,omitempty"`
	Event      json.RawMessage `json:"event"`
}

// Client posts request bodies to one collector.
type Client struct {
	endpoint        *url.URL
	authorization   string
	index           string
	http            *http.Client
	channel         string
	ackEndpoint     *url.URL
	ackPollInterval time.Duration
	ackTimeout      time.Duration
}

// New validates config and builds a client for it.
func New(config Config) (*Client, error) {
	endpoint, err := EventURL(config.Endpoint)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(config.Token)
	if token == "" {
		return nil, fmt.Errorf("splunk hec token is empty")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- InsecureSkipVerify is an explicit operator opt-in via a *_SKIP_TLS_VERIFY setting (default off).
		InsecureSkipVerify: config.InsecureSkipVerify,
	}
	client := &Client{
		endpoint:      endpoint,
		authorization: "Splunk " + token,
		index:         strings.TrimSpace(config.Index),
		http: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// A redirect can discard the POST body or send evidence and the
			// token to a different endpoint. Only the configured HEC may reply.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if config.ACKEnabled {
		if err := client.enableACK(); err != nil {
			client.CloseIdleConnections()
			return nil, err
		}
	}
	return client, nil
}

// EventURL resolves a configured endpoint to the JSON event endpoint URL.
func EventURL(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("parse splunk hec endpoint: %w", err)
	}
	if (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, fmt.Errorf("splunk hec endpoint %q must be an absolute http or https url", parsed.Redacted())
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = EventPath
	}
	return parsed, nil
}

// Endpoint returns the resolved event URL with any userinfo password
// redacted, for logs.
func (c *Client) Endpoint() string { return c.endpoint.Redacted() }

// PlainHTTP reports whether the token and events travel unencrypted.
func (c *Client) PlainHTTP() bool { return c.endpoint.Scheme == "http" }

// Index is the configured destination index; empty means the token's default.
func (c *Client) Index() string { return c.index }

// Post sends one request body of concatenated envelopes. With ACKEnabled it
// also polls until Splunk confirms that batch, or cancellation/the ACK deadline
// leaves delivery unconfirmed. Callers must retain unconfirmed records.
func (c *Client) Post(ctx context.Context, body []byte) error {
	reply, err := c.post(ctx, c.endpoint, body)
	if err != nil {
		return err
	}
	if code := replyCode(reply); code != 0 {
		return fmt.Errorf("splunk hec did not confirm acceptance with code 0 (reply code %d)", code)
	}
	if c.channel == "" {
		return nil
	}
	id, err := acknowledgementID(reply)
	if err != nil {
		return err
	}
	return c.waitACK(ctx, id)
}

func (c *Client) post(ctx context.Context, endpoint *url.URL, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build splunk hec request: %w", err)
	}
	request.Header.Set("Authorization", c.authorization)
	request.Header.Set("Content-Type", "application/json")
	if c.channel != "" {
		request.Header.Set("X-Splunk-Request-Channel", c.channel)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("post to splunk hec: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return readReply(response.Body)
	}

	detail, _ := io.ReadAll(io.LimitReader(response.Body, errorBodyLimit))
	statusErr := fmt.Errorf("splunk hec responded %s: %s", response.Status, strings.TrimSpace(string(detail)))
	if retryableStatus(response.StatusCode) {
		return nil, statusErr
	}
	return nil, &rejectedError{err: statusErr, status: response.StatusCode, code: replyCode(detail)}
}

// readReply bounds both ingestion and ACK replies. A truncated or oversized
// response cannot establish acceptance or acknowledgement.
func readReply(body io.Reader) ([]byte, error) {
	reply, err := io.ReadAll(io.LimitReader(body, successBodyLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read splunk hec response: %w", err)
	}
	if len(reply) > successBodyLimit {
		return nil, fmt.Errorf("splunk hec response exceeds %d bytes", successBodyLimit)
	}
	return reply, nil
}

// replyCode extracts the HEC status code from a collector reply such as
// {"text":"Incorrect index","code":7}, or returns -1.
func replyCode(body []byte) int {
	var reply struct {
		Code *int `json:"code"`
	}
	if err := json.Unmarshal(body, &reply); err != nil || reply.Code == nil {
		return -1
	}
	return *reply.Code
}

// CloseIdleConnections releases pooled connections to the collector.
func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

// Time formats t as the epoch seconds, with millisecond precision, that HEC
// expects in an event's time field.
func Time(t time.Time) json.Number {
	return json.Number(fmt.Sprintf("%d.%03d", t.Unix(), t.Nanosecond()/int(time.Millisecond)))
}

// rejectedError marks a collector response that retrying cannot fix.
type rejectedError struct {
	err    error
	status int // HTTP status
	code   int // HEC reply code, or -1 when the reply carried none
}

func (e *rejectedError) Error() string { return e.err.Error() }

func (e *rejectedError) Unwrap() error { return e.err }

// IsRejected reports whether err is a collector response that retrying the
// same request cannot fix.
func IsRejected(err error) bool {
	var rejected *rejectedError
	return errors.As(err, &rejected)
}

// HEC reply codes that blame the event data itself rather than the token,
// index, or collector: invalid data format, event field required, event field
// blank, and error in handling indexed fields.
const (
	codeInvalidDataFormat   = 6
	codeEventFieldRequired  = 12
	codeEventFieldBlank     = 13
	codeIndexedFieldsFailed = 15
)

// IsInvalidEvent reports whether err is the collector refusing the request's
// events themselves -- malformed, or too large to accept -- so that sending
// the same events again can never succeed while other events would. Any other
// refusal (an index the token may not write to, a missing channel, a reply
// without a recognizable code) is about the configuration and says nothing
// about the events.
func IsInvalidEvent(err error) bool {
	var rejected *rejectedError
	if !errors.As(err, &rejected) {
		return false
	}
	if rejected.status == http.StatusRequestEntityTooLarge {
		return true
	}
	switch rejected.code {
	case codeInvalidDataFormat, codeEventFieldRequired, codeEventFieldBlank, codeIndexedFieldsFailed:
		return rejected.status == http.StatusBadRequest
	default:
		return false
	}
}

// retryableStatus reports whether a failed request may succeed later without
// a configuration change on the sender's side. Besides throttling and server
// errors this covers authentication failures, because a disabled token can be
// re-enabled on the Splunk side. Redirects leave acceptance unknown and must
// retain the events too. Other client errors (bad request, incorrect index,
// wrong path) reject the request itself.
func retryableStatus(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	default:
		return (status >= http.StatusMultipleChoices && status < http.StatusBadRequest) ||
			status >= http.StatusInternalServerError
	}
}
