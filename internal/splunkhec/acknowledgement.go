package splunkhec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	ackPollInterval = time.Second
	ackTimeout      = 5 * time.Minute
)

// enableACK assigns one channel to this client, shared by submissions and
// status queries. A new client gets a fresh channel after process restart.
func (c *Client) enableACK() error {
	endpoint, err := acknowledgementURL(c.endpoint)
	if err != nil {
		return err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("generate splunk hec acknowledgement channel: %w", err)
	}
	// Cookies preserve load-balancer affinity. Requests never follow redirects
	// and only address the configured collector origin.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("create splunk hec acknowledgement cookie jar: %w", err)
	}
	c.http.Jar = jar
	c.channel = id.String()
	c.ackEndpoint = endpoint
	c.ackPollInterval = ackPollInterval
	c.ackTimeout = ackTimeout
	// The generated header is authoritative, even if the configured event URL
	// carried a stale channel query parameter.
	query := c.endpoint.Query()
	query.Del("channel")
	c.endpoint.RawQuery = query.Encode()
	return nil
}

// acknowledgementURL preserves reverse-proxy prefixes, query parameters and
// origin. Unknown custom routes cannot safely imply an ACK route.
func acknowledgementURL(event *url.URL) (*url.URL, error) {
	escaped := strings.TrimRight(event.EscapedPath(), "/")
	for _, suffix := range []string{
		"/services/collector/event/1.0", "/services/collector/raw/1.0",
		"/services/collector/event", "/services/collector/raw", "/services/collector",
	} {
		if !strings.HasSuffix(escaped, suffix) {
			continue
		}
		ack := *event
		ack.RawPath = strings.TrimSuffix(escaped, suffix) + "/services/collector/ack"
		path, err := url.PathUnescape(ack.RawPath)
		if err != nil {
			return nil, fmt.Errorf("resolve splunk hec acknowledgement path: %w", err)
		}
		ack.Path = path
		query := ack.Query()
		query.Del("channel")
		ack.RawQuery = query.Encode()
		return &ack, nil
	}
	return nil, fmt.Errorf("splunk hec acknowledgement requires a standard /services/collector event endpoint, optionally behind a proxy prefix")
}

// acknowledgementID accepts exact nonnegative integers, including zero and
// the quoted integer form shown in Splunk's documentation, without float loss.
func acknowledgementID(body []byte) (int64, error) {
	var reply struct {
		ID json.RawMessage `json:"ackId"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return 0, fmt.Errorf("decode splunk hec acknowledgement id: %w", err)
	}
	raw := bytes.TrimSpace(reply.ID)
	value := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, fmt.Errorf("decode splunk hec acknowledgement id: %w", err)
		}
	}
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("splunk hec did not return a nonnegative integer ackId; check the token's indexer acknowledgement setting")
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse splunk hec acknowledgement id: %w", err)
	}
	return id, nil
}

// waitACK retains the ID while polling, including through transient failures.
// False can also mean an expired/unknown ID, so the bounded deadline eventually
// lets the caller resubmit its retained payload. Resubmission may duplicate it.
func (c *Client) waitACK(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, c.ackTimeout)
	defer cancel()
	ticker := time.NewTicker(c.ackPollInterval)
	defer ticker.Stop()
	var lastErr error
	for {
		confirmed, err := c.queryACK(ctx, id)
		if confirmed {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("splunk hec acknowledgement %d unconfirmed: %w (last status: %s)", id, ctx.Err(), fmt.Sprint(lastErr))
		case <-ticker.C:
		}
	}
}

func (c *Client) queryACK(ctx context.Context, id int64) (bool, error) {
	request := []byte(`{"acks":[` + strconv.FormatInt(id, 10) + `]}`)
	body, err := c.post(ctx, c.ackEndpoint, request)
	if err != nil {
		// A refusal of the status query says nothing about the event's validity.
		// Do not expose rejectedError to a caller that may discard invalid events.
		return false, fmt.Errorf("query splunk hec acknowledgement: %s", err.Error())
	}
	var reply struct {
		Acks map[string]*bool `json:"acks"`
		Code *int             `json:"code"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return false, fmt.Errorf("decode splunk hec acknowledgement status: %w", err)
	}
	if reply.Code != nil && *reply.Code != 0 {
		return false, fmt.Errorf("splunk hec acknowledgement query returned code %d", *reply.Code)
	}
	confirmed := reply.Acks[strconv.FormatInt(id, 10)]
	if confirmed == nil || !*confirmed {
		return false, fmt.Errorf("splunk hec acknowledgement %d is pending or unknown", id)
	}
	return true, nil
}
