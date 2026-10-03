package rdp

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tomatome/grdp/protocol/x224"
)

func TestParseClientConnectionRequestCapturedClients(t *testing.T) {
	// Captured by opening a .rdp file with loadbalanceinfo in FreeRDP 3.32.0
	// and Remmina 1.4.43 against a loopback listener.
	const prefix = "0300003530e0000000000030313233343536373839616263646566303132333435363738396162636465660d0a01000800"
	tests := []struct {
		name      string
		suffix    string
		protocols uint32
	}{
		{name: "FreeRDP", suffix: "01000000", protocols: x224.PROTOCOL_SSL},
		{name: "Remmina", suffix: "0b000000", protocols: x224.PROTOCOL_SSL | x224.PROTOCOL_HYBRID | x224.PROTOCOL_HYBRID_EX},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := hex.DecodeString(prefix + tt.suffix)
			if err != nil {
				t.Fatal(err)
			}
			request, err := parseClientConnectionRequest(packet)
			if err != nil {
				t.Fatal(err)
			}
			if request.routingToken != "0123456789abcdef0123456789abcdef" || request.requestedProtocols != tt.protocols {
				t.Fatalf("unexpected request: %+v", request)
			}
		})
	}
}

func requestWithPrefix(prefix string, correlation bool) []byte {
	payload := []byte{0, 0xe0, 0, 0, 0, 0, 0}
	payload = append(payload, prefix...)
	flags := byte(0)
	if correlation {
		flags = 0x08
	}
	payload = append(payload, 0x01, flags, 0x08, 0, 0x01, 0, 0, 0)
	if correlation {
		payload = append(payload, 0x06, 0, 36, 0)
		payload = append(payload, make([]byte, 32)...)
	}
	payload[0] = byte(len(payload) - 1)
	return wrapTPKT(payload)
}

func TestParseClientConnectionRequestLegacyAndCorrelation(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		correlation bool
		wantToken   string
	}{
		{name: "no token"},
		{name: "username cookie", prefix: "Cookie: mstshash=alice\r\n"},
		{name: "ANSI username cookie", prefix: "Cookie: mstshash=Andr\xe9\r\n"},
		{name: "token with correlation", prefix: strings.Repeat("a", 32) + "\r\n", correlation: true, wantToken: strings.Repeat("a", 32)},
		{name: "cookie with correlation", prefix: "Cookie: mstshash=alice\r\n", correlation: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := parseClientConnectionRequest(requestWithPrefix(tt.prefix, tt.correlation))
			if err != nil {
				t.Fatal(err)
			}
			if request.routingToken != tt.wantToken || request.requestedProtocols != x224.PROTOCOL_SSL {
				t.Fatalf("unexpected request: %+v", request)
			}
		})
	}
}

func TestParseClientConnectionRequestRejectsMalformedPrefix(t *testing.T) {
	for name, prefix := range map[string]string{
		"empty token":          "\r\n",
		"missing CRLF":         strings.Repeat("a", 32),
		"short token":          "deadbeef\r\n",
		"long token":           strings.Repeat("a", 33) + "\r\n",
		"uppercase token":      strings.Repeat("A", 32) + "\r\n",
		"invalid hex":          strings.Repeat("z", 32) + "\r\n",
		"multiple tokens":      strings.Repeat("a", 32) + "\r\n" + strings.Repeat("b", 32) + "\r\n",
		"token and cookie":     strings.Repeat("a", 32) + "\r\nCookie: mstshash=alice\r\n",
		"cookie and token":     "Cookie: mstshash=alice\r\n" + strings.Repeat("a", 32) + "\r\n",
		"control in cookie":    "Cookie: mstshash=ali\x00ce\r\n",
		"delete in cookie":     "Cookie: mstshash=ali\x7fce\r\n",
		"negotiation in token": "text\x01\x00\x08\x00\x01\x00\x00\x00\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseClientConnectionRequest(requestWithPrefix(prefix, false)); err == nil {
				t.Fatal("malformed request accepted")
			}
		})
	}
}

func TestParseClientConnectionRequestRejectsMalformedHeaders(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		value  byte
	}{
		{name: "TPKT version", offset: 0, value: 4},
		{name: "TPKT reserved", offset: 1, value: 1},
		{name: "TPKT length", offset: 3, value: 18},
		{name: "X224 length", offset: 4, value: 13},
		{name: "X224 type", offset: 5, value: 0xd0},
		{name: "X224 class", offset: 10, value: 1},
		{name: "negotiation type", offset: 11, value: 2},
		{name: "negotiation length", offset: 13, value: 9},
		{name: "missing correlation", offset: 12, value: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := requestWithPrefix("", false)
			packet[tt.offset] = tt.value
			if _, err := parseClientConnectionRequest(packet); err == nil {
				t.Fatal("malformed header accepted")
			}
		})
	}
}

func TestParseClientConnectionRequestRejectsMalformedCorrelation(t *testing.T) {
	for name, offset := range map[string]int{"missing flag": 12, "type": 19, "flags": 20, "length": 21} {
		t.Run(name, func(t *testing.T) {
			packet := requestWithPrefix("", true)
			packet[offset] ^= 0x08
			if _, err := parseClientConnectionRequest(packet); err == nil {
				t.Fatal("malformed correlation info accepted")
			}
		})
	}
}

func TestParseClientConnectionRequestRejectsTruncation(t *testing.T) {
	packet := requestWithPrefix(strings.Repeat("a", 32)+"\r\n", true)
	for n := range len(packet) {
		if _, err := parseClientConnectionRequest(packet[:n]); err == nil {
			t.Fatalf("accepted truncated request of length %d", n)
		}
	}
	if _, err := parseClientConnectionRequest(wrapTPKT([]byte{6, 0xe0, 0, 0, 0, 0, 0})); err == nil {
		t.Fatal("accepted request without negotiation")
	}
}

func FuzzParseClientConnectionRequest(f *testing.F) {
	f.Add(requestWithPrefix("", false))
	f.Add(requestWithPrefix("Cookie: mstshash=alice\r\n", false))
	f.Add(requestWithPrefix(strings.Repeat("a", 32)+"\r\n", true))
	f.Fuzz(func(t *testing.T, packet []byte) {
		request, err := parseClientConnectionRequest(packet)
		if err == nil && request == nil {
			t.Fatal("successful parse returned nil")
		}
	})
}
