package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/tomatome/grdp/protocol/x224"
)

type clientConnectionRequest struct {
	routingToken       string
	requestedProtocols uint32
}

// parseClientConnectionRequest reads the optional routing token/cookie before
// the negotiation structure. Its boundaries come from X.224 and CRLF, so token
// contents cannot be mistaken for a negotiation request.
func parseClientConnectionRequest(packet []byte) (*clientConnectionRequest, error) {
	if len(packet) < 11 || packet[0] != 3 || packet[1] != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return nil, fmt.Errorf("invalid TPKT connection request")
	}
	payload := packet[4:]
	if int(payload[0])+1 != len(payload) || payload[1] != byte(x224.TPDU_CONNECTION_REQUEST) || payload[6] != 0 {
		return nil, fmt.Errorf("invalid X.224 connection request")
	}
	token, negotiation, err := splitClientRoutingToken(payload[7:])
	if err != nil {
		return nil, err
	}
	protocols, err := parseClientNegotiation(negotiation)
	if err != nil {
		return nil, err
	}
	return &clientConnectionRequest{routingToken: token, requestedProtocols: protocols}, nil
}

func splitClientRoutingToken(data []byte) (string, []byte, error) {
	if len(data) == 0 || data[0] == byte(x224.TYPE_RDP_NEG_REQ) {
		return "", data, nil
	}
	end := bytes.Index(data, []byte("\r\n"))
	if end < 0 {
		return "", nil, fmt.Errorf("unterminated RDP routing token or cookie")
	}
	prefix := string(data[:end])
	if strings.HasPrefix(prefix, "Cookie: mstshash=") {
		// Conventional username cookies are not routing tokens. Parse them for
		// negotiation, then let route resolution reject the missing token.
		for _, b := range data[:end] {
			if b < 0x20 || b == 0x7f {
				return "", nil, fmt.Errorf("invalid RDP cookie")
			}
		}
		return "", data[end+2:], nil
	}
	if !validRoutingToken(prefix) {
		return "", nil, fmt.Errorf("invalid RDP routing token")
	}
	return prefix, data[end+2:], nil
}

func validRoutingToken(token string) bool {
	// Connect tokens encode 128 random bits as 32 lowercase hexadecimal characters.
	if len(token) != 32 {
		return false
	}
	for _, c := range token {
		if !('0' <= c && c <= '9') && !('a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

func parseClientNegotiation(data []byte) (uint32, error) {
	if len(data) < 8 || data[0] != byte(x224.TYPE_RDP_NEG_REQ) || binary.LittleEndian.Uint16(data[2:4]) != 8 {
		return 0, fmt.Errorf("invalid RDP negotiation request")
	}
	const correlationInfoPresent = 0x08
	if data[1]&correlationInfoPresent == 0 {
		if len(data) != 8 {
			return 0, fmt.Errorf("unexpected data after RDP negotiation request")
		}
	} else if len(data) != 44 || data[8] != 0x06 || data[9] != 0 || binary.LittleEndian.Uint16(data[10:12]) != 36 {
		return 0, fmt.Errorf("invalid RDP correlation info")
	}
	return binary.LittleEndian.Uint32(data[4:8]), nil
}
