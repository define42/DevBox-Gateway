package virt

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestUbuntuDomainEscapesValues proves that an unsafe value reaching UbuntuDomain
// cannot break out of its element/attribute and inject extra domain XML. This is
// defense-in-depth: login usernames are validated upstream, but the sink must be
// safe on its own.
func TestUbuntuDomainEscapesValues(t *testing.T) {
	const malicious = `evil</name><devices><disk device='disk'/></devices><name>x`

	xmlDoc := UbuntuDomain(malicious, "seed.iso", "pool", 2, 2048)

	if strings.Contains(xmlDoc, "</name><devices><disk") {
		t.Fatalf("injected XML must not appear unescaped:\n%s", xmlDoc)
	}

	var parsed struct {
		XMLName xml.Name `xml:"domain"`
		Name    string   `xml:"name"`
	}
	if err := xml.Unmarshal([]byte(xmlDoc), &parsed); err != nil {
		t.Fatalf("domain xml should remain well-formed: %v", err)
	}
	if parsed.Name != malicious {
		t.Fatalf("name should round-trip to the literal value, got %q", parsed.Name)
	}
}
