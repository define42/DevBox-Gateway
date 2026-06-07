package virt

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestDefaultNetworkXML(t *testing.T) {
	doc := defaultNetworkXML()

	// Must be well-formed XML so libvirt's NetworkDefineXML accepts it.
	var parsed struct {
		XMLName xml.Name `xml:"network"`
		Name    string   `xml:"name"`
		Forward struct {
			Mode string `xml:"mode,attr"`
		} `xml:"forward"`
	}
	if err := xml.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("defaultNetworkXML is not valid XML: %v", err)
	}

	if parsed.Name != defaultNetworkName {
		t.Fatalf("network name = %q, want %q", parsed.Name, defaultNetworkName)
	}
	if parsed.Forward.Mode != "nat" {
		t.Fatalf("forward mode = %q, want nat", parsed.Forward.Mode)
	}
	// The domain XML attaches VDIs to this exact network, so the name must match.
	if !strings.Contains(doc, "<name>"+defaultNetworkName+"</name>") {
		t.Fatalf("expected <name>%s</name> in network XML", defaultNetworkName)
	}
}
