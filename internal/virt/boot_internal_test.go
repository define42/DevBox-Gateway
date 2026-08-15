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
		IP struct {
			DHCP struct {
				Range struct {
					Start string `xml:"start,attr"`
					End   string `xml:"end,attr"`
				} `xml:"range"`
			} `xml:"dhcp"`
		} `xml:"ip"`
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
	if parsed.IP.DHCP.Range.Start != "192.168.122.2" {
		t.Fatalf("DHCP range start = %q, want 192.168.122.2", parsed.IP.DHCP.Range.Start)
	}
	if parsed.IP.DHCP.Range.End != "192.168.122.253" {
		t.Fatalf("DHCP range end = %q, want 192.168.122.253", parsed.IP.DHCP.Range.End)
	}
	// The domain XML attaches VDIs to this exact network, so the name must match.
	if !strings.Contains(doc, "<name>"+defaultNetworkName+"</name>") {
		t.Fatalf("expected <name>%s</name> in network XML", defaultNetworkName)
	}
}
