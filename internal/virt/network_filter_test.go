package virt

import (
	"strings"
	"testing"
)

func TestNetworkFiltersEqual(t *testing.T) {
	doc := networkFilterXML()
	rendered := strings.Replace(doc, "chain='root'>", "chain='root'>\n<uuid>ee160b68-071b-4478-993a-fd19a08c3ba6</uuid>", 1)
	rendered = strings.ReplaceAll(rendered, "action='drop' direction='out'", "direction='out' action='drop'")
	rendered = strings.ReplaceAll(rendered, "\n", "")
	if equal, err := networkFiltersEqual(doc, rendered); err != nil || !equal {
		t.Fatalf("libvirt formatting must not reinstall an unchanged filter: equal=%t err=%v", equal, err)
	}
	unsafe := strings.Replace(rendered, "srcmacaddr='$MAC'", "srcmacaddr='52:54:00:00:00:01'", 1)
	if equal, err := networkFiltersEqual(doc, unsafe); err != nil || equal {
		t.Fatalf("changed source-MAC enforcement accepted: equal=%t err=%v", equal, err)
	}
	if _, err := networkFiltersEqual(doc, "<filter"); err == nil {
		t.Fatal("malformed installed filter must fail validation")
	}
}
