package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"libvirt.org/go/libvirt"
)

const networkFilterName = "devbox-isolated-ipv4"

// networkFilterXML uses Ethernet-layer rules, before bridge source-MAC learning.
// IP and MAC are supplied by the host, never learned from guest packets. The
// final drop also excludes VLAN, IPv6, RARP and other unsupported EtherTypes.
func networkFilterXML() string {
	return fmt.Sprintf(`<filter name='%s' chain='root'>
  <rule action='drop' direction='out' priority='-1000'>
    <mac match='no' srcmacaddr='$MAC'/>
  </rule>
  <rule action='drop' direction='out' priority='-990'>
    <ip protocol='udp' srcportstart='67'/>
  </rule>
  <rule action='drop' direction='in' priority='-930'>
    <ip protocol='udp' srcportstart='67'/>
  </rule>
  <rule action='accept' direction='out' priority='-950'>
    <ip srcipaddr='0.0.0.0' dstipaddr='255.255.255.255' protocol='udp' srcportstart='68' dstportstart='67'/>
  </rule>
  <rule action='accept' direction='out' priority='-950'>
    <ip srcipaddr='0.0.0.0' dstipaddr='192.168.123.1' protocol='udp' srcportstart='68' dstportstart='67'/>
  </rule>
  <rule action='accept' direction='in' priority='-940'>
    <ip srcipaddr='192.168.123.1' protocol='udp' srcportstart='67' dstportstart='68'/>
  </rule>
  <rule action='drop' direction='out' priority='-900'>
    <arp match='no' arpsrcmacaddr='$MAC'/>
  </rule>
  <rule action='accept' direction='out' priority='-890'>
    <arp hwtype='1' protocoltype='0x800' opcode='Request' arpsrcipaddr='0.0.0.0' arpdstipaddr='$IP'/>
  </rule>
  <rule action='drop' direction='out' priority='-880'>
    <arp match='no' arpsrcipaddr='$IP'/>
  </rule>
  <rule action='drop' direction='out' priority='-800'>
    <ip match='no' srcipaddr='$IP'/>
  </rule>
  <rule action='accept' direction='out' priority='-700'>
    <ip dstipaddr='192.168.123.1'/>
  </rule>
  <rule action='drop' direction='out' priority='-690'>
    <ip dstipaddr='192.168.123.0' dstipmask='24'/>
  </rule>
  <rule action='accept' direction='in' priority='100'>
    <ip dstipaddr='$IP'/>
  </rule>
  <rule action='accept' direction='out' priority='100'>
    <ip/>
  </rule>
  <rule action='accept' direction='inout' priority='200'>
    <arp hwtype='1' protocoltype='0x800' opcode='Request'/>
  </rule>
  <rule action='accept' direction='inout' priority='200'>
    <arp hwtype='1' protocoltype='0x800' opcode='Reply'/>
  </rule>
  <rule action='drop' direction='inout' priority='1000'/>
</filter>`, networkFilterName)
}

func ensureNetworkFilter(conn *libvirt.Connect) error {
	doc, err := networkFilterDefinition(conn)
	if err != nil || doc == "" {
		return err
	}
	filter, err := conn.NWFilterDefineXML(doc)
	if err != nil {
		return fmt.Errorf("install mandatory network filter %s: %w", networkFilterName, err)
	}
	defer func() { _ = filter.Free() }()
	return nil
}

// Existing filters keep their UUID. Matching filters are read-only, so backend
// connections do not repeatedly rebuild the rules of every running VM.
func networkFilterDefinition(conn *libvirt.Connect) (string, error) {
	doc := networkFilterXML()
	filter, err := conn.LookupNWFilterByName(networkFilterName)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_NWFILTER) {
			return networkFilterWithUUID(doc, "ee160b68-071b-4478-993a-fd19a08c3ba6"), nil
		}
		return "", fmt.Errorf("lookup mandatory network filter: %w", err)
	}
	defer func() { _ = filter.Free() }()
	existing, err := filter.GetXMLDesc(0)
	if err != nil {
		return "", fmt.Errorf("read mandatory network filter: %w", err)
	}
	matches, err := networkFiltersEqual(existing, doc)
	if err != nil || matches {
		return "", err
	}
	uuid, err := filter.GetUUIDString()
	if err != nil {
		return "", fmt.Errorf("read mandatory network filter UUID: %w", err)
	}
	return networkFilterWithUUID(doc, uuid), nil
}

func networkFilterWithUUID(doc, uuid string) string {
	return strings.Replace(doc, "chain='root'>", "chain='root'><uuid>"+xmlValue(uuid)+"</uuid>", 1)
}

func networkFiltersEqual(first, second string) (bool, error) {
	a, err := canonicalNetworkFilter(first)
	if err != nil {
		return false, err
	}
	b, err := canonicalNetworkFilter(second)
	return a == b, err
}

func canonicalNetworkFilter(doc string) (string, error) {
	decoder := xml.NewDecoder(strings.NewReader(doc))
	var result strings.Builder
	encoder := xml.NewEncoder(&result)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("parse mandatory network filter: %w", err)
		}
		if err := encodeFilterToken(decoder, encoder, token); err != nil {
			return "", err
		}
	}
	if err := encoder.Flush(); err != nil {
		return "", err
	}
	return result.String(), nil
}

func encodeFilterToken(decoder *xml.Decoder, encoder *xml.Encoder, token xml.Token) error {
	switch value := token.(type) {
	case xml.StartElement:
		if value.Name.Local == "uuid" {
			return decoder.Skip()
		}
		slices.SortFunc(value.Attr, func(a, b xml.Attr) int {
			return strings.Compare(a.Name.Space+":"+a.Name.Local, b.Name.Space+":"+b.Name.Local)
		})
		token = value
	case xml.CharData:
		if strings.TrimSpace(string(value)) == "" {
			return nil
		}
	case xml.Comment:
		return nil
	}
	return encoder.EncodeToken(token)
}
