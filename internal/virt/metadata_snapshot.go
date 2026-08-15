package virt

import (
	"encoding/xml"
	"fmt"
	"log"
	"strings"

	"libvirt.org/go/libvirt"
)

// domainMetadataSnapshot is the dashboard-facing subset of persistent domain
// metadata. The individual metadata getters remain the authoritative direct
// helpers; inventory uses this snapshot to replace four libvirt calls with one
// inactive-domain XML read.
type domainMetadataSnapshot struct {
	Owner     string
	GuestUser string
	BaseImage string
	CreatedAt string
}

type domainMetadataSnapshotLoader func() (domainMetadataSnapshot, error)

// domainMetadataCacheSweep builds the worker's metadata cache for one complete
// inventory pass. Entries are keyed only by libvirt's immutable domain UUID;
// retaining into a fresh map makes domains that disappeared since the previous
// successful pass fall out of the cache automatically. A nonblank CreatedAt
// makes the gateway-authored metadata immutable for inventory purposes. An
// external administrator editing a completed definition will therefore not be
// reflected until its UUID changes, the identified libvirt host changes, or the
// gateway restarts; authorization getters remain direct and uncached.
type domainMetadataCacheSweep struct {
	previous map[string]domainMetadataSnapshot
	retained map[string]domainMetadataSnapshot
}

func newDomainMetadataCacheSweep(previous map[string]domainMetadataSnapshot) *domainMetadataCacheSweep {
	return &domainMetadataCacheSweep{
		previous: previous,
		retained: make(map[string]domainMetadataSnapshot),
	}
}

func (sweep *domainMetadataCacheSweep) load(
	domainUUID string,
	loader domainMetadataSnapshotLoader,
) (domainMetadataSnapshot, error) {
	domainUUID = strings.TrimSpace(domainUUID)
	if domainUUID != "" {
		if metadata, ok := sweep.retained[domainUUID]; ok {
			return metadata, nil
		}
		if metadata, ok := sweep.previous[domainUUID]; ok {
			sweep.retained[domainUUID] = metadata
			return metadata, nil
		}
	}

	metadata, err := loader()
	if err != nil {
		return domainMetadataSnapshot{}, err
	}

	// startVM writes CreatedAt last, after all optional metadata setters have
	// completed. It is therefore the completion marker. Owner, GuestUser, and
	// BaseImage may legitimately be blank and do not prevent caching.
	if domainUUID != "" && strings.TrimSpace(metadata.CreatedAt) != "" {
		sweep.retained[domainUUID] = metadata
	}
	return metadata, nil
}

func (sweep *domainMetadataCacheSweep) retainedEntries() map[string]domainMetadataSnapshot {
	return sweep.retained
}

type domainMetadataXMLDocument struct {
	XMLName  xml.Name                  `xml:"domain"`
	Metadata domainMetadataXMLContents `xml:"metadata"`
}

type domainMetadataXMLContents struct {
	Owner     string
	GuestUser string
	BaseImage string
	CreatedAt string

	ownerSeen     bool
	guestUserSeen bool
	baseImageSeen bool
	createdAtSeen bool
}

type domainMetadataXMLTarget struct {
	value         *string
	seen          *bool
	expectedLocal string
}

func (metadata *domainMetadataXMLContents) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}

		finished, err := metadata.decodeXMLToken(decoder, start, token)
		if err != nil {
			return err
		}
		if finished {
			return nil
		}
	}
}

func (metadata *domainMetadataXMLContents) decodeXMLToken(
	decoder *xml.Decoder,
	start xml.StartElement,
	token xml.Token,
) (bool, error) {
	switch token := token.(type) {
	case xml.StartElement:
		return false, metadata.decodeXMLStartElement(decoder, token)
	case xml.EndElement:
		return token.Name == start.Name, nil
	default:
		return false, nil
	}
}

func (metadata *domainMetadataXMLContents) decodeXMLStartElement(
	decoder *xml.Decoder,
	start xml.StartElement,
) error {
	target := metadata.targetForXMLNamespace(start.Name.Space)
	if target == nil || *target.seen {
		return decoder.Skip()
	}

	// libvirt's element-metadata lookup selects the first direct child in a
	// namespace. Remember that selection even when its element name is invalid
	// or its value is blank, so a later duplicate cannot make inventory disagree
	// with the direct GetMetadata helpers.
	*target.seen = true
	if start.Name.Local != target.expectedLocal {
		return decoder.Skip()
	}

	var value string
	if err := decoder.DecodeElement(&value, &start); err != nil {
		return err
	}
	*target.value = value
	return nil
}

func (metadata *domainMetadataXMLContents) targetForXMLNamespace(namespace string) *domainMetadataXMLTarget {
	switch namespace {
	case domainOwnerMetadataNamespace:
		return &domainMetadataXMLTarget{
			value:         &metadata.Owner,
			seen:          &metadata.ownerSeen,
			expectedLocal: "owner",
		}
	case domainGuestUserMetadataNamespace:
		return &domainMetadataXMLTarget{
			value:         &metadata.GuestUser,
			seen:          &metadata.guestUserSeen,
			expectedLocal: "guestuser",
		}
	case domainBaseImageMetadataNamespace:
		return &domainMetadataXMLTarget{
			value:         &metadata.BaseImage,
			seen:          &metadata.baseImageSeen,
			expectedLocal: "baseimage",
		}
	case domainCreatedAtMetadataNamespace:
		return &domainMetadataXMLTarget{
			value:         &metadata.CreatedAt,
			seen:          &metadata.createdAtSeen,
			expectedLocal: "createdat",
		}
	default:
		return nil
	}
}

type domainXMLDescGetter func(libvirt.DomainXMLFlags) (string, error)

func loadDomainMetadataSnapshot(getXML domainXMLDescGetter) (domainMetadataSnapshot, error) {
	xmlDesc, err := getXML(libvirt.DOMAIN_XML_INACTIVE)
	if err != nil {
		return domainMetadataSnapshot{}, fmt.Errorf("get inactive domain XML: %w", err)
	}
	return parseDomainMetadataSnapshot(xmlDesc)
}

func parseDomainMetadataSnapshot(xmlDesc string) (domainMetadataSnapshot, error) {
	var document domainMetadataXMLDocument
	if err := xml.Unmarshal([]byte(xmlDesc), &document); err != nil {
		return domainMetadataSnapshot{}, fmt.Errorf("parse domain metadata XML: %w", err)
	}
	return domainMetadataSnapshot{
		Owner:     strings.TrimSpace(document.Metadata.Owner),
		GuestUser: strings.TrimSpace(document.Metadata.GuestUser),
		BaseImage: strings.TrimSpace(document.Metadata.BaseImage),
		CreatedAt: strings.TrimSpace(document.Metadata.CreatedAt),
	}, nil
}

func domainMetadataForVMInfo(name string, d *libvirt.Domain) domainMetadataSnapshot {
	metadata, err := loadDomainMetadataSnapshot(d.GetXMLDesc)
	if err != nil {
		log.Printf("domain metadata %s: %v", name, err)
		return domainMetadataSnapshot{}
	}
	return metadata
}
