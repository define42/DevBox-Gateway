// Channel filtering for the RDP proxy.
//
// The gateway terminates TLS on both the client and backend sides, so it has
// access to the plaintext RDP byte stream. Right after the TLS handshake the
// client sends an MCS Connect Initial PDU that, embedded in its GCC Conference
// Create Request user data, lists the static virtual channels the client wants
// to use (CS_NET, type=0xC003). Among these are the well known names:
//
//   * "cliprdr" – clipboard redirection
//   * "rdpdr"   – file system / drive redirection (also smart cards, ports…)
//
// To enforce a "no clipboard" or "no drive mapping" policy from the gateway,
// regardless of what the client requests or how the VM is configured, we
// rewrite the channel name in place to something the server will not bind any
// service to. The server still allocates an MCS channel ID for the entry, so
// the subsequent MCS Channel Join sequence still succeeds (and the RDP
// connection does not abort), but no traffic ever flows on that channel.
//
// Renaming keeps every length field – BER, PER, GCC and CS_NET – unchanged, so
// no enclosing length needs to be patched. This is the same trick used by
// several open source RDP proxies (e.g. freerdp-proxy's ChannelFilter).

package rdp

import (
	"encoding/binary"
	"log"
	"rdptlsgateway/internal/config"
	"strings"
)

const (
	// channelNameByteLen is the fixed byte length of a virtual channel name in
	// the CS_NET ChannelDef structure (null padded ASCII).
	channelNameByteLen = 8

	// channelDefByteLen is the size in bytes of one ChannelDef entry
	// (8-byte name + 4-byte options).
	channelDefByteLen = 12

	// csNetHeaderByteLen is the size of the CS_NET block header: 2-byte type
	// + 2-byte length + 4-byte channelCount.
	csNetHeaderByteLen = 8

	// csNetMaxChannels is an upper bound used to sanity-check the
	// channelCount field. MS-RDPBCGR limits the number of static channels to
	// 31; we accept a slightly larger value for safety when scanning.
	csNetMaxChannels = 31

	// csNetTypeLow / csNetTypeHigh are the two little-endian bytes of the
	// CS_NET block type identifier (0xC003).
	csNetTypeLow  = 0x03
	csNetTypeHigh = 0xC0
)

// channelFilter decides which RDP virtual channels the gateway will strip.
type channelFilter struct {
	blocked map[string]string
}

// newChannelFilter builds the filter from gateway settings.
func newChannelFilter(settings *config.SettingsType) channelFilter {
	blocked := make(map[string]string)
	if settings != nil && settings.GetBool(config.RDP_DISABLE_CLIPBOARD) {
		blocked["cliprdr"] = "_NOCLIP\x00"
	}
	if settings != nil && settings.GetBool(config.RDP_DISABLE_DRIVES) {
		blocked["rdpdr"] = "_NODRV\x00\x00"
	}
	return channelFilter{blocked: blocked}
}

// enabled reports whether the filter would modify any traffic.
func (f channelFilter) enabled() bool {
	return len(f.blocked) > 0
}

// rewriteMCSConnectInitial scans buf (a full TPKT PDU containing an MCS
// Connect Initial) for the CS_NET block and renames any channel whose name is
// blocked. It modifies buf in place. The return value is the list of original
// channel names that were rewritten; an empty slice means no change was made.
func (f channelFilter) rewriteMCSConnectInitial(buf []byte) []string {
	if !f.enabled() {
		return nil
	}

	offset, count, ok := findCSNetBlock(buf)
	if !ok {
		return nil
	}

	return f.renameChannels(buf, offset, count)
}

// findCSNetBlock searches buf for the CS_NET GCC user-data block and returns
// the byte offset of its first ChannelDef entry along with the channel count.
// It uses a structural signature scan rather than a full BER/PER parse: the
// fixed 2-byte type identifier 0xC003 is followed by a length and a channel
// count whose relationship (length == 8 + 12*count) is highly unlikely to
// match arbitrary bytes by accident.
func findCSNetBlock(buf []byte) (channelArrayOffset int, channelCount uint32, ok bool) {
	// Skip the 4-byte TPKT header and the X.224 Data TPDU header (3 bytes).
	// Start a bit before just in case the scanner needs slack; the block can
	// occur anywhere inside the GCC user data.
	const minStart = 7
	if len(buf) < minStart+csNetHeaderByteLen {
		return 0, 0, false
	}

	for i := minStart; i+csNetHeaderByteLen <= len(buf); i++ {
		if buf[i] != csNetTypeLow || buf[i+1] != csNetTypeHigh {
			continue
		}
		length := binary.LittleEndian.Uint16(buf[i+2 : i+4])
		count := binary.LittleEndian.Uint32(buf[i+4 : i+8])

		if count == 0 || count > csNetMaxChannels {
			continue
		}
		if int(length) != csNetHeaderByteLen+int(count)*channelDefByteLen {
			continue
		}
		if i+int(length) > len(buf) {
			continue
		}
		return i + csNetHeaderByteLen, count, true
	}
	return 0, 0, false
}

// renameChannels iterates ChannelDef entries starting at offset and replaces
// the names of blocked channels in place. It returns the original names of
// channels that were rewritten.
func (f channelFilter) renameChannels(buf []byte, offset int, count uint32) []string {
	var rewritten []string
	for k := uint32(0); k < count; k++ {
		nameStart := offset + int(k)*channelDefByteLen
		nameEnd := nameStart + channelNameByteLen

		original := strings.ToLower(strings.TrimRight(string(buf[nameStart:nameEnd]), "\x00"))
		replacement, blockedName := f.blocked[original]
		if !blockedName {
			continue
		}

		// Zero the slot then copy the replacement so trailing bytes stay null
		// padded as per MS-RDPBCGR 2.2.1.3.4.1.
		for j := nameStart; j < nameEnd; j++ {
			buf[j] = 0
		}
		copy(buf[nameStart:nameEnd], replacement)

		rewritten = append(rewritten, original)
		log.Printf("rdp debug: stripped virtual channel %q (renamed to %q)", original, strings.TrimRight(replacement, "\x00"))
	}
	return rewritten
}
