package virt

import "github.com/define42/devbox-gateway/internal/cloudinit"

type (
	// SeedUserData is the cloud-init user-data document stored on the seed ISO.
	SeedUserData = cloudinit.UserData
	// SeedOutput configures cloud-init console logging.
	SeedOutput = cloudinit.Output
	// SeedKeyboard configures the guest keyboard layout.
	SeedKeyboard = cloudinit.Keyboard
	// SeedUser describes a cloud-init user account.
	SeedUser = cloudinit.User
	// SeedMetaData is the NoCloud meta-data document stored on the seed ISO.
	SeedMetaData = cloudinit.MetaData
	// SeedNetworkConfig is the NoCloud network-config document.
	SeedNetworkConfig = cloudinit.NetworkConfig
	// SeedNetwork describes the top-level network section for cloud-init.
	SeedNetwork = cloudinit.Network
	// SeedEthernets groups ethernet interface definitions for cloud-init.
	SeedEthernets = cloudinit.Ethernets
	// SeedEthernet configures a single ethernet interface definition.
	SeedEthernet = cloudinit.Ethernet
	// SeedInterfaceMatch matches interfaces by name glob for cloud-init.
	SeedInterfaceMatch = cloudinit.InterfaceMatch
)

// CreateSeedISO builds a NoCloud seed ISO and returns its bytes.
func CreateSeedISO(
	userDataDoc *SeedUserData,
	metaDataDoc *SeedMetaData,
	networkConfigDoc *SeedNetworkConfig,
) ([]byte, error) {
	return cloudinit.CreateSeedISO(userDataDoc, metaDataDoc, networkConfigDoc)
}
