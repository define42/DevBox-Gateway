// Package cloudinit builds NoCloud configuration documents and seed images.
package cloudinit

import (
	"bytes"
	"fmt"
	"reflect"

	yaml "github.com/goccy/go-yaml"
	"github.com/kdomanski/iso9660"
)

// UserData is the cloud-init user-data document stored on the seed ISO.
type UserData struct {
	Output    *Output   `yaml:"output,omitempty"`
	Keyboard  *Keyboard `yaml:"keyboard,omitempty"`
	Users     []User    `yaml:"users,omitempty"`
	SSHPwAuth bool      `yaml:"ssh_pwauth,omitempty"`
	RunCmd    []string  `yaml:"runcmd,omitempty"`
}

// Output configures cloud-init console logging.
type Output struct {
	All string `yaml:"all,omitempty"`
}

// Keyboard configures the guest keyboard layout.
type Keyboard struct {
	Layout  string `yaml:"layout,omitempty"`
	Variant string `yaml:"variant"`
}

// User describes a cloud-init user account.
type User struct {
	Name       string `yaml:"name,omitempty"`
	Sudo       string `yaml:"sudo,omitempty"`
	Shell      string `yaml:"shell,omitempty"`
	LockPasswd bool   `yaml:"lock_passwd"`
	Passwd     string `yaml:"passwd,omitempty"`
}

// MetaData is the NoCloud meta-data document stored on the seed ISO.
type MetaData struct {
	InstanceID    string `yaml:"instance-id,omitempty"`
	LocalHostname string `yaml:"local-hostname,omitempty"`
}

// NetworkConfig is the NoCloud network-config document.
type NetworkConfig struct {
	Network Network `yaml:"network"`
}

// Network describes the top-level network section for cloud-init.
type Network struct {
	Version   int       `yaml:"version"`
	Ethernets Ethernets `yaml:"ethernets,omitempty"`
}

// Ethernets groups ethernet interface definitions for cloud-init.
type Ethernets struct {
	All Ethernet `yaml:"all"`
}

// Ethernet configures a single ethernet interface definition.
type Ethernet struct {
	Match    *InterfaceMatch `yaml:"match,omitempty"`
	DHCP4    bool            `yaml:"dhcp4"`
	DHCP6    bool            `yaml:"dhcp6"`
	AcceptRA bool            `yaml:"accept-ra"`
}

// InterfaceMatch matches interfaces by name glob for cloud-init.
type InterfaceMatch struct {
	Name string `yaml:"name,omitempty"`
}

// CreateSeedISO builds a NoCloud seed ISO and returns its bytes.
func CreateSeedISO(userDataDoc *UserData, metaDataDoc *MetaData, networkConfigDoc *NetworkConfig) ([]byte, error) {
	userData, err := seedISOYAMLBytes("user-data", userDataDoc, true, "#cloud-config\n")
	if err != nil {
		return nil, err
	}

	metaData, err := seedISOYAMLBytes("meta-data", metaDataDoc, true, "")
	if err != nil {
		return nil, err
	}

	networkConfig, err := seedISOYAMLBytes("network-config", networkConfigDoc, false, "#cloud-config\n")
	if err != nil {
		return nil, err
	}

	const volumeID = "cidata"

	isoWriter, err := iso9660.NewWriter()
	if err != nil {
		return nil, fmt.Errorf("create iso writer: %w", err)
	}
	defer func() {
		_ = isoWriter.Cleanup()
	}()

	// cloud-init requires exact filenames.
	if err := isoWriter.AddFile(bytes.NewReader(userData), "user-data"); err != nil {
		return nil, fmt.Errorf("add user-data: %w", err)
	}

	if err := isoWriter.AddFile(bytes.NewReader(metaData), "meta-data"); err != nil {
		return nil, fmt.Errorf("add meta-data: %w", err)
	}

	if len(networkConfig) > 0 {
		if err := isoWriter.AddFile(bytes.NewReader(networkConfig), "network-config"); err != nil {
			return nil, fmt.Errorf("add network-config: %w", err)
		}
	}

	var buf bytes.Buffer
	if err := isoWriter.WriteTo(&buf, volumeID); err != nil {
		return nil, fmt.Errorf("write iso: %w", err)
	}

	return buf.Bytes(), nil
}

func seedISOYAMLBytes[T any](name string, doc *T, required bool, prefix string) ([]byte, error) {
	if doc == nil || isZeroSeedDoc(*doc) {
		if required {
			return nil, fmt.Errorf("%s is required", name)
		}
		return nil, nil
	}

	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", name, err)
	}
	if prefix == "" {
		return data, nil
	}

	buf := make([]byte, 0, len(prefix)+len(data))
	buf = append(buf, prefix...)
	buf = append(buf, data...)
	return buf, nil
}

func isZeroSeedDoc[T any](doc T) bool {
	return reflect.ValueOf(doc).IsZero()
}
