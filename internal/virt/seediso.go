package virt

import (
	"bytes"
	"fmt"
	"reflect"

	yaml "github.com/goccy/go-yaml"
	"github.com/kdomanski/iso9660"
)

type SeedUserData struct {
	Output    *SeedOutput   `yaml:"output,omitempty"`
	Keyboard  *SeedKeyboard `yaml:"keyboard,omitempty"`
	Users     []SeedUser    `yaml:"users,omitempty"`
	SSHPwAuth bool          `yaml:"ssh_pwauth,omitempty"`
	RunCmd    []string      `yaml:"runcmd,omitempty"`
}

type SeedOutput struct {
	All string `yaml:"all,omitempty"`
}

type SeedKeyboard struct {
	Layout  string `yaml:"layout,omitempty"`
	Variant string `yaml:"variant"`
}

type SeedUser struct {
	Name       string `yaml:"name,omitempty"`
	Sudo       string `yaml:"sudo,omitempty"`
	Shell      string `yaml:"shell,omitempty"`
	LockPasswd bool   `yaml:"lock_passwd"`
	Passwd     string `yaml:"passwd,omitempty"`
}

type SeedMetaData struct {
	InstanceID    string `yaml:"instance-id,omitempty"`
	LocalHostname string `yaml:"local-hostname,omitempty"`
}

type SeedNetworkConfig struct {
	Network SeedNetwork `yaml:"network"`
}

type SeedNetwork struct {
	Version   int           `yaml:"version"`
	Ethernets SeedEthernets `yaml:"ethernets,omitempty"`
}

type SeedEthernets struct {
	All SeedEthernet `yaml:"all"`
}

type SeedEthernet struct {
	Match    *SeedInterfaceMatch `yaml:"match,omitempty"`
	DHCP4    bool                `yaml:"dhcp4"`
	DHCP6    bool                `yaml:"dhcp6"`
	AcceptRA bool                `yaml:"accept-ra"`
}

type SeedInterfaceMatch struct {
	Name string `yaml:"name,omitempty"`
}

// CreateSeedISO builds a NoCloud seed ISO and returns its bytes.
func CreateSeedISO(userDataDoc *SeedUserData, metaDataDoc *SeedMetaData, networkConfigDoc *SeedNetworkConfig) ([]byte, error) {
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

	volumeID := "cidata"

	isoWriter, err := iso9660.NewWriter()
	if err != nil {
		return nil, fmt.Errorf("create iso writer: %w", err)
	}
	defer func() {
		_ = isoWriter.Cleanup()
	}()

	// cloud-init requires exact filenames
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
	if doc == nil {
		if required {
			return nil, fmt.Errorf("%s is required", name)
		}
		return nil, nil
	}
	if required && isZeroSeedDoc(*doc) {
		return nil, fmt.Errorf("%s is required", name)
	}
	if !required && isZeroSeedDoc(*doc) {
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
