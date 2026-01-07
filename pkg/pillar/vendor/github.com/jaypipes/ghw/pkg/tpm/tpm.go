package tpm

import (
	"fmt"

	"github.com/jaypipes/ghw/pkg/marshal"
	"github.com/jaypipes/ghw/pkg/option"
)

type Info struct {
	Present         bool   `json:"present"`
	Manufacturer    string `json:"manufacturer"`
	FirmwareVersion string `json:"firmware_version"`
	SpecVersion     string `json:"spec_version"`
}

func (i *Info) String() string {
	if i.Present {
		return fmt.Sprintf("TPM %s (FW: %s, Spec: %s)", i.Manufacturer, i.FirmwareVersion, i.SpecVersion)
	}
	return "TPM not present"
}

func New(opts ...option.Option) (*Info, error) {
	merged := option.FromEnv()
	for _, opt := range opts {
		opt(merged)
	}
	info := &Info{}
	if err := info.load(merged); err != nil {
		return nil, err
	}
	return info, nil
}

func (i *Info) JSONString(indent bool) string {
	return marshal.SafeJSON(i, indent)
}

func (i *Info) YAMLString() string {
	return marshal.SafeYAML(i)
}
