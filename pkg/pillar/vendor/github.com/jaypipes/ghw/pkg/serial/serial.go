// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package serial

import (
	"fmt"

	"github.com/jaypipes/ghw/pkg/marshal"
	"github.com/jaypipes/ghw/pkg/option"
)

type PCIAddress struct {
	Domain   string `json:"domain"`
	Bus      string `json:"bus"`
	Device   string `json:"device"`
	Function string `json:"function"`
}

type USBAddress struct {
	Bus    string `json:"bus"`
	Devnum string `json:"devnum"`
}

type BusParent struct {
	PCI *PCIAddress `json:"pci,omitempty"`
	USB *USBAddress `json:"usb,omitempty"`
}

type Device struct {
	Name    string     `json:"name"`
	Address string     `json:"address"`
	IO      string     `json:"io"`
	IRQ     string     `json:"irq"`
	Parent  *BusParent `json:"parent,omitempty"`
}

func (d Device) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.Address)
}

type Info struct {
	Devices []*Device `json:"devices"`
}

func (i *Info) String() string {
	return fmt.Sprintf(
		"Serial (%d devices)",
		len(i.Devices),
	)
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

func (i *Info) YAMLString() string {
	return marshal.SafeYAML(i)
}

func (i *Info) JSONString(indent bool) string {
	return marshal.SafeJSON(i, indent)
}
