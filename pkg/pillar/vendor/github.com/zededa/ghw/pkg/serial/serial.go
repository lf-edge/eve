// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package serial

import (
	"fmt"

	"github.com/zededa/ghw/pkg/bus"
	"github.com/zededa/ghw/pkg/marshal"
	"github.com/zededa/ghw/pkg/option"
)

type Device struct {
	Name    string        `json:"name"`
	Address string        `json:"address"`
	IO      string        `json:"io"`
	IRQ     string        `json:"irq"`
	Parent  bus.BusParent `json:"parent,omitempty"`
}

func (d Device) String() string {
	return fmt.Sprintf("%s (address: %s) (io: %s) (irq: %s) (parent: %+v)", d.Name, d.Address, d.IO, d.IRQ, d.Parent)
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
