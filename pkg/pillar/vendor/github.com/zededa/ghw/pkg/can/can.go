package can

import (
	"fmt"

	"github.com/zededa/ghw/pkg/bus"
	"github.com/zededa/ghw/pkg/marshal"
	"github.com/zededa/ghw/pkg/option"
)

type Device struct {
	Name   string        `json:"name"`
	Parent bus.BusParent `json:"parent,omitempty"`
}

type Info struct {
	Devices []*Device `json:"devices"`
}

func (i *Info) String() string {
	return fmt.Sprintf("CAN (%d devices)", len(i.Devices))
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
