// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package usb

import (
	"fmt"
	"strings"

	"github.com/zededa/ghw/pkg/marshal"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/bus"
	usbAddress "github.com/zededa/ghw/pkg/usb/address"
)

type Device struct {
	Driver         string        `json:"driver"`
	Type           string        `json:"type"`
	VendorID       string        `json:"vendor_id"`
	ProductID      string        `json:"product_id"`
	Product        string        `json:"product"`
	RevisionID     string        `json:"revision_id"`
	Interface      string        `json:"interface"`
	Devnum         string        `json:"devnum"`
	Parent         bus.BusParent `json:"parent,omitempty"`
	Class          string        `json:"class"`
	Subclass       string        `json:"subclass"`
	Protocol       string        `json:"protocol"`
	Controller     string        `json:"controller,omitempty"`
	UEventFilePath string
	usbAddress.Address
}

func (d Device) String() string {
	address := ""
	if d.Port != "" {
		address = d.Address.String()
	}

	kvs := []struct {
		name  string
		value string
	}{
		{"driver", d.Driver},
		{"type", d.Type},
		{"vendorID", d.VendorID},
		{"productID", d.ProductID},
		{"product", d.Product},
		{"revisionID", d.RevisionID},
		{"interface", d.Interface},
		{"pci_address", d.Controller},
		{"address", address},
	}

	if d.Parent.PCI != nil {
		kvs = append(kvs, struct {
			name  string
			value string
		}{
			name:  "parent-pci",
			value: fmt.Sprintf("%s:%s:%s.%s", d.Parent.PCI.Domain, d.Parent.PCI.Bus, d.Parent.PCI.Device, d.Parent.PCI.Function),
		})
	}
	if d.Parent.USB != nil {
		kvs = append(kvs, struct {
			name  string
			value string
		}{
			name:  "parent-usb",
			value: fmt.Sprintf("%d-%s", d.Parent.USB.Busnum, d.Parent.USB.Port),
		})
	}

	var str strings.Builder

	i := 0
	for _, s := range kvs {
		k := s.name
		v := s.value

		if v == "" {
			continue
		}
		needsQuotationMarks := strings.ContainsAny(v, " \t")

		if i > 0 {
			str.WriteString(" ")
		}
		i++
		str.WriteString(k)
		str.WriteString("=")
		if needsQuotationMarks {
			str.WriteString("\"")
		}
		str.WriteString(v)
		if needsQuotationMarks {
			str.WriteString("\"")
		}

	}

	return str.String()
}

// Info describes all network interface controllers (NICs) in the host system.
type Info struct {
	Devices []*Device `json:"devices"`
}

// String returns a short string with information about the networking on the
// host system.
func (i *Info) String() string {
	return fmt.Sprintf(
		"USB (%d USBs)",
		len(i.Devices),
	)
}

// New returns a pointer to an Info struct that contains information about the
// USB devices on the host system
func New(opt ...option.Option) (*Info, error) {
	opts := &option.Options{}
	for _, o := range opt {
		o(opts)
	}
	info := &Info{}
	if err := info.load(opts); err != nil {
		return nil, err
	}

	return info, nil
}

// simple private struct used to encapsulate usb information in a
// top-level "usb" YAML/JSON map/object key
type usbPrinter struct {
	Info *Info `json:"usb"`
}

// YAMLString returns a string with the net information formatted as YAML
// under a top-level "net:" key
func (i *Info) YAMLString() string {
	return marshal.SafeYAML(usbPrinter{i})
}

// JSONString returns a string with the net information formatted as JSON
// under a top-level "net:" key
func (i *Info) JSONString(indent bool) string {
	return marshal.SafeJSON(usbPrinter{i}, indent)
}
