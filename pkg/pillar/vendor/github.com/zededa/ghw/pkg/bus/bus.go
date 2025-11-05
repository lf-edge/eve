package bus

import (
	pciAddress "github.com/zededa/ghw/pkg/pci/address"
	usbAddress "github.com/zededa/ghw/pkg/usb/address"
)

type BusParent struct {
	PCI *pciAddress.Address `json:"pci,omitempty"`
	USB *usbAddress.Address `json:"usb,omitempty"`
}
