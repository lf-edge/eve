package main

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/inventory"
)

func main() {
	logger, log := agentlog.Init("spec-cli")
	inventory.SetLogger(logger, log)

	i, err := inventory.CreateInventory()
	if err != nil {
		panic(err)
	}

	for _, pci := range i.PciDevices {
		fmt.Printf(
			"%x:%x:%x.%x vendor %x device %x\n\t%+v\n\n",
			pci.Address.Domain,
			pci.Address.Bus,
			pci.Address.Device,
			pci.Address.Function,
			pci.VendorId,
			pci.DeviceId,
			pci,
		)
	}

	fmt.Println("-------------------------------------------")

	for _, usb := range i.UsbDevices {
		fmt.Printf("%x:%x\n\t%+v\n\n", usb.VendorId, usb.ProductId, usb)
	}
}
