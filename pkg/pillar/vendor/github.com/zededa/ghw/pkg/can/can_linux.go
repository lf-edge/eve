package can

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/zededa/ghw/pkg/bus"
	"github.com/zededa/ghw/pkg/linuxpath"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/pci"
	pciAddress "github.com/zededa/ghw/pkg/pci/address"
	"github.com/zededa/ghw/pkg/usb"
	usbAddress "github.com/zededa/ghw/pkg/usb/address"
)

func (i *Info) load(opts *option.Options) error {
	paths := linuxpath.New(opts)
	// CAN devices are network devices with type 280 (ARPHRD_CAN)
	entries, err := os.ReadDir(paths.SysClassNet)
	if err != nil {
		return nil // Return empty if net class doesn't exist
	}

	for _, entry := range entries {
		name := entry.Name()
		devPath := filepath.Join(paths.SysClassNet, name)

		// Check type
		typePath := filepath.Join(devPath, "type")
		typeBytes, err := os.ReadFile(typePath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(typeBytes)) != "280" {
			continue
		}

		device := &Device{
			Name: name,
		}

		// Resolve Parent (PCI/USB)
		realPath, err := filepath.EvalSymlinks(filepath.Join(devPath, "device"))
		if err == nil {
			device.Parent = resolveParent(strings.TrimPrefix(realPath, paths.SysRoot))
		}

		i.Devices = append(i.Devices, device)
	}
	return nil
}

// resolveParent attempts to find PCI or USB parent info from a sysfs path
func resolveParent(path string) bus.BusParent {
	parent := bus.BusParent{}

	bus, port, err := usb.ExtractUSBBusnumPort(path)
	if err == nil {
		parent.USB = &usbAddress.Address{
			Busnum: bus,
			Port:   port,
		}
	}
	pciAddr := pci.FindPCIAddress(path)
	if pciAddr != "" {
		parent.PCI = pciAddress.FromString(pciAddr)
	}

	return parent
}
