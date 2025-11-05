package can

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/jaypipes/ghw/pkg/linuxpath"
	"github.com/jaypipes/ghw/pkg/option"
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
			device.Parent = resolveParent(realPath)
		}

		i.Devices = append(i.Devices, device)
	}
	return nil
}

// resolveParent attempts to find PCI or USB parent info from a sysfs path
func resolveParent(path string) *BusParent {
	// Check for USB
	if strings.Contains(path, "/usb") {
		p := path
		for i := 0; i < 5; i++ { // limit depth
			if _, err := os.Stat(filepath.Join(p, "busnum")); err == nil {
				bus, _ := os.ReadFile(filepath.Join(p, "busnum"))
				dev, _ := os.ReadFile(filepath.Join(p, "devnum"))
				return &BusParent{
					USB: &USBAddress{
						Bus:    strings.TrimSpace(string(bus)),
						Devnum: strings.TrimSpace(string(dev)),
					},
				}
			}
			p = filepath.Dir(p)
		}
	}

	// Check for PCI
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		// 0000:00:00.0 length is 12
		if len(part) == 12 && part[4] == ':' && part[7] == ':' && part[10] == '.' {
			return &BusParent{
				PCI: &PCIAddress{
					Domain:   part[0:4],
					Bus:      part[5:7],
					Device:   part[8:10],
					Function: part[11:],
				},
			}
		}
	}

	return nil
}
