// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// injectionChars break out of a config directive. The QEMU (-readconfig) and
// Xen xl configs are line-oriented, so a newline or CR starts a new directive;
// NUL truncates the value in the C-level hypervisor tooling.
const injectionChars = "\n\r\x00"

// validateConfigField rejects a controller-supplied value that could inject
// extra config lines. Quotes and commas are allowed: they are legitimate in
// paths and kernel command lines and cannot break out of a single line.
func validateConfigField(name, value string) error {
	if i := strings.IndexAny(value, injectionChars); i >= 0 {
		return fmt.Errorf("invalid character %q in %s: control characters "+
			"are not allowed (possible hypervisor config injection)",
			value[i], name)
	}
	return nil
}

// validateDomainConfig rejects injectionChars in every controller-supplied
// string rendered into the QEMU/Xen config, as a single choke point at the top
// of each CreateDomConfig. It covers the full set of rendered strings, not a
// subset, so it does not rot as the templates change. Not checked: the
// cloud-init payload (written to a separate image and may contain newlines),
// numeric/enum fields and the parsed MAC (cannot carry these chars), and
// DisplayName (overwritten with the validated domainName before rendering).
func validateDomainConfig(domainName string, config types.DomainConfig,
	diskStatusList []types.DiskStatus, aa *types.AssignableAdapters) error {

	fields := []struct {
		name, value string
	}{
		{"domain name", domainName},
		{"kernel path", config.Kernel},
		{"ramdisk path", config.Ramdisk},
		{"device tree path", config.DeviceTree},
		{"boot loader path", config.BootLoader},
		{"root device", config.RootDev},
		{"extra boot args", config.ExtraArgs},
		{"VNC password", config.VncPasswd},
	}
	for _, f := range fields {
		if err := validateConfigField(f.name, f.value); err != nil {
			return err
		}
	}

	// Xen dtdev= and iomem= list entries.
	for _, dt := range config.DtDev {
		if err := validateConfigField("device tree device", dt); err != nil {
			return err
		}
	}
	for _, im := range config.IOMem {
		if err := validateConfigField("iomem range", im); err != nil {
			return err
		}
	}

	for i := range diskStatusList {
		ds := &diskStatusList[i]
		if err := validateConfigField("disk file location", ds.FileLocation); err != nil {
			return err
		}
		if err := validateConfigField("disk WWN", ds.WWN); err != nil {
			return err
		}
		if err := validateConfigField("disk vdev", ds.Vdev); err != nil {
			return err
		}
	}

	for i := range config.VifList {
		vif := &config.VifList[i]
		if err := validateConfigField("bridge name", vif.Bridge); err != nil {
			return err
		}
		if err := validateConfigField("vif name", vif.Vif); err != nil {
			return err
		}
	}

	// Passthrough attributes rendered into the KVM vfio-pci address and the Xen
	// pci=/irqs=/ioports=/serial=/usb= lines. Only this domain's bundles are
	// checked, so another app's bad bundle can't block it.
	if aa != nil {
		for i := range aa.IoBundleList {
			ib := &aa.IoBundleList[i]
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				continue
			}
			ioFields := []struct {
				name, value string
			}{
				{"PCI address", ib.PciLong},
				{"IRQ", ib.Irq},
				{"I/O ports", ib.Ioports},
				{"serial device", ib.Serial},
				{"USB address", ib.UsbAddr},
			}
			for _, f := range ioFields {
				if err := validateConfigField(f.name, f.value); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
