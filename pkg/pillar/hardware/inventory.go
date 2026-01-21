// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jaypipes/pcidb"
	pcitypes "github.com/jaypipes/pcidb/types"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/zededa/ghw"
	"github.com/zededa/ghw/pkg/can"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/pci/address"
	"github.com/zededa/ghw/pkg/watchdog"
)

func GetInventoryInfo(log *base.LogObject) (*info.HardwareInventory, error) {
	inventory := &info.HardwareInventory{}

	errs := make(map[string]error)
	inventory.PciDevices, errs["PCI"] = getPCIDevices()
	inventory.UsbDevices, errs["USB"] = getUSBDevices()
	inventory.SerialDevices, errs["Serial"] = getSerialDevices()
	inventory.NetworkDevices, errs["Network"] = getNetworkDevices()
	inventory.CanDevices, errs["CAN"] = getCANDevices()
	inventory.Bios, errs["BIOS"] = getBIOSInfo()
	inventory.CpuInfo, errs["CPU"] = getCPUInfo()
	inventory.TotalMemoryBytes, errs["Memory"] = getMemoryBytes()
	inventory.TotalStorageBytes, errs["Storage"] = getStorageBytes()
	inventory.WatchdogPresent, errs["Watchdog"] = watchdogPresent()
	inventory.Tpm, errs["TPM"] = getTPMInfo()

	inventory.StatusLedPresent = GetStatusLedPresent(GetHardwareModel(log))

	var finalErr error
	for key, err := range errs {
		if err != nil {
			finalErr = errors.Join(finalErr, fmt.Errorf("failed to query for %s: %w", key, err))
		}
	}

	return inventory, finalErr
}

func stringToPCIAddress(str string) *info.PCIAddress {
	pciAddr := address.FromString(str)
	if pciAddr == nil {
		return nil
	}
	domain := pciHexToUint32(pciAddr.Domain)
	bus := pciHexToUint32(pciAddr.Bus)
	device := pciHexToUint32(pciAddr.Device)
	function := pciHexToUint32(pciAddr.Function)

	return &info.PCIAddress{
		Domain:   domain,
		Bus:      bus,
		Device:   device,
		Function: function,
	}
}

func getUSBDevices() ([]*info.USBDevice, error) {
	usbDevices := []*info.USBDevice{}

	usbs, err := ghw.USB(option.WithDisableTools())
	if err != nil {
		return nil, err
	}

	for _, usb := range usbs.Devices {
		vendorId := pciHexToUint32(usb.VendorID)
		productId := pciHexToUint32(usb.ProductID)
		classId := pciHexToUint32(usb.Class)

		parent := &info.BusParent{}
		if usb.Parent.USB != nil {
			parent.UsbParent = &info.USBAddress{
				Bus:  uint32(usb.Parent.USB.Busnum),
				Port: usb.Parent.USB.Port,
			}
		}
		if usb.Parent.PCI != nil {
			parent.PciParent = &info.PCIAddress{
				Domain:   pciHexToUint32(usb.Parent.PCI.Domain),
				Bus:      pciHexToUint32(usb.Parent.PCI.Bus),
				Device:   pciHexToUint32(usb.Parent.PCI.Device),
				Function: pciHexToUint32(usb.Parent.PCI.Function),
			}
		}

		ud := info.USBDevice{
			Parent:    parent,
			VendorId:  vendorId,
			ProductId: productId,
			BusPort: &info.USBAddress{
				Bus:  uint32(usb.Busnum),
				Port: usb.Port,
			},
			ClassId: classId,
			Driver:  usb.Driver,
		}
		usbDevices = append(usbDevices, &ud)
	}

	return usbDevices, nil
}

func getPCIDevices() ([]*info.PCIDevice, error) {
	pciDevices := []*info.PCIDevice{}

	db := pcidb.PCIDB{
		Classes:  map[string]*pcitypes.Class{},
		Vendors:  map[string]*pcitypes.Vendor{},
		Products: map[string]*pcitypes.Product{},
	}
	pcis, err := ghw.PCI(option.WithPCIDB(&db), option.WithDisableTools())
	if err != nil {
		return nil, fmt.Errorf("could not retrieve PCI information: %+w", err)
	}

	for _, pci := range pcis.Devices {
		vendorId := pciHexToUint32(pci.Vendor.ID)
		if vendorId == 0 {
			continue
		}
		productId := pciHexToUint32(pci.Product.ID)
		if productId == 0 {
			continue
		}
		revisionId := pciHexToUint32(pci.Revision)
		subsystemId := pciHexToUint32(pci.Subsystem.ID)
		classId := pciHexToUint32(pci.Class.ID)
		subclassId := pciHexToUint64(pci.Subclass.ID)

		pciDevices = append(pciDevices, &info.PCIDevice{
			ParentPciDeviceAddress: stringToPCIAddress(pci.ParentAddress),
			Driver:                 pci.Driver,
			Address:                stringToPCIAddress(pci.Address),
			VendorId:               vendorId,
			DeviceId:               productId,
			Revision:               revisionId,
			SubsystemId:            subsystemId,
			ClassId:                classId,
			SubclassId:             subclassId,
			IommuGroup:             pci.IOMMUGroup,
		})
	}

	return pciDevices, nil
}

func pciHexToUint32(idString string) uint32 {
	if strings.HasPrefix(idString, "0x") {
		var id uint32
		_, err := fmt.Sscanf(idString, "0x%x", &id)
		if err != nil {
			return 0
		}

		return id
	}

	// otherwise we get an "odd length hex string"
	if len(idString)%2 == 1 {
		idString = "0" + idString
	}
	bs, err := hex.DecodeString(idString)
	if err != nil {
		return 0
	}
	if len(bs) == 4 {
		return binary.BigEndian.Uint32(bs)
	}
	if len(bs) == 2 {
		return uint32(binary.BigEndian.Uint16(bs))
	}
	if len(bs) == 1 {
		var id uint32

		_, err := fmt.Sscanf(idString, "%x", &id)
		if err != nil {
			return 0
		}

		return id
	}

	return 0
}

func pciHexToUint64(idString string) uint64 {
	if strings.HasPrefix(idString, "0x") {
		var id uint64
		_, err := fmt.Sscanf(idString, "0x%x", &id)
		if err != nil {
			return 0
		}

		return id
	}

	// otherwise we get an "odd length hex string"
	if len(idString)%2 == 1 {
		idString = "0" + idString
	}
	bs, err := hex.DecodeString(idString)
	if err != nil {
		return 0
	}
	if len(bs) == 8 {
		return binary.BigEndian.Uint64(bs)
	}
	if len(bs) == 4 {
		return uint64(binary.BigEndian.Uint32(bs))
	}
	if len(bs) == 2 {
		return uint64(binary.BigEndian.Uint16(bs))
	}
	if len(bs) == 1 {
		var id uint64

		_, err := fmt.Sscanf(idString, "%x", &id)
		if err != nil {
			return 0
		}

		return id
	}

	return 0
}

func getSerialDevices() ([]*info.SerialPort, error) {
	serialDevices := []*info.SerialPort{}

	serials, err := ghw.Serial(option.WithDisableTools())
	if err != nil {
		return nil, err
	}
	for _, serial := range serials.Devices {
		sp := info.SerialPort{
			Devpath:     serial.Address,
			IoportRange: serial.IO,
		}

		if irq, err := strconv.ParseUint(serial.IRQ, 10, 64); err == nil {
			sp.Irq = irq
		}

		sp.Parent = &info.BusParent{}
		if serial.Parent.PCI != nil {
			sp.Parent.PciParent = stringToPCIAddress(fmt.Sprintf("%s:%s:%s.%s", serial.Parent.PCI.Domain, serial.Parent.PCI.Bus, serial.Parent.PCI.Device, serial.Parent.PCI.Function))
		}
		if serial.Parent.USB != nil {
			sp.Parent.UsbParent = &info.USBAddress{
				Bus:  uint32(serial.Parent.USB.Busnum),
				Port: serial.Parent.USB.Port,
			}
		}
		serialDevices = append(serialDevices, &sp)
	}
	return serialDevices, nil
}

func getNetworkDevices() ([]*info.NetworkDevice, error) {
	networkDevices := []*info.NetworkDevice{}

	netInfo, err := ghw.Network(option.WithDisableTools())
	if err != nil {
		return nil, err
	}
	for _, nic := range netInfo.NICs {
		nd := info.NetworkDevice{
			Ifname:     nic.Name,
			MacAddress: nic.MACAddress,
		}
		// Speed parsing
		if nic.Speed != "" {
			s := strings.ToLower(nic.Speed)
			var mult uint32 = 1
			if strings.Contains(s, "gb") {
				mult = 1000
			}
			// Remove non-digits
			digits := ""
			for _, r := range s {
				if r >= '0' && r <= '9' {
					digits += string(r)
				}
			}
			if len(digits) > 0 {
				val, _ := strconv.ParseUint(digits, 10, 32)
				nd.SpeedMbps = uint32(val) * mult
			}
		}

		// Type guessing
		if strings.HasPrefix(nic.Name, "wlan") || strings.HasPrefix(nic.Name, "wl") {
			nd.Type = info.NetworkDeviceType_NETWORK_DEVICE_TYPE_WIFI
		} else if strings.HasPrefix(nic.Name, "wwan") {
			nd.Type = info.NetworkDeviceType_NETWORK_DEVICE_TYPE_WWAN
		} else if strings.HasPrefix(nic.Name, "eth") || strings.HasPrefix(nic.Name, "en") {
			nd.Type = info.NetworkDeviceType_NETWORK_DEVICE_TYPE_ETHERNET
		}

		if nic.PCIAddress != nil {
			nd.Parent = &info.BusParent{
				PciParent: stringToPCIAddress(*nic.PCIAddress),
			}
		}
		networkDevices = append(networkDevices, &nd)
	}
	return networkDevices, nil
}

func getCANDevices() ([]*info.CANDevice, error) {
	canDevices := []*info.CANDevice{}

	canInfo, err := can.New()
	if err != nil {
		return nil, err
	}
	for _, dev := range canInfo.Devices {
		cd := info.CANDevice{
			Ifname: dev.Name,
		}
		cd.Parent = &info.BusParent{}
		if dev.Parent.PCI != nil {
			cd.Parent.PciParent = stringToPCIAddress(fmt.Sprintf("%s:%s:%s.%s", dev.Parent.PCI.Domain, dev.Parent.PCI.Bus, dev.Parent.PCI.Device, dev.Parent.PCI.Function))
		}
		if dev.Parent.USB != nil {
			cd.Parent.UsbParent = &info.USBAddress{
				Bus:  uint32(dev.Parent.USB.Busnum),
				Port: dev.Parent.USB.Port,
			}
		}
		canDevices = append(canDevices, &cd)
	}
	return canDevices, nil
}

func getBIOSInfo() (*info.BIOS, error) {
	biosInfo, err := ghw.BIOS(option.WithDisableTools())
	if err != nil {
		return nil, err
	}

	// Collect firmware attributes from /sys/class/firmware-attributes
	fwAttrs := getFirmwareAttributes()

	return &info.BIOS{
		Vendor:     biosInfo.Vendor,
		Version:    biosInfo.Version,
		Attributes: fwAttrs,
	}, nil
}

func getFirmwareAttributes() map[string]string {
	settings := make(map[string]string)
	root := "/sys/class/firmware-attributes"

	drivers, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	for _, drv := range drivers {
		// Look for 'attributes' subdirectory
		attrDir := filepath.Join(root, drv.Name(), "attributes")
		if _, err := os.Stat(attrDir); err != nil {
			continue
		}

		// Iterate over settings
		attrs, err := os.ReadDir(attrDir)
		if err != nil {
			continue
		}

		for _, attr := range attrs {
			if !attr.IsDir() {
				continue
			}
			// Read current_value
			valPath := filepath.Join(attrDir, attr.Name(), "current_value")
			valBytes, err := os.ReadFile(valPath)
			if err == nil {
				// We use "driver/setting" as key in the intermediate map
				key := fmt.Sprintf("%s/%s", drv.Name(), attr.Name())
				settings[key] = strings.TrimSpace(string(valBytes))
			}
		}
	}
	return settings
}

func getCPUInfo() (*info.CPUInfo, error) {
	cpuInfo, err := ghw.CPU(option.WithDisableTools())
	if err != nil {
		return nil, err
	}
	cpuInfoProto := &info.CPUInfo{}
	for _, proc := range cpuInfo.Processors {
		for _, core := range proc.Cores {
			c := info.CPU{
				Model:  proc.Model,
				Vendor: proc.Vendor,
				Id:     uint32(core.ID),
			}
			cpuInfoProto.Cpus = append(cpuInfoProto.Cpus, &c)
		}
	}
	return cpuInfoProto, nil
}

func getMemoryBytes() (uint64, error) {
	memInfo, err := ghw.Memory(option.WithDisableTools())
	if err != nil {
		return 0, err
	}
	return uint64(memInfo.TotalPhysicalBytes), nil
}

func getStorageBytes() (uint64, error) {
	blockInfo, err := ghw.Block(option.WithDisableTools())
	if err != nil {
		return 0, err
	}
	return uint64(blockInfo.TotalPhysicalBytes), nil
}

func watchdogPresent() (bool, error) {
	wdInfo, err := watchdog.New()
	if err != nil {
		return false, err
	}
	return wdInfo.Present, nil
}

func getTPMInfo() (*info.TPM, error) {
	present := evetpm.IsTpmEnabled()
	tpmInfoProto := &info.TPM{
		Present: present,
	}

	if present {
		tpmInfo, err := evetpm.FetchTpmHwInfo()
		if err != nil {
			return nil, err
		}
		// The string returned by FetchTpmHwInfo is formatted as:
		// "Manufacturer-Model, FW Version Version"
		// We try to parse it to fill the individual fields
		parts := strings.Split(tpmInfo, ", FW Version ")
		if len(parts) == 2 {
			tpmInfoProto.FirmwareVersion = parts[1]
			vendorParts := strings.Split(parts[0], "-")
			if len(vendorParts) >= 1 {
				tpmInfoProto.Manufacturer = vendorParts[0]
			}
		} else {
			// Fallback if formatting is unexpected
			tpmInfoProto.Manufacturer = tpmInfo
		}
		specVersion, err := evetpm.GetSpecVersion()
		if err != nil {
			return nil, err
		}
		tpmInfoProto.SpecVersion = specVersion
	}
	return tpmInfoProto, nil
}
