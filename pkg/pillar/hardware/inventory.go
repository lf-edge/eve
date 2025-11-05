// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jaypipes/pcidb"
	pcitypes "github.com/jaypipes/pcidb/types"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/zededa/ghw"
	"github.com/zededa/ghw/pkg/can"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/pci/address"
	"github.com/zededa/ghw/pkg/tpm"
	"github.com/zededa/ghw/pkg/watchdog"
)

type inventoryMsgCreator struct {
	msg *info.ZInfoHardware
}

func AddInventoryInfo(msg *info.ZInfoHardware) error {
	imc := &inventoryMsgCreator{}

	imc.msg = msg
	if imc.msg.Inventory == nil {
		imc.msg.Inventory = &info.HardwareInventory{}
	}

	errs := make(map[string]error)
	errs["PCI"] = imc.fillPCI()
	errs["USB"] = imc.fillUSB()
	errs["Serial"] = imc.fillSerial()
	errs["Network"] = imc.fillNetwork()
	errs["CAN"] = imc.fillCAN()
	errs["BIOS"] = imc.fillBIOS()
	errs["CPU"] = imc.fillCPU()
	errs["Memory"] = imc.fillMemory()
	errs["Storage"] = imc.fillStorage()
	errs["Watchdog"] = imc.fillWatchdog()
	errs["TPM"] = imc.fillTPM()

	var finalErr error
	for key, err := range errs {
		if err != nil {
			finalErr = errors.Join(finalErr, fmt.Errorf("failed to query for %s: %w", key, err))
		}
	}

	return finalErr
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

func (imc *inventoryMsgCreator) fillUSB() error {
	usbs, err := ghw.USB(option.WithDisableTools())
	if err != nil {
		return err
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
		imc.msg.Inventory.UsbDevices = append(imc.msg.Inventory.UsbDevices, &ud)
	}

	return nil
}

func (imc *inventoryMsgCreator) fillPCI() error {
	db := pcidb.PCIDB{
		Classes:  map[string]*pcitypes.Class{},
		Vendors:  map[string]*pcitypes.Vendor{},
		Products: map[string]*pcitypes.Product{},
	}
	pcis, err := ghw.PCI(option.WithPCIDB(&db), option.WithDisableTools())
	if err != nil {
		return fmt.Errorf("could not retrieve PCI information: %+w", err)
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

		imc.msg.Inventory.PciDevices = append(imc.msg.Inventory.PciDevices, &info.PCIDevice{
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

	return nil
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

func (imc *inventoryMsgCreator) fillSerial() error {
	serials, err := ghw.Serial(option.WithDisableTools())
	if err != nil {
		return err
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
		imc.msg.Inventory.SerialDevices = append(imc.msg.Inventory.SerialDevices, &sp)
	}
	return nil
}

func (imc *inventoryMsgCreator) fillNetwork() error {
	netInfo, err := ghw.Network(option.WithDisableTools())
	if err != nil {
		return err
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
		imc.msg.Inventory.NetworkDevices = append(imc.msg.Inventory.NetworkDevices, &nd)
	}
	return nil
}

func (imc *inventoryMsgCreator) fillCAN() error {
	canInfo, err := can.New()
	if err != nil {
		return err
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
		imc.msg.Inventory.CanDevices = append(imc.msg.Inventory.CanDevices, &cd)
	}
	return nil
}

func (imc *inventoryMsgCreator) fillBIOS() error {
	biosInfo, err := ghw.BIOS(option.WithDisableTools())
	if err != nil {
		return err
	}
	imc.msg.Inventory.Bios = &info.BIOS{
		Vendor:     biosInfo.Vendor,
		Version:    biosInfo.Version,
		Attributes: map[string]string{"date": biosInfo.Date},
	}
	return nil
}

func (imc *inventoryMsgCreator) fillCPU() error {
	cpuInfo, err := ghw.CPU(option.WithDisableTools())
	if err != nil {
		return err
	}
	imc.msg.Inventory.CpuInfo = &info.CPUInfo{}
	for _, proc := range cpuInfo.Processors {
		for _, core := range proc.Cores {
			c := info.CPU{
				Model:  proc.Model,
				Vendor: proc.Vendor,
				Id:     uint32(core.ID),
			}
			imc.msg.Inventory.CpuInfo.Cpus = append(imc.msg.Inventory.CpuInfo.Cpus, &c)
		}
	}
	return nil
}

func (imc *inventoryMsgCreator) fillMemory() error {
	memInfo, err := ghw.Memory(option.WithDisableTools())
	if err != nil {
		return err
	}
	imc.msg.Inventory.TotalMemoryBytes = uint64(memInfo.TotalPhysicalBytes)
	return nil
}

func (imc *inventoryMsgCreator) fillStorage() error {
	blockInfo, err := ghw.Block(option.WithDisableTools())
	if err != nil {
		return err
	}
	imc.msg.Inventory.TotalStorageBytes = uint64(blockInfo.TotalPhysicalBytes)
	return nil
}

func (imc *inventoryMsgCreator) fillWatchdog() error {
	wdInfo, err := watchdog.New()
	if err != nil {
		return err
	}
	imc.msg.Inventory.WatchdogPresent = wdInfo.Present
	return nil
}

func (imc *inventoryMsgCreator) fillTPM() error {
	tpmInfo, err := tpm.New()
	if err != nil {
		return err
	}
	imc.msg.Inventory.Tpm = &info.TPM{
		Present:         tpmInfo.Present,
		Manufacturer:    tpmInfo.Manufacturer,
		FirmwareVersion: tpmInfo.FirmwareVersion,
		SpecVersion:     tpmInfo.SpecVersion,
	}
	return nil
}
