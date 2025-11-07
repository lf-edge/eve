// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jaypipes/ghw"
	"github.com/jaypipes/ghw/pkg/option"
	"github.com/jaypipes/ghw/pkg/pci/address"
	"github.com/jaypipes/pcidb"
	pcitypes "github.com/jaypipes/pcidb/types"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	agentName = "inventory"
	// Time limits for event loop handlers
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
)

type boardingStatusType uint32

const (
	unknownStatus boardingStatusType = iota
	onboardedStatus
	offboardStatus
)

type inventoryReporter struct {
	dns types.DeviceNetworkStatus

	needUpload     atomic.Bool
	boardingStatus atomic.Uint32

	uploading sync.Mutex
}

type inventoryMsgCreator struct {
	msg *info.ZInfoHardware
}

func AddInventoryInfo(msg *info.ZInfoHardware) error {
	imc := &inventoryMsgCreator{}

	imc.msg = msg

	errs := make(map[string]error)
	fmt.Fprintf(os.Stderr, "BBBBB FillPCI\n")
	errs["PCI"] = imc.fillPCI()
	fmt.Fprintf(os.Stderr, "BBBBB FillUSB\n")
	errs["USB"] = imc.fillUSB()
	fmt.Fprintf(os.Stderr, "BBBBB FillUSB done\n")

	var errStr string
	for key, err := range errs {
		if err != nil {
			errStr += fmt.Sprintf("failed to query for %s: %v", key, err)
		}
	}

	var err error
	if len(errStr) > 0 {
		err = fmt.Errorf("querying for hardware failed: %s", errStr)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "BBBBB AddInventoryInfo err: %+v\n", err)
	}

	var buf bytes.Buffer

	args := []string{"/usr/bin/spec.sh", "-v", "-u"}

	env := []string{}

	taskID := fmt.Sprintf("%d", time.Now().Unix())
	err = containerd.RunInDebugContainer(context.Background(), taskID, &buf, args, env, 15*time.Minute)

	imc.msg.SpecSh = buf.String()

	return err
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
	usbs, err := ghw.USB()
	if err != nil {
		return err
	}

	for _, usb := range usbs.USBs {
		vendorId := pciHexToUint32(usb.VendorID)
		productId := pciHexToUint32(usb.ProductID)
		busnum := pciHexToUint32(usb.Busnum)
		devnum := pciHexToUint32(usb.Devnum)
		parentBusnum := pciHexToUint32(usb.ParentBusnum)
		parentDevnum := pciHexToUint32(usb.ParentDevnum)

		ud := info.USBDevice{
			PciParent: stringToPCIAddress(usb.PCIAddress),
			UsbParent: &info.USBBusDevnum{
				Bus:    parentBusnum,
				Devnum: parentDevnum,
			},
			VendorId:  vendorId,
			ProductId: productId,
			BusDevnum: &info.USBBusDevnum{
				Bus:    busnum,
				Devnum: devnum,
			},
		}
		imc.msg.UsbDevices = append(imc.msg.UsbDevices, &ud)
	}

	return nil
}

func (imc *inventoryMsgCreator) fillPCI() error {
	db := pcidb.PCIDB{
		Classes:  map[string]*pcitypes.Class{},
		Vendors:  map[string]*pcitypes.Vendor{},
		Products: map[string]*pcitypes.Product{},
	}
	pcis, err := ghw.PCI(option.WithPCIDB(&db))
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

		imc.msg.PciDevices = append(imc.msg.PciDevices, &info.PCIDevice{
			ParentPciDeviceAddress: stringToPCIAddress(pci.ParentAddress),
			Driver:                 pci.Driver,
			Address:                stringToPCIAddress(pci.Address),
			VendorId:               vendorId,
			DeviceId:               productId,
			Revision:               revisionId,
			SubsystemId:            subsystemId,
			ClassId:                classId,
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
