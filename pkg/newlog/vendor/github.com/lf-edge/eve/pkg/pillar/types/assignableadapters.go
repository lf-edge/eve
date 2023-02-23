// Copyright (c) 2018,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// IoBundles which can be assigned to applications/domUs.
// Derived from a description of the physical device plus knowledge
// about the level of granularity at which the hypervisor can do the
// assignment.

// The information is normally read from a hardware model specific
// file on boot.

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/disk"
)

type AssignableAdapters struct {
	Initialized  bool
	IoBundleList []IoBundle
}

// IoBundle has one entry per individual receptacle with a reference
// to a group name. Those sharing a group name needs to be assigned
// together.
type IoBundle struct {
	// Type
	//	Type of the IoBundle
	Type IoType
	// Phylabel
	//	Label on the outside of the enclosure
	Phylabel string

	// Logical Label assigned to the Adapter. Could match Phylabel
	// or could be a user-chosen string like "shopfloor"
	Logicallabel string

	// Assignment Group, is unique label that is applied across PhysicalIOs
	// Entire group can be assigned to application or nothing at all
	// If this is an empty string it means the IoBundle can not be assigned.
	AssignmentGroup string

	Usage zcommon.PhyIoMemberUsage

	// Cost is zero for the free ports; less desirable ports have higher numbers
	Cost uint8

	// The following set of I/O addresses and info/aliases are used to find
	// a device, and also to configure it.
	// XXX TBD: Add PciClass, PciVendor and PciDevice strings as well
	// for matching
	Ifname string // Matching for network PCI devices e.g., "eth1"

	// Attributes from controller but can also be set locally.
	PciLong string // Specific PCI bus address in Domain:Bus:Device.Function syntax
	// For non-PCI devices such as the ISA serial ports we have:
	// XXX: Why is IRQ a string?? Should convert it into Int.
	Irq     string // E.g., "5"
	Ioports string // E.g., "2f8-2ff"
	Serial  string // E.g., "/dev/ttyS1"
	UsbAddr string // E.g., "1:2.3"

	// Attributes Derived and assigned locally ( not from controller)

	Unique  string // From firmware_node symlink; used for debug checks
	MacAddr string // Set for networking adapters. XXX Note used for match.

	// UsedByUUID
	//	Application UUID ( Can be Dom0 too ) that owns the Bundle.
	//	For unassigned adapters, this is not set.
	UsedByUUID uuid.UUID

	// IsPciBack
	//	Is the IoBundle assigned to pciBack; means other bundles in the same group are also assigned
	//  If the device is managed by dom0, this is False.
	//  If the device is ( or to be ) managed by DomU, this is True
	IsPCIBack bool // Assigned to pciback
	IsPort    bool // Whole or part of the bundle is a zedrouter port
	// Do not put device under pciBack, instead keep it in dom0 as long as it is not assigned to any application.
	// In other words, this does not prevent assignments but keeps unassigned devices visible to EVE.
	KeepInHost bool
	Error      string
	ErrorTime  time.Time

	// Only used in PhyIoNetEthPF
	Vfs sriov.VFList
	// Only used in PhyIoNetEthVF
	VfParams VfInfo
}

// VfInfo Stores information about Virtual Function (VF)
type VfInfo struct {
	Index   uint8
	VlanID  uint16
	PFIface string
}

// Really a constant
var nilUUID = uuid.UUID{}

// For NVMEIsMountedByEVE
const sysfsPciDevices = "/sys/bus/pci/devices/"

var zfsManagerDir = "/run/zfsmanager"

// HasAdapterChanged - We store each Physical Adapter using the IoBundle object.
// Compares IoBundle with Physical adapter and returns if they are the Same
// or the Physical Adapter has changed.
func (ib IoBundle) HasAdapterChanged(log *base.LogObject, phyAdapter PhysicalIOAdapter) bool {
	if IoType(phyAdapter.Ptype) != ib.Type {
		log.Functionf("Type changed from %d to %d", ib.Type, phyAdapter.Ptype)
		return true
	}
	if phyAdapter.Phylabel != ib.Phylabel {
		log.Functionf("Name changed from %s to %s", ib.Phylabel, phyAdapter.Phylabel)
		return true
	}
	if phyAdapter.Phyaddr.PciLong != ib.PciLong {
		log.Functionf("PciLong changed from %s to %s",
			ib.PciLong, phyAdapter.Phyaddr.PciLong)
		return true
	}
	if phyAdapter.Phyaddr.Ifname != ib.Ifname {
		log.Functionf("Ifname changed from %s to %s",
			ib.Ifname, phyAdapter.Phyaddr.Ifname)
		return true
	}
	if phyAdapter.Phyaddr.Serial != ib.Serial {
		log.Functionf("Serial changed from %s to %s",
			ib.Serial, phyAdapter.Phyaddr.Serial)
		return true
	}
	if phyAdapter.Phyaddr.UsbAddr != ib.UsbAddr {
		log.Functionf("USB address changed from %s to %s",
			ib.UsbAddr, phyAdapter.Phyaddr.UsbAddr)
		return true
	}
	if phyAdapter.Phyaddr.Irq != ib.Irq {
		log.Functionf("Irq changed from %s to %s", ib.Irq, phyAdapter.Phyaddr.Irq)
		return true
	}
	if phyAdapter.Phyaddr.Ioports != ib.Ioports {
		log.Functionf("Ioports changed from %s to %s",
			ib.Ioports, phyAdapter.Phyaddr.Ioports)
		return true
	}
	if phyAdapter.Logicallabel != ib.Logicallabel {
		log.Functionf("Logicallabel changed from %s to %s",
			ib.Logicallabel, phyAdapter.Logicallabel)
		return true
	}
	if phyAdapter.Assigngrp != ib.AssignmentGroup {
		log.Functionf("AssignmentGroup changed from %s to %s",
			ib.AssignmentGroup, phyAdapter.Assigngrp)
		return true
	}
	if phyAdapter.Usage != ib.Usage {
		log.Functionf("Usage changed from %d to %d", ib.Usage, phyAdapter.Usage)
		return true
	}
	if !reflect.DeepEqual(phyAdapter.Vfs, ib.Vfs) {
		log.Functionf("Vfs changed from %v to %v", ib.Vfs, phyAdapter.Vfs)
		return true
	}
	return false
}

// IoBundleFromPhyAdapter - Creates an IoBundle from the given PhyAdapter
func IoBundleFromPhyAdapter(log *base.LogObject, phyAdapter PhysicalIOAdapter) *IoBundle {
	// XXX - We should really change IoType to type zcommon.PhyIoType
	ib := IoBundle{}
	ib.Type = IoType(phyAdapter.Ptype)
	ib.Phylabel = phyAdapter.Phylabel
	ib.Logicallabel = phyAdapter.Logicallabel
	ib.AssignmentGroup = phyAdapter.Assigngrp
	ib.Ifname = phyAdapter.Phyaddr.Ifname
	ib.PciLong = phyAdapter.Phyaddr.PciLong
	ib.UsbAddr = phyAdapter.Phyaddr.UsbAddr
	ib.Irq = phyAdapter.Phyaddr.Irq
	ib.Ioports = phyAdapter.Phyaddr.Ioports
	ib.Serial = phyAdapter.Phyaddr.Serial
	ib.Usage = phyAdapter.Usage
	// We're making deep copy
	ib.Vfs.Data = make([]sriov.EthVF, len(phyAdapter.Vfs.Data))
	copy(ib.Vfs.Data, phyAdapter.Vfs.Data)
	ib.Vfs.Count = phyAdapter.Vfs.Count
	// Guard against models without ifname for network adapters
	if ib.Type.IsNet() && ib.Ifname == "" {
		log.Warnf("phyAdapter IsNet without ifname: phylabel %s logicallabel %s",
			ib.Phylabel, ib.Logicallabel)
		if ib.Logicallabel != "" {
			ib.Ifname = ib.Logicallabel
		} else {
			ib.Ifname = ib.Phylabel
		}
	}
	return &ib
}

// Must match definition of PhyIoType in devmodel.proto which is an strict
// subset of the values in ZCioType in devmodel.proto
type IoType uint8

const (
	IoNop     IoType = 0
	IoNetEth  IoType = 1
	IoUSB     IoType = 2
	IoCom     IoType = 3
	IoAudio   IoType = 4
	IoNetWLAN IoType = 5
	IoNetWWAN IoType = 6
	IoHDMI    IoType = 7
	// enum 8 is reserved for backward compatibility with controller API
	IoNVMEStorage IoType = 9
	IoSATAStorage IoType = 10
	IoNetEthPF    IoType = 11
	IoNetEthVF    IoType = 12
	IoNVME        IoType = 255
	IoOther       IoType = 255
)

// IsNet checks if the type is any of the networking types.
func (ioType IoType) IsNet() bool {
	switch ioType {
	case IoNetEth, IoNetWLAN, IoNetWWAN, IoNetEthPF, IoNetEthVF:
		return true
	default:
		return false
	}
}

// Key is used with pubsub
func (aa AssignableAdapters) Key() string {
	return "global"
}

// LogCreate :
func (aa AssignableAdapters) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AssignableAdaptersLogType, "",
		nilUUID, aa.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Assignable adapters create")
}

// LogModify :
func (aa AssignableAdapters) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AssignableAdaptersLogType, "",
		nilUUID, aa.LogKey())

	oldAa, ok := old.(AssignableAdapters)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AssignableAdapters type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldAa, aa)).
		Noticef("Assignable adapters modify")
}

// LogDelete :
func (aa AssignableAdapters) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AssignableAdaptersLogType, "",
		nilUUID, aa.LogKey())
	logObject.Noticef("Assignable adapters delete")

	base.DeleteLogObject(logBase, aa.LogKey())
}

// LogKey :
func (aa AssignableAdapters) LogKey() string {
	return string(base.AssignableAdaptersLogType) + "-" + aa.Key()
}

// AddOrUpdateIoBundle - Add an Io bundle to AA. If the bundle already exists,
// the function updates it, while preserving the most specific information.
// The information we preserve are of two kinds:
// - IsPort/IsPCIBack/UsedByUUID/KeepInHost which come from interaction with nim
// - PciLong, UsbAddr, etc which come from controller but might be filled in by domainmgr
// - Unique/MacAddr which come from the PhysicalIoAdapter
func (aa *AssignableAdapters) AddOrUpdateIoBundle(log *base.LogObject, ib IoBundle) {
	curIbPtr := aa.LookupIoBundlePhylabel(ib.Phylabel)
	if curIbPtr == nil {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) New bundle",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
		aa.IoBundleList = append(aa.IoBundleList, ib)
		return
	}
	log.Functionf("AddOrUpdateIoBundle(%d %s %s) Update bundle; diff %+v",
		ib.Type, ib.Phylabel, ib.AssignmentGroup,
		cmp.Diff(*curIbPtr, ib))

	// We preserve the most specific
	if curIbPtr.UsedByUUID != nilUUID {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve UsedByUUID %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.UsedByUUID)
		ib.UsedByUUID = curIbPtr.UsedByUUID
	}
	if curIbPtr.IsPort {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve IsPort %t",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.IsPort)
		ib.IsPort = curIbPtr.IsPort
	}
	if curIbPtr.IsPCIBack {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve IsPCIBack %t",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.IsPCIBack)
		ib.IsPCIBack = curIbPtr.IsPCIBack
	}
	if curIbPtr.KeepInHost {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve KeepInHost %t",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.KeepInHost)
		ib.KeepInHost = curIbPtr.KeepInHost
	}
	if curIbPtr.PciLong != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve PciLong %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.PciLong)
		ib.PciLong = curIbPtr.PciLong
	}
	if curIbPtr.Irq != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve Irq %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.Irq)
		ib.Irq = curIbPtr.Irq
	}
	if curIbPtr.Ioports != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve Ioports %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.Ioports)
		ib.Ioports = curIbPtr.Ioports
	}
	if curIbPtr.Serial != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve Serial %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.Serial)
		ib.Serial = curIbPtr.Serial
	}
	if curIbPtr.UsbAddr != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve UsbAddr %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.UsbAddr)
		ib.UsbAddr = curIbPtr.UsbAddr
	}
	if curIbPtr.Unique != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve Unique %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.Unique)
		ib.Unique = curIbPtr.Unique
	}
	if curIbPtr.MacAddr != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve MacAddr %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.MacAddr)
		ib.MacAddr = curIbPtr.MacAddr
	}
	*curIbPtr = ib
}

// LookupIoBundlePhylabel returns nil if not found
func (aa *AssignableAdapters) LookupIoBundlePhylabel(phylabel string) *IoBundle {
	for i, b := range aa.IoBundleList {
		if strings.EqualFold(b.Phylabel, phylabel) {
			return &aa.IoBundleList[i]
		}
	}
	return nil
}

// LookupIoBundleLogicallabel returns nil if not found
func (aa *AssignableAdapters) LookupIoBundleLogicallabel(label string) *IoBundle {
	for i, b := range aa.IoBundleList {
		if strings.EqualFold(b.Logicallabel, label) {
			return &aa.IoBundleList[i]
		}
	}
	return nil
}

// LookupIoBundleGroup returns an empty slice if not found
// Returns pointers into aa
func (aa *AssignableAdapters) LookupIoBundleGroup(group string) []*IoBundle {

	var list []*IoBundle
	if group == "" {
		return list
	}
	for i, b := range aa.IoBundleList {
		if b.AssignmentGroup == "" {
			continue
		}
		if strings.EqualFold(b.AssignmentGroup, group) {
			list = append(list, &aa.IoBundleList[i])
		}
	}
	return list
}

// LookupIoBundleAny returns an empty slice if not found; name can be
// a member phylabel, logicallabel, or a group
// Returns pointers into aa
func (aa *AssignableAdapters) LookupIoBundleAny(name string) []*IoBundle {

	list := aa.LookupIoBundleGroup(name)
	if len(list) != 0 {
		return list
	}
	ib := aa.LookupIoBundlePhylabel(name)
	if ib == nil {
		ib = aa.LookupIoBundleLogicallabel(name)
		if ib == nil {
			return list
		}
	}
	if ib.AssignmentGroup == "" {
		// Singleton
		list = append(list, ib)
		return list
	}
	return aa.LookupIoBundleGroup(ib.AssignmentGroup)
}

// LookupIoBundleIfName checks for IoNet* types and a ifname match
func (aa *AssignableAdapters) LookupIoBundleIfName(ifname string) *IoBundle {
	for i, b := range aa.IoBundleList {
		if b.Type.IsNet() && strings.EqualFold(b.Ifname, ifname) {
			return &aa.IoBundleList[i]
		}
	}
	return nil
}

// CheckBadAssignmentGroups sets ib.Error/ErrorTime if two IoBundles in different
// assignment groups have the same PCI ID (ignoring the PCI function number)
// Returns true if there was a modification so caller can publish.
func (aa *AssignableAdapters) CheckBadAssignmentGroups(log *base.LogObject, PCISameController func(string, string) bool) bool {
	changed := false
	for i := range aa.IoBundleList {
		ib := &aa.IoBundleList[i]
		for _, ib2 := range aa.IoBundleList {
			if ib2.Phylabel == ib.Phylabel {
				continue
			}
			if ib.AssignmentGroup == "" || ib2.AssignmentGroup == ib.AssignmentGroup {
				continue
			}
			if PCISameController != nil && PCISameController(ib.PciLong, ib2.PciLong) {
				err := fmt.Errorf("CheckBadAssignmentGroup: %s same PCI controller as %s; pci long %s vs %s",
					ib2.Ifname, ib.Ifname, ib2.PciLong, ib.PciLong)
				log.Error(err)
				ib.Error = err.Error()
				ib.ErrorTime = time.Now()
				changed = true
			}
		}
	}
	return changed
}

// ExpandControllers expands the list to include other PCI functions on the same PCI controller
// (while ignoring the function number). The output might have duplicate entries.
func (aa *AssignableAdapters) ExpandControllers(log *base.LogObject, list []*IoBundle, PCISameController func(string, string) bool) []*IoBundle {
	var elist []*IoBundle

	elist = list
	for _, ib := range list {
		for i := range aa.IoBundleList {
			ib2 := &aa.IoBundleList[i]
			already := false
			for _, ib3 := range elist {
				if ib2.Phylabel == ib3.Phylabel {
					already = true
					break
				}
			}
			if already {
				log.Tracef("ExpandController already %s long %s",
					ib2.Phylabel, ib2.PciLong)
				continue
			}
			if PCISameController != nil && PCISameController(ib.PciLong, ib2.PciLong) {
				log.Warnf("ExpandController found %s matching %s; long %s long %s",
					ib2.Phylabel, ib.Phylabel, ib2.PciLong, ib.PciLong)
				elist = append(elist, ib2)
			}
		}
	}
	return elist
}

func getDeviceNameFromPciID(pciID string) (string, error) {
	// e.g., ls /sys/bus/pci/devices/<pciID>/nvme/
	//  -> nvme0
	deviceName := ""
	nvmePath, err := os.ReadDir(sysfsPciDevices + pciID + "/nvme")
	if err != nil {
		return "", err
	}
	for _, file := range nvmePath {
		deviceName = file.Name()
	}
	return deviceName, nil
}

// NVMEIsUsed checks if an NVME device is in a ZFS pool or mounted
func NVMEIsUsed(log *base.LogObject, zfsPoolStatusMap map[string]interface{}, pciID string) bool {
	if _, err := os.Stat(zfsManagerDir); os.IsNotExist(err) {
		log.Noticef("ZFS manager is not initialized yet")
		return true
	}

	// Get /dev/nvmX from pciID
	deviceName, err := getDeviceNameFromPciID(pciID)
	if err != nil {
		log.Errorf("Can't determine nvme device name for %s (%v)", pciID, err)
		return false
	}

	// Checking zfs pools
	for _, el := range zfsPoolStatusMap {
		zfsPoolStatus, ok := el.(ZFSPoolStatus)
		if !ok {
			log.Errorf("Could not convert to ZFSPoolStatus")
			continue
		}
		for _, disk := range zfsPoolStatus.Disks {
			if strings.Contains(disk.DiskName.LogicalName, deviceName) {
				return true
			}
		}
	}

	// Checking mounted partitions
	partitions, err := disk.Partitions(true)
	if err != nil {
		log.Errorf("Could not find mounted partitions error:%+v", err)
		return false
	}

	for _, partition := range partitions {
		if strings.Contains(partition.Device, deviceName) {
			return true
		}
	}

	return false
}
