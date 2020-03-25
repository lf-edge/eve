// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// IoBundles which can be assigned to applications/domUs.
// Derived from a description of the physical device plus knowledge
// about the level of granularity at which the hypervisor can do the
// assignment.

// The information is normally read from a hardware model specific
// file on boot.

import (
	"strings"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
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
	//	Short hand name such as "COM1".
	//	Used in the API to specify that a adapter should
	//	be assigned to an application.
	Phylabel string

	// Logical Label assigned to the Adapter
	Logicallabel string

	// Assignment Group, is unique label that is applied across PhysicalIOs
	// Entire group can be assigned to application or nothing at all
	AssignmentGroup string

	Usage zconfig.PhyIoMemberUsage

	// FreeUplink - The network connection through this adapter is Free.
	// Prefer this adapter for connecting to the cloud.
	FreeUplink bool

	// The following set of I/O addresses and info/aliases are used to find
	// a device, and also to configure it.
	// XXX TBD: Add PciClass, PciVendor and PciDevice strings as well
	// for matching
	Ifname  string // Matching for network PCI devices e.g., "eth1"
	PciLong string // Specific PCI bus address in Domain:Bus:Device.Funcion syntax
	// For non-PCI devices such as the ISA serial ports we have:
	// XXX: Why is IRQ a string?? Should convert it into Int.
	Irq     string // E.g., "5"
	Ioports string // E.g., "2f8-2ff"
	Serial  string // E.g., "/dev/ttyS1"

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
}

// Really a constant
var nilUUID = uuid.UUID{}

// HasAdapterChanged - We store each Physical Adapter using the IoBundle object.
// Compares IoBundle with Physical adapter and returns if they are the Same
// or the Physical Adapter has changed.
func (ib IoBundle) HasAdapterChanged(phyAdapter PhysicalIOAdapter) bool {
	if IoType(phyAdapter.Ptype) != ib.Type {
		log.Infof("Type changed from %d to %d", ib.Type, phyAdapter.Ptype)
		return true
	}
	if phyAdapter.Phylabel != ib.Phylabel {
		log.Infof("Name changed from %s to %s", ib.Phylabel, phyAdapter.Phylabel)
		return true
	}
	if phyAdapter.Phyaddr.PciLong != ib.PciLong {
		log.Infof("PciLong changed from %s to %s",
			ib.PciLong, phyAdapter.Phyaddr.PciLong)
		return true
	}
	if phyAdapter.Phyaddr.Ifname != ib.Ifname {
		log.Infof("Ifname changed from %s to %s",
			ib.Ifname, phyAdapter.Phyaddr.Ifname)
		return true
	}
	if phyAdapter.Phyaddr.Serial != ib.Serial {
		log.Infof("Serial changed from %s to %s",
			ib.Serial, phyAdapter.Phyaddr.Serial)
		return true
	}
	if phyAdapter.Phyaddr.Irq != ib.Irq {
		log.Infof("Irq changed from %s to %s", ib.Irq, phyAdapter.Phyaddr.Irq)
		return true
	}
	if phyAdapter.Phyaddr.Ioports != ib.Ioports {
		log.Infof("Ioports changed from %s to %s",
			ib.Ioports, phyAdapter.Phyaddr.Ioports)
		return true
	}
	if phyAdapter.Logicallabel != ib.Logicallabel {
		log.Infof("Logicallabel changed from %s to %s",
			ib.Logicallabel, phyAdapter.Logicallabel)
		return true
	}
	if phyAdapter.Assigngrp != ib.AssignmentGroup {
		log.Infof("Ifname changed from %s to %s",
			ib.AssignmentGroup, phyAdapter.Assigngrp)
		return true
	}
	if phyAdapter.Usage != ib.Usage {
		log.Infof("Usage changed from %d to %d", ib.Usage, phyAdapter.Usage)
		return true
	}
	if phyAdapter.UsagePolicy.FreeUplink != ib.FreeUplink {
		log.Infof("FreeUplink changed from %t to %t",
			ib.FreeUplink, phyAdapter.UsagePolicy.FreeUplink)
		return true
	}
	return false
}

// IoBundleFromPhyAdapter - Creates an IoBundle from the given PhyAdapter
func IoBundleFromPhyAdapter(phyAdapter PhysicalIOAdapter) *IoBundle {
	// XXX - We should really change IoType to type zconfig.PhyIoType
	ib := IoBundle{}
	ib.Type = IoType(phyAdapter.Ptype)
	ib.Phylabel = phyAdapter.Phylabel
	ib.Logicallabel = phyAdapter.Logicallabel
	ib.AssignmentGroup = phyAdapter.Assigngrp
	ib.Ifname = phyAdapter.Phyaddr.Ifname
	ib.PciLong = phyAdapter.Phyaddr.PciLong
	ib.Irq = phyAdapter.Phyaddr.Irq
	ib.Ioports = phyAdapter.Phyaddr.Ioports
	ib.Serial = phyAdapter.Phyaddr.Serial
	ib.Usage = phyAdapter.Usage
	ib.FreeUplink = phyAdapter.UsagePolicy.FreeUplink
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
	IoOther   IoType = 255
)

// IsNet checks if the type is any of the networking types.
func (ioType IoType) IsNet() bool {
	switch ioType {
	case IoNetEth, IoNetWLAN, IoNetWWAN:
		return true
	default:
		return false
	}
}

// AddOrUpdateIoBundle - Add an Io bundle to AA. If the bundle already exists,
// the function updates it, while preserving the most specific information.
// The information we preserve are of two kinds:
// - IsPort/IsPCIBack/UsedByUUID which come from interaction with nim
// - Unique/MacAddr which come from the PhysicalIoAdapter
func (aa *AssignableAdapters) AddOrUpdateIoBundle(ib IoBundle) {
	curIbPtr := aa.LookupIoBundlePhylabel(ib.Phylabel)
	if curIbPtr == nil {
		log.Infof("AddOrUpdateIoBundle(%d %s %s) New bundle",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
		aa.IoBundleList = append(aa.IoBundleList, ib)
		return
	}
	log.Infof("AddOrUpdateIoBundle(%d %s %s) Update bundle; diff %+v",
		ib.Type, ib.Phylabel, ib.AssignmentGroup,
		cmp.Diff(*curIbPtr, ib))

	// We preserve the most specific
	if curIbPtr.UsedByUUID != nilUUID {
		log.Infof("AddOrUpdateIoBundle(%d %s %s) preserve UsedByUUID %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.UsedByUUID)
		ib.UsedByUUID = curIbPtr.UsedByUUID
	}
	if curIbPtr.IsPort {
		log.Infof("AddOrUpdateIoBundle(%d %s %s) preserve IsPort %t",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.IsPort)
		ib.IsPort = curIbPtr.IsPort
	}
	if curIbPtr.IsPCIBack {
		log.Infof("AddOrUpdateIoBundle(%d %s %s) preserve IsPCIBack %t",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.IsPCIBack)
		ib.IsPCIBack = curIbPtr.IsPCIBack
	}
	if curIbPtr.Unique != "" {
		log.Infof("AddOrUpdateIoBundle(%d %s %s) preserve Unique %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.Unique)
		ib.Unique = curIbPtr.Unique
	}
	if curIbPtr.MacAddr != "" {
		log.Infof("AddOrUpdateIoBundle(%d %s %s) preserve MacAddr %v",
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
// a member phylabel or a group
// Returns pointers into aa
func (aa *AssignableAdapters) LookupIoBundleAny(name string) []*IoBundle {

	list := aa.LookupIoBundleGroup(name)
	if len(list) != 0 {
		return list
	}
	ib := aa.LookupIoBundlePhylabel(name)
	if ib == nil {
		return list
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
