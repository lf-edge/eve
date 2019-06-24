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

	"github.com/satori/go.uuid"
)

type AssignableAdapters struct {
	Initialized  bool
	IoBundleList []IoBundle
}

type IoBundle struct {
	// Type
	//	Type of the IoBundle
	Type IoType
	// Name
	//	Short hand name such as "com".
	//  xxx - Any description is where this is used? How this is to be set etc??
	Name string // Short hand name such as "com"
	// Members
	//	List of members ( names )
	//  XXX - Should this be a map?? With list, we cannot detect duplicate members
	//		In most cases, we probably do lookups on members - they become easy with
	//		Maps too.
	Members []string // E.g., "com1", "com2"
	// UsedByUUID
	//	Application UUID ( Can be Dom0 too ) that owns the Bundle.
	//	For unassigned adapters, this is not set.
	UsedByUUID uuid.UUID

	// Local information not reported to cloud
	Lookup   bool   // Look up name to find PCI
	PciLong  string // If adapter on some bus and not Eth
	PciShort string // If pci adapter and not Eth
	XenCfg   string // If template for the bundle
	Unique   string // From firmware_node symlink; used for debug checks

	// For each member we have these with the same indicies. Only used when
	// Lookup is set.
	// XXX a Member struct would make more sense but need compatibility with existing json
	MPciLong  []string // If adapter on some bus
	MPciShort []string // If pci adapter
	MUnique   []string // From firmware_node symlink; used for debug checks
	MMacAddr  []string // Set for networking adapters

	// IsPciBack
	//	Is the IoBundle assigned to pciBack; means all members are assigned
	//  If the device is managed by dom0, this is False.
	//  If the device is ( or to be ) managed by DomU, this is True
	IsPCIBack bool // Assigned to pciback
	IsPort    bool // Whole or part of the bundle is a zedrouter port

	// DeviceExists
	//	This is to indicate if the device exists in the system
	//  Currently, there are many checks using pciShort to see
	//  if the device exists. This attribute is to abstract it out.
	// DeviceExists bool

}

// Must match definition of PhyIoType in devmodel.proto which is an strict
// subset of the values in ZCioType in devmodel.proto
type IoType uint8

const (
	IoNop     IoType = 0
	IoNetEth  IoType = 1
	IoEth     IoType = 1
	IoUSB     IoType = 2
	IoCom     IoType = 3
	IoAudio   IoType = 4
	IoNetWLAN IoType = 5
	IoNetWWAN IoType = 6
	IoHDMI    IoType = 7
	IoOther   IoType = 255
)

// Returns nil if not found
func LookupIoBundle(aa *AssignableAdapters, ioType IoType, name string) *IoBundle {
	for i, b := range aa.IoBundleList {
		if b.Type == ioType && strings.EqualFold(b.Name, name) {
			return &aa.IoBundleList[i]
		}
	}
	return nil
}

func (aa *AssignableAdapters) LookupIoBundleForMember(
	ioType IoType, memberName string) *IoBundle {
	for i, b := range aa.IoBundleList {
		if b.Type != ioType {
			continue
		}
		for _, member := range b.Members {
			if strings.EqualFold(member, memberName) {
				return &aa.IoBundleList[i]
			}
		}
	}
	return nil
}

func (aa *AssignableAdapters) getIoBundleOrBundleForMemberByName(
	ioType IoType, adapter string) *IoBundle {
	ib := LookupIoBundle(aa, ioType, adapter)
	if ib == nil {
		// Check if adapter is a member of iobundle
		ib = aa.LookupIoBundleForMember(ioType, adapter)
	}
	return ib
}
