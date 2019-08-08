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
	// Name
	//	Short hand name such as "COM1".
	//	Used in the API to specify that a adapter should
	//	be assigned to an application.
	Name string

	// Assignment Group, is unique label that is applied across PhysicalIOs
	// Entire group can be assigned to application or nothing at all
	AssignmentGroup string

	// UsedByUUID
	//	Application UUID ( Can be Dom0 too ) that owns the Bundle.
	//	For unassigned adapters, this is not set.
	UsedByUUID uuid.UUID

	// The following set of I/O addresses and info/aliases are used to find
	// a device, and also to configure it.
	// XXX TBD: Add PciClass, PciVendor and PciDevice strings as well
	// for matching
	Ifname  string // Matching for network PCI devices e.g., "eth1"
	PciLong string // Specific PCI bus address in Domain:Bus:Device.Funcion syntax
	// For non-PCI devices such as the ISA serial ports we have:
	Irq     string // E.g., "5"
	Ioports string // E.g., "2f8-2ff"
	Serial  string // E.g., "/dev/ttyS1"

	Unique  string // From firmware_node symlink; used for debug checks
	MacAddr string // Set for networking adapters. XXX Note used for match.

	// IsPciBack
	//	Is the IoBundle assigned to pciBack; means other bundles in the same group are also assigned
	//  If the device is managed by dom0, this is False.
	//  If the device is ( or to be ) managed by DomU, this is True
	IsPCIBack bool // Assigned to pciback
	IsPort    bool // Whole or part of the bundle is a zedrouter port
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

// LookupIoBundle returns nil if not found
func (aa *AssignableAdapters) LookupIoBundle(ioType IoType, name string) *IoBundle {
	for i, b := range aa.IoBundleList {
		// XXX the new enums are sent as zero by the controller
		// hence temporary workaround
		if (ioType == 0 || b.Type == ioType) && strings.EqualFold(b.Name, name) {
			if ioType == 0 {
				log.Warnf("XXX Matching name %s for ioType 0",
					b.Name)
			}
			return &aa.IoBundleList[i]
		}
	}
	return nil
}

// LookupIoBundleGroup returns an empty slice if not found
// Returns pointers into aa
func (aa *AssignableAdapters) LookupIoBundleGroup(ioType IoType, group string) []*IoBundle {

	var list []*IoBundle
	for i, b := range aa.IoBundleList {
		if b.AssignmentGroup == "" {
			continue
		}
		// XXX the new enums are sent as zero by the controller
		// hence temporary workaround
		if (ioType == 0 || b.Type == ioType) && strings.EqualFold(b.AssignmentGroup, group) {
			if ioType == 0 {
				log.Warnf("XXX Matching group %s for ioType 0",
					b.AssignmentGroup)
			}
			list = append(list, &aa.IoBundleList[i])
		}
	}
	return list
}

// LookupIoBundleNet checks for IoNet*
func (aa *AssignableAdapters) LookupIoBundleNet(name string) *IoBundle {
	for i, b := range aa.IoBundleList {
		if b.Type.IsNet() && strings.EqualFold(b.Name, name) {
			return &aa.IoBundleList[i]
		}
	}
	return nil
}
