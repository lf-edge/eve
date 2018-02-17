// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package types

// IoBundles which can be assigned to applications/domUs.
// Derived from a description of the physical device plus knowledge
// about the level of granularity at which the hypervisor can do the
// assignment.

// The information is normally read from a hardware model specific
// file on boot.

import (
	"github.com/satori/go.uuid"
	"strings"
)

type AssignableAdapters struct {
	IoBundleList []IoBundle
}

type IoBundle struct {
	Type       IoType
	Name       string    // Short hand name such as "com"
	Members    []string  // E.g., "com1", "com2"
	UsedByUUID uuid.UUID // UUID for application

	// Local information not reported to cloud
	Lookup   bool   // Look up name to find PCI
	PciLong  string // If adapter on some bus
	PciShort string // If pci adapter
	XenCfg   string // If template for the bundle
}

// Should match definition in appconfig.proto
type IoType uint8

const (
	IoNop   IoType = 0
	IoEth   IoType = 1
	IoUSB   IoType = 2
	IoCom   IoType = 3
	IoOther IoType = 255
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
