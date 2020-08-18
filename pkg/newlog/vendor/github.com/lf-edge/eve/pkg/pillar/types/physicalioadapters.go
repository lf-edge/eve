// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// PhysicalIoAdapters on the device given by the cloud.
//  These are translated to AssignableAdapters

import (
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
)

// PhysicalAddress - Structure that represents various attributes related
// to the addressing of the Adapter
type PhysicalAddress struct {
	PciLong string
	Ifname  string
	Serial  string
	Irq     string
	Ioports string
	// unknownType - If a type in config is unknown, store it here.
	UnknownType string
}

// PhyIOUsagePolicy - Usage policy for the Adapter
// This is constructed from api/proto/config/devmodel.proto PhyIOUsagePolicy
// Keep the two structures consistent
type PhyIOUsagePolicy struct {
	FreeUplink bool
	// FallBackPriority
	//  0 is the highest priority.
	//  Lower priority interfaces are used only when NONE of the higher
	//  priority interfaces are up.
	//  For example:
	//      First use all interfaces with priority 0
	//      if no priority 0 interfaces, use interfaces with priority 1
	//      if no priority 1 interfaces, use interfaces with priority 2
	//      and so on..
	FallBackPriority uint32
}

// PhysicalIOAdapter - Object used to store Adapter configuration (L1)
// from controller for each Adapter.
type PhysicalIOAdapter struct {
	Ptype        zcommon.PhyIoType // Type of IO Device
	Phylabel     string            // Label put on the box
	Phyaddr      PhysicalAddress
	Logicallabel string
	Assigngrp    string
	Usage        zcommon.PhyIoMemberUsage
	UsagePolicy  PhyIOUsagePolicy
	// FIXME: cbattr - This needs to be thought through to be made into
	//  a structure OR may be even various attributes in PhysicalIO structure
	// itself.
	// map <string, string> cbattr = 8;
}

// PhysicalIOAdapterList - List of Physical Adapters to be used on the
// device by EVE from the controller
type PhysicalIOAdapterList struct {
	Initialized bool
	AdapterList []PhysicalIOAdapter
}

// LookupAdapter - look up an Adapter by its name ( phylabel )
func (ioAdapterList *PhysicalIOAdapterList) LookupAdapter(
	name string) *PhysicalIOAdapter {
	for indx := range ioAdapterList.AdapterList {
		adapter := &ioAdapterList.AdapterList[indx]
		if adapter.Phylabel == name {
			return adapter
		}
	}
	return nil
}
