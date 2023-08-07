// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// PhysicalIoAdapters on the device given by the cloud.
//  These are translated to AssignableAdapters

import (
	"github.com/google/go-cmp/cmp"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
)

// PhysicalAddress - Structure that represents various attributes related
// to the addressing of the Adapter
type PhysicalAddress struct {
	PciLong string
	Ifname  string
	Serial  string
	Irq     string
	Ioports string
	UsbAddr string
	// unknownType - If a type in config is unknown, store it here.
	UnknownType string
}

// PhyIOUsagePolicy - Usage policy for the Adapter
// This is constructed from api/proto/config/devmodel.proto PhyIOUsagePolicy
// Keep the two structures consistent
type PhyIOUsagePolicy struct {
	// FreeUplink is needed while we transition to just a Cost integer
	FreeUplink bool
}

// PhysicalIOAdapter - Object used to store Adapter configuration (L1)
// from controller for each Adapter.
type PhysicalIOAdapter struct {
	Ptype        zcommon.PhyIoType // Type of IO Device
	Phylabel     string            // Label printed on the enclosure
	Phyaddr      PhysicalAddress
	Logicallabel string // Label assigned by model creator
	Assigngrp    string
	Usage        zcommon.PhyIoMemberUsage
	UsagePolicy  PhyIOUsagePolicy
	// FIXME: cbattr - This needs to be thought through to be made into
	//  a structure OR may be even various attributes in PhysicalIO structure
	// itself.
	// map <string, string> cbattr = 8;
	Vfs sriov.VFList // Used only for Physical Functions PFs
}

// PhysicalIOAdapterList - List of Physical Adapters to be used on the
// device by EVE from the controller
type PhysicalIOAdapterList struct {
	Initialized bool
	AdapterList []PhysicalIOAdapter
}

// Key returns the key for pubsub
func (ioAdapterList PhysicalIOAdapterList) Key() string {
	return "global"
}

// LogCreate :
func (ioAdapterList PhysicalIOAdapterList) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.PhysicalIOAdapterListLogType, "",
		nilUUID, ioAdapterList.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Onboarding ioAdapterList create")
}

// LogModify :
func (ioAdapterList PhysicalIOAdapterList) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.PhysicalIOAdapterListLogType, "",
		nilUUID, ioAdapterList.LogKey())

	oldIoAdapterList, ok := old.(PhysicalIOAdapterList)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of PhysicalIOAdapterList type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldIoAdapterList, ioAdapterList)).
		Noticef("Onboarding ioAdapterList modify")
}

// LogDelete :
func (ioAdapterList PhysicalIOAdapterList) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.PhysicalIOAdapterListLogType, "",
		nilUUID, ioAdapterList.LogKey())
	logObject.Noticef("Onboarding ioAdapterList delete")

	base.DeleteLogObject(logBase, ioAdapterList.LogKey())
}

// LogKey :
func (ioAdapterList PhysicalIOAdapterList) LogKey() string {
	return string(base.PhysicalIOAdapterListLogType) + "-" + ioAdapterList.Key()
}

// LookupAdapter - look up an Adapter by its phylabel
func (ioAdapterList *PhysicalIOAdapterList) LookupAdapter(
	phylabel string) *PhysicalIOAdapter {
	for indx := range ioAdapterList.AdapterList {
		adapter := &ioAdapterList.AdapterList[indx]
		if adapter.Phylabel == phylabel {
			return adapter
		}
	}
	return nil
}
