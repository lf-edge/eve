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
	"reflect"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	uuid "github.com/satori/go.uuid"
)

type AssignableAdapters struct {
	Initialized  bool       `json:",omitempty"`
	IoBundleList []IoBundle `json:",omitempty"`
}

type ioBundleErrorBase struct {
	ErrStr  string `json:",omitempty"`
	TypeStr string `json:",omitempty"`
	// Warning marks an advisory entry: a model inconsistency EVE worked around.
	// Reported to the controller as a warning, not an error.
	Warning bool `json:",omitempty"`
	// GroupScoped marks an entry describing the whole assignment group (e.g. a
	// collision). Stored on every member but reported once, without attribution.
	GroupScoped bool `json:",omitempty"`
}

func (i ioBundleErrorBase) Error() string {
	return i.ErrStr
}

// IOBundleError is an error stored in IoBundles that can be marshalled
type IOBundleError struct {
	Errors      []ioBundleErrorBase `json:",omitempty"`
	TimeOfError time.Time           `json:",omitempty"`
}

// ErrorTime returns the time of the last error added
func (iobe *IOBundleError) ErrorTime() time.Time {
	return iobe.TimeOfError
}

func (iobe *IOBundleError) String() string {
	if len(iobe.Errors) == 0 {
		return ""
	}
	errorStrings := make([]string, 0, len(iobe.Errors))
	for _, err := range iobe.Errors {
		errorStrings = append(errorStrings, err.Error())
	}
	return strings.Join(errorStrings, "; ")
}

// appendEntry adds entry unless an identical one exists, refreshing the
// timestamp. Dedup keeps the list bounded when a condition is re-detected.
func (iobe *IOBundleError) appendEntry(entry ioBundleErrorBase) {
	if iobe.Errors == nil {
		iobe.Errors = make([]ioBundleErrorBase, 0, 1)
	}
	for _, e := range iobe.Errors {
		if e.ErrStr == entry.ErrStr && e.TypeStr == entry.TypeStr &&
			e.Warning == entry.Warning && e.GroupScoped == entry.GroupScoped {
			// Already present; leave the timestamp so a persistent error
			// keeps its original time.
			return
		}
	}
	iobe.Errors = append(iobe.Errors, entry)
	iobe.TimeOfError = time.Now()
}

// SetSourceErrors reconciles the entries owned by owner's type to exactly the
// desired strings (all classified alike by warning/groupScoped). Unchanged
// entries are left in place; TimeOfError advances only when an entry is added,
// and resets when the last entry is removed. An empty desired clears the source.
// This lets each source refresh its own errors every reconciliation pass without
// churning the timestamp of a persistent error or touching other sources.
// Returns true if the entry set changed.
func (iobe *IOBundleError) SetSourceErrors(owner error, warning, groupScoped bool, desired []string) bool {
	typeStr := reflect.TypeOf(owner).String()
	want := make(map[string]bool, len(desired))
	for _, s := range desired {
		want[s] = true
	}
	have := make(map[string]bool)
	changed := false
	kept := iobe.Errors[:0]
	for _, e := range iobe.Errors {
		if e.TypeStr == typeStr && !want[e.ErrStr] {
			changed = true // stale entry of this source: drop
			continue
		}
		if e.TypeStr == typeStr {
			have[e.ErrStr] = true
		}
		kept = append(kept, e)
	}
	iobe.Errors = kept
	added := false
	for _, s := range desired {
		if !have[s] {
			iobe.Errors = append(iobe.Errors, ioBundleErrorBase{
				ErrStr: s, TypeStr: typeStr, Warning: warning, GroupScoped: groupScoped,
			})
			added = true
		}
	}
	if len(iobe.Errors) == 0 {
		iobe.TimeOfError = time.Time{}
	} else if added {
		iobe.TimeOfError = time.Now()
	}
	return changed || added
}

// Append adds a member-scoped hard error.
func (iobe *IOBundleError) Append(err error) {
	iobe.appendEntry(ioBundleErrorBase{
		ErrStr:  err.Error(),
		TypeStr: reflect.TypeOf(err).String(),
	})
}

// AppendWarning adds a member-scoped advisory warning (see Warning).
func (iobe *IOBundleError) AppendWarning(err error) {
	iobe.appendEntry(ioBundleErrorBase{
		ErrStr:  err.Error(),
		TypeStr: reflect.TypeOf(err).String(),
		Warning: true,
	})
}

// AppendGroupError adds a group-scoped hard error (see GroupScoped).
func (iobe *IOBundleError) AppendGroupError(err error) {
	iobe.appendEntry(ioBundleErrorBase{
		ErrStr:      err.Error(),
		TypeStr:     reflect.TypeOf(err).String(),
		GroupScoped: true,
	})
}

// IsOnlyWarnings returns true if there is at least one entry and every entry is
// an advisory warning (no hard errors). Used to pick the reported severity.
func (iobe *IOBundleError) IsOnlyWarnings() bool {
	if len(iobe.Errors) == 0 {
		return false
	}
	for _, err := range iobe.Errors {
		if !err.Warning {
			return false
		}
	}
	return true
}

// Empty returns true if no error has been added
func (iobe *IOBundleError) Empty() bool {
	if iobe.Errors == nil || len(iobe.Errors) == 0 {
		return true
	}

	return false
}

// HasErrorByType returns true if error of the same type is found
func (iobe *IOBundleError) HasErrorByType(e error) bool {
	typeStr := reflect.TypeOf(e).String()
	base, ok := e.(ioBundleErrorBase)
	if ok {
		typeStr = base.TypeStr
	}
	for _, err := range iobe.Errors {
		if typeStr == err.TypeStr {
			return true
		}
	}

	return false
}

func (iobe *IOBundleError) removeByType(e error) {
	typeStr := reflect.TypeOf(e).String()
	toRemoveIndices := []int{}
	for i, err := range iobe.Errors {
		if typeStr == err.TypeStr {
			toRemoveIndices = append(toRemoveIndices, i)
		}
	}

	for i := len(toRemoveIndices) - 1; i >= 0; i-- {
		toRemove := toRemoveIndices[i]
		iobe.Errors = append(iobe.Errors[:toRemove], iobe.Errors[toRemove+1:]...)
	}
}

// RemoveByType clears entries of type e, leaving other errors and warnings.
func (iobe *IOBundleError) RemoveByType(e error) {
	iobe.removeByType(e)
}

// AggregatedIoBundleError is the combined error state of an assignment group,
// ready for reporting in a single ZioBundle.
type AggregatedIoBundleError struct {
	Description  string    // combined text
	OnlyWarnings bool      // every entry is a warning (picks WARNING vs ERROR)
	Empty        bool      // no member carries an entry
	ErrorTime    time.Time // most recent error time across members
}

// AggregateIoBundleGroupErrors combines a group's members' entries for reporting:
// group-scoped entries once and unattributed, member-scoped entries prefixed with
// their member's label. Duplicates are suppressed; nil members ignored.
func AggregateIoBundleGroupErrors(members []*IoBundle) AggregatedIoBundleError {
	var parts []string
	seenGroup := map[string]bool{}
	onlyWarnings := true
	anyEntry := false
	var latest time.Time
	// Group-scoped entries first, deduplicated across members.
	for _, m := range members {
		if m == nil {
			continue
		}
		if m.Error.TimeOfError.After(latest) {
			latest = m.Error.TimeOfError
		}
		for _, e := range m.Error.Errors {
			if !e.GroupScoped {
				continue
			}
			key := e.TypeStr + "\x00" + e.ErrStr
			if seenGroup[key] {
				continue
			}
			seenGroup[key] = true
			anyEntry = true
			if !e.Warning {
				onlyWarnings = false
			}
			parts = append(parts, e.ErrStr)
		}
	}
	// Member-scoped entries, attributed to the owning member.
	for _, m := range members {
		if m == nil {
			continue
		}
		seenMember := map[string]bool{}
		for _, e := range m.Error.Errors {
			if e.GroupScoped {
				continue
			}
			key := e.TypeStr + "\x00" + e.ErrStr
			if seenMember[key] {
				continue
			}
			seenMember[key] = true
			anyEntry = true
			if !e.Warning {
				onlyWarnings = false
			}
			parts = append(parts, fmt.Sprintf("%s: %s", m.Logicallabel, e.ErrStr))
		}
	}
	return AggregatedIoBundleError{
		Description:  strings.Join(parts, "; "),
		OnlyWarnings: anyEntry && onlyWarnings,
		Empty:        !anyEntry,
		ErrorTime:    latest,
	}
}

// IoBundle has one entry per individual receptacle with a reference
// to a group name. Those sharing a group name needs to be assigned
// together.
type IoBundle struct {
	// Type
	//	Type of the IoBundle
	Type IoType `json:",omitempty"`
	// Phylabel
	//	Label on the outside of the enclosure
	Phylabel string `json:",omitempty"`

	// Logical Label assigned to the Adapter. Could match Phylabel
	// or could be a user-chosen string like "shopfloor"
	Logicallabel string `json:",omitempty"`

	// Assignment Group, is unique label that is applied across PhysicalIOs
	// Entire group can be assigned to application or nothing at all
	// If this is an empty string it means the IoBundle can not be assigned.
	AssignmentGroup string `json:",omitempty"`

	// Parent Assignment Group is there to reference the parent assignment group in order to make the device
	// dependent on a different device.
	// Currently the concrete reason to do this is to make a usb device dependent on the PCI address the USB
	// controller is using to prevent passthrough of the USB controller in one application while trying to passthrough
	// a USB device on this controller to another application.
	ParentAssignmentGroup string `json:",omitempty"`

	Usage zcommon.PhyIoMemberUsage `json:",omitempty"`

	// Cost is zero for the free ports; less desirable ports have higher numbers
	Cost uint8 `json:",omitempty"`

	// The following set of I/O addresses and info/aliases are used to find
	// a device, and also to configure it.
	// XXX TBD: Add PciClass, PciVendor and PciDevice strings as well
	// for matching
	Ifname string `json:",omitempty"` // Matching for network PCI devices e.g., "eth1"

	// Attributes from controller but can also be set locally.
	PciLong string `json:",omitempty"` // Specific PCI bus address in Domain:Bus:Device.Function syntax
	// For non-PCI devices such as the ISA serial ports we have:
	// XXX: Why is IRQ a string?? Should convert it into Int.
	Irq        string `json:",omitempty"` // E.g., "5"
	Ioports    string `json:",omitempty"` // E.g., "2f8-2ff"
	Serial     string `json:",omitempty"` // E.g., "/dev/ttyS1"
	UsbAddr    string `json:",omitempty"` // E.g., "1:2.3"
	UsbProduct string `json:",omitempty"` // E.g., "0951:1666"

	// Attributes Derived and assigned locally ( not from controller)

	Unique  string `json:",omitempty"` // From firmware_node symlink; used for debug checks
	MacAddr string `json:",omitempty"` // Set for networking adapters. XXX Note used for match.

	// UsedByUUID
	//	Application UUID ( Can be Dom0 too ) that owns the Bundle.
	//	For unassigned adapters, this is not set.
	UsedByUUID uuid.UUID `json:",omitempty"`

	// IsPciBack
	//	Is the IoBundle assigned to pciBack; means other bundles in the same group are also assigned
	//  If the device is managed by dom0, this is False.
	//  If the device is ( or to be ) managed by DomU, this is True
	IsPCIBack bool `json:",omitempty"` // Assigned to pciback
	IsPort    bool `json:",omitempty"` // Whole or part of the bundle is a zedrouter port
	// Do not put device under pciBack, instead keep it in dom0 as long as it is not assigned to any application.
	// In other words, this does not prevent assignments but keeps unassigned devices visible to EVE.
	KeepInHost bool          `json:",omitempty"`
	Error      IOBundleError `json:",omitempty"`

	// Only used in PhyIoNetEthPF
	Vfs sriov.VFList `json:",omitempty"`
	// Only used in PhyIoNetEthVF
	VfParams VfInfo `json:",omitempty"`
	// Used for additional attributes
	Cbattr map[string]string `json:",omitempty"`
}

// VfInfo Stores information about Virtual Function (VF)
type VfInfo struct {
	Index   uint8  `json:",omitempty"`
	VlanID  uint16 `json:",omitempty"`
	PFIface string `json:",omitempty"`
}

// Really a constant
var nilUUID = uuid.UUID{}

// IsUSBController checks if the IoBundle is a USB controller, including when using the deprecated type IoUSB
func (ib IoBundle) IsUSBController() bool {
	if ib.Type == IoUSBController {
		return true
	}

	// let's assume that if no usbaddr and no usbproduct is set, that it is a USB controller
	// we cannot check for PciLong as there are USB controllers out there that are not connected via PCI
	if ib.Type == IoUSB && ib.UsbAddr == "" && ib.UsbProduct == "" {
		return true
	}

	return false
}

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
	if phyAdapter.Phyaddr.UsbProduct != ib.UsbProduct {
		log.Functionf("USB product changed from %s to %s",
			ib.UsbProduct, phyAdapter.Phyaddr.UsbProduct)
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
	ib.ParentAssignmentGroup = phyAdapter.Parentassigngrp
	ib.Ifname = phyAdapter.Phyaddr.Ifname
	ib.PciLong = phyAdapter.Phyaddr.PciLong
	ib.UsbAddr = phyAdapter.Phyaddr.UsbAddr
	ib.UsbProduct = phyAdapter.Phyaddr.UsbProduct
	ib.Irq = phyAdapter.Phyaddr.Irq
	ib.Ioports = phyAdapter.Phyaddr.Ioports
	ib.Serial = phyAdapter.Phyaddr.Serial
	ib.Usage = phyAdapter.Usage
	ib.Cbattr = phyAdapter.Cbattr
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
	IoNVMEStorage   IoType = 9
	IoSATAStorage   IoType = 10
	IoNetEthPF      IoType = 11
	IoNetEthVF      IoType = 12
	IoUSBController IoType = 13
	IoUSBDevice     IoType = 14
	IoCAN           IoType = 15
	IoVCAN          IoType = 16
	IoLCAN          IoType = 17
	IoNVME          IoType = 255
	IoOther         IoType = 255
)

// IsNet checks if the type is any of the networking types.
func (ioType IoType) IsNet() bool {
	switch ioType {
	case IoNetEth, IoNetWLAN, IoNetWWAN, IoNetEthPF:
		return true
	default:
		return false
	}
}

// IsNetEthVF returns true when the adapter is an SR-IOV Virtual Function.
// VFs are intentionally excluded from IsNet() because:
//   - They must be bound to vfio-pci (pciback) regardless of testing mode.
//   - They are never EVE network ports (keepInHost logic must not apply).
//
// Use this predicate wherever VF-specific behaviour is required.
func (ioType IoType) IsNetEthVF() bool {
	return ioType == IoNetEthVF
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
	if curIbPtr.UsbProduct != "" {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve UsbProduct %v",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, curIbPtr.UsbProduct)
		ib.UsbProduct = curIbPtr.UsbProduct
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
	if len(curIbPtr.Cbattr) > 0 {
		log.Functionf("AddOrUpdateIoBundle(%d %s %s) preserve cbattr",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
		ib.Cbattr = curIbPtr.Cbattr
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

// ErrOwnParent describes an error where an IoBundle is parent of itself
type ErrOwnParent struct{}

func (ErrOwnParent) Error() string {
	return "IOBundle cannot be it's own parent"
}

// ErrParentAssigngrpMismatch describes an error where an IoBundle has a mismatch with the parentassigngrp
type ErrParentAssigngrpMismatch struct{}

func (ErrParentAssigngrpMismatch) Error() string {
	return "IOBundle with parentassigngrp mismatch found"
}

// ErrEmptyAssigngrpWithParent describes an error where an IoBundle without assigngrp has a parentassingrp
type ErrEmptyAssigngrpWithParent struct{}

func (ErrEmptyAssigngrpWithParent) Error() string {
	return "IOBundle with empty assigngrp cannot have a parent"
}

// ErrCycleDetected describes an error where an IoBundle has cycles with parentassigngrp
type ErrCycleDetected struct{}

func (ErrCycleDetected) Error() string {
	return "Cycle detected, please check provided parentassigngrp/assigngrp"
}

// The following empty types are owner markers for SetSourceErrors: they identify
// which source produced an entry so each source clears only its own.

// ErrIoBundleAssignmentGroupConflict owns CheckBadAssignmentGroups errors.
type ErrIoBundleAssignmentGroupConflict struct{}

func (ErrIoBundleAssignmentGroupConflict) Error() string { return "assignment-group conflict" }

// ErrIoBundleModelInconsistency owns updatePortAndPciBackIoBundle warnings.
type ErrIoBundleModelInconsistency struct{}

func (ErrIoBundleModelInconsistency) Error() string { return "device-model inconsistency" }

// ErrIoBundleRename owns the interface-rename warning from IoBundleToPci.
type ErrIoBundleRename struct{}

func (ErrIoBundleRename) Error() string { return "interface renamed to match model" }

// ErrIoBundlePcibackOp owns errors from moving a device in/out of pciback.
type ErrIoBundlePcibackOp struct{}

func (ErrIoBundlePcibackOp) Error() string { return "pciback operation failed" }

// ErrIoBundleMissingDevice means the device backing an IoBundle was not found.
// Typed so callers can clear it (RemoveByType) once resolvable, keeping warnings.
type ErrIoBundleMissingDevice struct {
	msg string
}

func (e ErrIoBundleMissingDevice) Error() string {
	return e.msg
}

// CheckParentAssigngrp validates the parentassigngrp/assigngrp graph and records
// the applicable per-bundle error (self-parent, parent mismatch, empty-group with
// parent, or a dependency cycle). Errors are reconciled through SetSourceErrors so
// a persistent error keeps a stable timestamp across reconciliation passes instead
// of being churned by a remove-then-re-add; a churning timestamp republishes
// AssignableAdapters every pass and spins nim's DPC verification. Returns true if
// the error set changed.
func (aa *AssignableAdapters) CheckParentAssigngrp() bool {
	assigngrp2parent := make(map[string]string)
	ownParent := make(map[int]bool)
	mismatch := make(map[int]bool)
	emptyWithParent := make(map[int]bool)

	for i := range aa.IoBundleList {
		ib := &aa.IoBundleList[i]
		if ib.AssignmentGroup == ib.ParentAssignmentGroup && ib.AssignmentGroup != "" {
			ownParent[i] = true
			continue
		}
		if parent, ok := assigngrp2parent[ib.AssignmentGroup]; ok && parent != ib.ParentAssignmentGroup {
			mismatch[i] = true
			continue
		}
		if ib.AssignmentGroup == "" && ib.ParentAssignmentGroup != "" {
			emptyWithParent[i] = true
			continue
		}
		assigngrp2parent[ib.AssignmentGroup] = ib.ParentAssignmentGroup
	}

	// A group is in a cycle if following parent links from it returns to an
	// already-visited group. Self-parents are excluded above, so they are
	// reported as ErrOwnParent rather than ErrCycleDetected.
	cycleGroups := make(map[string]bool)
	for assigngrp := range assigngrp2parent {
		visited := map[string]struct{}{assigngrp: {}}
		for g := assigngrp; g != ""; {
			g = assigngrp2parent[g]
			if _, seen := visited[g]; seen {
				cycleGroups[g] = true
				break
			}
			visited[g] = struct{}{}
		}
	}

	changed := false
	setErr := func(ib *IoBundle, owner error, want bool) {
		var desired []string
		if want {
			desired = []string{owner.Error()}
		}
		if ib.Error.SetSourceErrors(owner, false, false, desired) {
			changed = true
		}
	}
	for i := range aa.IoBundleList {
		ib := &aa.IoBundleList[i]
		setErr(ib, ErrOwnParent{}, ownParent[i])
		setErr(ib, ErrParentAssigngrpMismatch{}, mismatch[i])
		setErr(ib, ErrEmptyAssigngrpWithParent{}, emptyWithParent[i])
		setErr(ib, ErrCycleDetected{}, cycleGroups[ib.AssignmentGroup])
	}
	return changed
}

// IOBundleCollision has the members IoBundles can collide on
type IOBundleCollision struct {
	Phylabel   string
	USBAddr    string
	USBProduct string
	PCILong    string
	Assigngrp  string
}

func (i IOBundleCollision) String() string {
	var parts []string
	if i.USBAddr != "" {
		parts = append(parts, "usbaddr "+i.USBAddr)
	}
	if i.USBProduct != "" {
		parts = append(parts, "usbproduct "+i.USBProduct)
	}
	if i.PCILong != "" {
		parts = append(parts, "pcilong "+i.PCILong)
	}
	if i.Assigngrp != "" {
		parts = append(parts, "assigngrp "+i.Assigngrp)
	}
	if len(parts) == 0 {
		return i.Phylabel
	}
	return fmt.Sprintf("%s (%s)", i.Phylabel, strings.Join(parts, ", "))
}

// ErrIOBundleCollision describes an error where an IoBundle collides with another IoBundle
type ErrIOBundleCollision struct {
	Collisions []IOBundleCollision
}

func (i ErrIOBundleCollision) Error() string {
	collisionStrs := make([]string, 0, len(i.Collisions))
	for _, collision := range i.Collisions {
		collisionStrs = append(collisionStrs, collision.String())
	}
	return "ioBundle collision: " + strings.Join(collisionStrs, "; ")
}

func newIoBundleCollisionErr() ErrIOBundleCollision {
	return ErrIOBundleCollision{
		Collisions: []IOBundleCollision{},
	}
}

// CheckBadUSBBundles sets and clears ib.Error/ErrorTime if bundle collides in regards of USB
func (aa *AssignableAdapters) CheckBadUSBBundles() {
	usbProductsAddressMap := make(map[[4]string][]*IoBundle)
	for i := range aa.IoBundleList {
		ioBundle := &aa.IoBundleList[i]
		if ioBundle.UsbAddr == "" && ioBundle.UsbProduct == "" && ioBundle.PciLong == "" {
			continue
		}

		id := [4]string{ioBundle.UsbAddr, ioBundle.UsbProduct, ioBundle.PciLong, ioBundle.AssignmentGroup}
		usbProductsAddressMap[id] = append(usbProductsAddressMap[id], ioBundle)
	}

	// Collision text per colliding bundle (a group-scoped error listing every
	// colliding member; identical for all members of the collision).
	collisionText := make(map[*IoBundle]string)
	for _, bundles := range usbProductsAddressMap {
		if len(bundles) <= 1 {
			continue
		}
		collisionErr := newIoBundleCollisionErr()
		for _, bundle := range bundles {
			collisionErr.Collisions = append(collisionErr.Collisions, IOBundleCollision{
				Phylabel:   bundle.Phylabel,
				USBAddr:    bundle.UsbAddr,
				USBProduct: bundle.UsbProduct,
				PCILong:    bundle.PciLong,
				Assigngrp:  bundle.AssignmentGroup,
			})
		}
		for _, bundle := range bundles {
			collisionText[bundle] = collisionErr.Error()
		}
	}

	for i := range aa.IoBundleList {
		ib := &aa.IoBundleList[i]
		var desired []string
		if s, ok := collisionText[ib]; ok {
			desired = []string{s}
		}
		ib.Error.SetSourceErrors(ErrIOBundleCollision{}, false, true, desired)
	}
}

// CheckBadAssignmentGroups sets ib.Error/ErrorTime if two IoBundles in different
// assignment groups have the same PCI ID (ignoring the PCI function number)
// Returns true if there was a modification so caller can publish.
func (aa *AssignableAdapters) CheckBadAssignmentGroups(log *base.LogObject, PCISameController func(string, string) bool) bool {
	changed := false
	for i := range aa.IoBundleList {
		ib := &aa.IoBundleList[i]
		var desired []string
		for _, ib2 := range aa.IoBundleList {
			if ib2.Phylabel == ib.Phylabel {
				continue
			}
			if ib.AssignmentGroup == "" || ib2.AssignmentGroup == ib.AssignmentGroup {
				continue
			}
			// skip usb passthrough checking here
			if ib.UsbAddr != "" || ib2.UsbAddr != "" {
				continue
			}
			if ib.UsbProduct != "" || ib2.UsbProduct != "" {
				continue
			}
			if PCISameController != nil && PCISameController(ib.PciLong, ib2.PciLong) {
				s := fmt.Sprintf("CheckBadAssignmentGroup: %s same PCI controller as %s; pci long %s vs %s",
					ib2.Ifname, ib.Ifname, ib2.PciLong, ib.PciLong)
				log.Error(s)
				desired = append(desired, s)
			}
		}
		if ib.Error.SetSourceErrors(ErrIoBundleAssignmentGroupConflict{}, false, true, desired) {
			changed = true
		}
	}

	return changed || aa.CheckParentAssigngrp()
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
			if ib.UsbAddr != "" || ib2.UsbAddr != "" {
				continue
			}
			if ib.UsbProduct != "" || ib2.UsbProduct != "" {
				continue
			}
			if PCISameController != nil && PCISameController(ib.PciLong, ib2.PciLong) {
				log.Warnf("ExpandController: adapter %s (logicallabel %s, ifname %q, "+
					"PCI %s) shares a PCI controller with %s (logicallabel %s, ifname %q, "+
					"PCI %s) and is pulled into the same assignment group %q, which the "+
					"controller's model did not include",
					ib2.Phylabel, ib2.Logicallabel, ib2.Ifname, ib2.PciLong,
					ib.Phylabel, ib.Logicallabel, ib.Ifname, ib.PciLong, ib.AssignmentGroup)
				elist = append(elist, ib2)
			}
		}
	}
	return elist
}
