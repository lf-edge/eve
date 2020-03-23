// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package fib

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/lisp/dataplane/dptypes"
	log "github.com/sirupsen/logrus"
	"net"
)

var ifaceMap *dptypes.InterfaceMap
var eidMap *dptypes.EIDMap

func NewIfaceMap() *dptypes.InterfaceMap {
	return &dptypes.InterfaceMap{
		InterfaceDB: make(map[string]dptypes.Interface),
	}
}

func NewEIDMap() *dptypes.EIDMap {
	return &dptypes.EIDMap{
		EidEntries: make(map[uint32]dptypes.EIDEntry),
	}
}

func InitIfaceMaps() {
	ifaceMap = NewIfaceMap()
	eidMap = NewEIDMap()
}

func LookupIfaceIID(name string) uint32 {
	ifaceMap.LockMe.RLock()
	defer ifaceMap.LockMe.RUnlock()
	entry, ok := ifaceMap.InterfaceDB[name]
	if ok {
		return entry.InstanceId
	}
	return 0
}

func LookupIfaceEids(iid uint32) []net.IP {
	eidMap.LockMe.RLock()
	defer eidMap.LockMe.RUnlock()
	entry, ok := eidMap.EidEntries[iid]
	if ok {
		return entry.Eids
	}
	return nil
}

func IfaceGetEids(name string) []net.IP {
	iid := LookupIfaceIID(name)
	if iid > 0 {
		return LookupIfaceEids(iid)
	}
	return nil
}

func UpdateIfaceIIDs(interfaces []dptypes.Interface) {
	ifaceMap.LockMe.Lock()
	defer ifaceMap.LockMe.Unlock()

	// Interface/database-bindings come as a group of commands.
	// lispers.net does not send any differential messages.
	// Delete all the old entries and add the new entries
	for key := range ifaceMap.InterfaceDB {
		delete(ifaceMap.InterfaceDB, key)
	}

	// Add latest entries
	for _, iface := range interfaces {
		ifaceMap.InterfaceDB[iface.Name] = iface
	}
}

func UpdateIfaceEids(eidEntries []dptypes.EIDEntry) {
	eidMap.LockMe.Lock()
	defer eidMap.LockMe.Unlock()

	// Interface/database-bindings come as a group of commands.
	// lispers.net does not send any differential messages.
	// Delete all the old entries and add the new entries
	for key := range eidMap.EidEntries {
		delete(eidMap.EidEntries, key)
	}

	// Add latest entries
	for _, eidEntry := range eidEntries {
		eidMap.EidEntries[eidEntry.InstanceId] = eidEntry
	}
}

func ShowIfaceIIDs() {
	ifaceMap.LockMe.RLock()
	defer ifaceMap.LockMe.RUnlock()

	log.Println("##### INTERFACE IIDs #####")
	for key, data := range ifaceMap.InterfaceDB {
		log.Println("Interface:", key)
		log.Println("IID:", data.InstanceId)
		log.Println()
	}
	log.Println()
}

func GetInterfaces() []string {
	ifaceMap.LockMe.RLock()
	defer ifaceMap.LockMe.RUnlock()

	ifaces := []string{}

	for key, data := range ifaceMap.InterfaceDB {
		iface := fmt.Sprintf("%s:%d", key, data.InstanceId)
		ifaces = append(ifaces, iface)
	}
	return ifaces
}

func ShowIfaceEIDs() {
	eidMap.LockMe.RLock()
	defer eidMap.LockMe.RUnlock()

	log.Println("##### INTERFACE EIDs #####")
	for key, data := range eidMap.EidEntries {
		log.Println("IID:", key)
		log.Println("Eids:")
		for _, eid := range data.Eids {
			log.Println(eid.String())
		}
		log.Println()
	}
	log.Println()
}

func GetIfaceEIDs() []string {
	eidMap.LockMe.RLock()
	defer eidMap.LockMe.RUnlock()

	eids := []string{}
	for key, data := range eidMap.EidEntries {
		eidEntry := fmt.Sprintf("%d --> ", key)
		for _, eid := range data.Eids {
			eidEntry += eid.String() + " "
		}
		eids = append(eids, eidEntry)
	}
	return eids
}

func GetEidMaps() []dptypes.EIDEntry {
	eidMap.LockMe.RLock()
	defer eidMap.LockMe.RUnlock()

	var eidMaps []dptypes.EIDEntry
	for key, data := range eidMap.EidEntries {
		eidMap := dptypes.EIDEntry{
			InstanceId: key,
		}
		for _, eid := range data.Eids {
			eidMap.Eids = append(eidMap.Eids, eid)
		}
		eidMaps = append(eidMaps, eidMap)
	}
	return eidMaps
}
