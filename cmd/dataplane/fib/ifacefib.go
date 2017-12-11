package fib

import (
    "fmt"
	"net"
    "github.com/zededa/go-provision/types"
)

var ifaceMap *types.InterfaceMap
var eidMap   *types.EIDMap

func NewIfaceMap() *types.InterfaceMap {
	return &types.InterfaceMap {
		InterfaceDB: make(map[string]types.Interface),
	}
}

func NewEIDMap() *types.EIDMap {
	return &types.EIDMap {
		EidEntries: make(map[uint32]types.EIDEntry),
	}
}

func InitIfaceMaps() {
	ifaceMap = NewIfaceMap()
	eidMap   = NewEIDMap()
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

func UpdateIfaceIIDs(interfaces []types.Interface) {
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

func UpdateIfaceEids(eidEntries []types.EIDEntry) {
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

	for key, data := range ifaceMap.InterfaceDB {
		fmt.Println("Interface:", key)
		fmt.Println("IID:", data.InstanceId)
		fmt.Println()
	}
	fmt.Println()
}

func ShowIfaceEIDs() {
	eidMap.LockMe.RLock()
	defer eidMap.LockMe.RUnlock()

	for key, data := range eidMap.EidEntries {
		fmt.Println("IID:", key)
		fmt.Println("Eids:")
		for _, eid := range data.Eids {
			fmt.Println(eid.String())
		}
		fmt.Println()
	}
	fmt.Println()
}
