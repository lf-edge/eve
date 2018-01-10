package main

import (
	"encoding/json"
	"github.com/zededa/go-provision/dataplane/fib"
	"github.com/zededa/go-provision/types"
	"log"
	"net"
	"strconv"
)

// Parse the json RLOC message and extract ip addresses along
// with respective priorities and weights.
func parseRloc(rlocStr *Rloc) (types.Rloc, bool) {
	rloc := net.ParseIP(rlocStr.Rloc)
	if rloc == nil {
		log.Println("RLOC:", rlocStr.Rloc, "is invalid")
		return types.Rloc{}, false
	}
	x, err := strconv.ParseUint(rlocStr.Priority, 10, 32)
	if err != nil {
		return types.Rloc{}, false
	}
	priority := uint32(x)
	x, err = strconv.ParseUint(rlocStr.Weight, 10, 32)
	if err != nil {
		return types.Rloc{}, false
	}
	weight := uint32(x)
	if weight == 0 {
		weight = 1
	}

	// find the family of Rloc

	family := types.MAP_CACHE_FAMILY_UNKNOWN
	for i := 0; i < len(rlocStr.Rloc); i++ {
		switch rlocStr.Rloc[i] {
		case '.':
			family = types.MAP_CACHE_FAMILY_IPV4
		case ':':
			family = types.MAP_CACHE_FAMILY_IPV6
		}
	}
	if family == types.MAP_CACHE_FAMILY_UNKNOWN {
		// This ip address is not correct
		return types.Rloc{}, false
	}

	// XXX We are not decoding the keys for now.
	// Will have to add code for key handling in future.

	rlocEntry := types.Rloc{
		Rloc:     rloc,
		Priority: priority,
		Weight:   weight,
		Family:   uint32(family),
	}
	return rlocEntry, true
}

func isAddressIPv6(eid string) bool {
	for i := 0; i < len(eid); i++ {
		switch eid[i] {
		case ':':
			return true
		case '.':
			return false
		default:
			continue
		}
	}
	return false
}

// Extract map cache message and add to our database
func handleMapCache(msg []byte) {
	var mapCache MapCacheEntry

	log.Println(string(msg))
	err := json.Unmarshal(msg, &mapCache)
	if err != nil {
		log.Println("Error:", err)
		return
	}
	//log.Println("map-cache is", mapCache)
	log.Println("Opcode:", mapCache.Opcode)
	log.Println("eid-prefix:", mapCache.EidPrefix)
	log.Println("IID:", mapCache.InstanceId)
	log.Println()

	rlocs := []types.Rloc{}

	x, err := strconv.ParseUint(mapCache.InstanceId, 10, 32)
	if err != nil {
		return
	}
	iid := uint32(x)
	eid, ipNet, _ := net.ParseCIDR(mapCache.EidPrefix)
	if eid == nil {
		return
	}
	v6 := isAddressIPv6(mapCache.EidPrefix)
	maskLen, _ := ipNet.Mask.Size()

	if (maskLen == 0) && v6 {
		log.Printf("XXXXX Eid %s length is %d\n", mapCache.EidPrefix, maskLen)
		for _, b := range eid {
			log.Printf("%d:", b)
		}
		log.Println()
	}
	if (maskLen != 128) && ((maskLen != 0) || !v6) {
		// We are not interested in prefixes shorter then 128 other than 0
		log.Println("Ignoring EID with mask length:", maskLen)
		return
	}

	// if the opcode is delete we do not have to parse
	if mapCache.Opcode == "delete" {
		fib.DeleteMapCacheEntry(iid, eid)
		return
	}

	// If rlocs are empty bail
	if len(mapCache.Rlocs) == 0 {
		return
	}

	// Parse Rloc entries and convert strings to net.IP
	for _, rlocStr := range mapCache.Rlocs {
		rlocEntry, ok := parseRloc(&rlocStr)
		if !ok {
			continue
		}
		rlocs = append(rlocs, rlocEntry)
	}

	// Add this map-cache entry to database
	//fib.LookupAndUpdate(iid, eid, rlocs)
	fib.UpdateMapCacheEntry(iid, eid, rlocs)
}

func parseDatabaseMappings(databaseMappings DatabaseMappings) map[uint32][]net.IP {
	tmpMap := make(map[uint32][]net.IP)

	for _, entry := range databaseMappings.Mappings {
		log.Println("IID:", entry.InstanceId)
		log.Println("Eid prefix:", entry.EidPrefix)
		log.Println()

		x, err := strconv.ParseUint(entry.InstanceId, 10, 32)
		if err != nil {
			continue
		}
		iid := uint32(x)
		eid, _, err := net.ParseCIDR(entry.EidPrefix)
		//if eid == nil {
		if err != nil {
			continue
		}
		_, ok := tmpMap[iid]
		if !ok {
			tmpMap[iid] = []net.IP{}
		}
		tmpMap[iid] = append(tmpMap[iid], eid)
	}
	return tmpMap
}

func handleDatabaseMappings(msg []byte) {
	var databaseMappings DatabaseMappings

	err := json.Unmarshal(msg, &databaseMappings)
	if err != nil {
		log.Println("Error:", err)
		return
	}

	// lispers.net sends database-mappings as an array of iid to individual eid
	// pairs. It may have multiple rows for the same iid with different EIDs.
	// We have to convert these rows to a map of IID to list of EIDs.
	tmpMap := parseDatabaseMappings(databaseMappings)
	eidEntries := []types.EIDEntry{}

	if eidEntries == nil {
		log.Println("Allocation of EID entry slice failed")
		return
	}

	for key, data := range tmpMap {
		eidEntries = append(eidEntries, types.EIDEntry{
			InstanceId: key,
			Eids:       data,
		})
	}
	fib.UpdateIfaceEids(eidEntries)
}

func handleInterfaces(msg []byte) {
	var interfaces Interfaces

	err := json.Unmarshal(msg, &interfaces)
	if err != nil {
		log.Println("Error:", err)
		return
	}
	ifaces := []types.Interface{}

	if ifaces == nil {
		log.Println("Allocation of Interface slice failed")
		return
	}

	for _, iface := range interfaces.Interfaces {
		log.Println("Interface:", iface.Interface, ", Instance Id:", iface.InstanceId)
		log.Println()
		x := iface.InstanceId
		if err != nil {
			continue
		}
		iid := uint32(x)
		ifaces = append(ifaces, types.Interface{
			Name:       iface.Interface,
			InstanceId: iid,
		})
	}
	fib.UpdateIfaceIIDs(ifaces)

	// XXX
	// Should we wait till the IID to EID maps also arrive?
	// Existing threads might work fine, but the newly created threads
	// will not have the required EID data in FIB for input packet verification.
	ManageItrThreads(interfaces)
}

func handleDecapKeys(msg []byte) {
	var decapMsg DecapKeys

	err := json.Unmarshal(msg, &decapMsg)
	if err != nil {
		log.Println("Error:", err)
		return
	}

	rloc := net.ParseIP(decapMsg.Rloc)
	if rloc == nil {
		return
	}

	// XXX We do not parse and store the decap keys for now.
	// We will have to implement code for this in the future.
	decapEntry := types.DecapKeys{
		Rloc: rloc,
	}
	fib.UpdateDecapKeys(decapEntry)
}

func handleEtrNatPort(msg []byte) {
	var etrNatPort EtrNatPort
	log.Println(string(msg))

	err := json.Unmarshal(msg, &etrNatPort)
	if err != nil {
		log.Println("Error:", err)
		return
	}
	//port, err := strconv.ParseInt(etrNatPort.Port, 10, 32)
	//if err != nil {
	//	log.Printf("NAT port %s conversion to integer failed: %s\n",
	//	etrNatPort.Port, err)
	//	return
	//}
	ManageETRThread(etrNatPort.Port)
}
