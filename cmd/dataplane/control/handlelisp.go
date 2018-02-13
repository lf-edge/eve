package main

import (
	"crypto/aes"
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
		// XXX Should we log.Fatal here?
		log.Println("RLOC:", rlocStr.Rloc, "is invalid")
		return types.Rloc{}, false
	}
	x, err := strconv.ParseUint(rlocStr.Priority, 10, 32)
	if err != nil {
		// XXX Should we log.Fatal here?
		return types.Rloc{}, false
	}
	priority := uint32(x)
	x, err = strconv.ParseUint(rlocStr.Weight, 10, 32)
	if err != nil {
		// XXX Should we log.Fatal here?
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
		// XXX Should we log.Fatal here?
		return types.Rloc{}, false
	}

	//keys := make([]types.Key, len(rlocStr.Keys))
	// Max number of keys per RLOC can only be 3. Look at RFC 8061 lisp header
	keys := make([]types.Key, 3)

	//for i, key := range rlocStr.Keys {
	for _, key := range rlocStr.Keys {
		keyId, err := strconv.ParseUint(key.KeyId, 10, 32)
		if err != nil {
			// XXX Should we log.Fatal here?
			continue
		}

		if (len(key.EncKey) != CRYPTO_KEY_LEN) ||
			(len(key.IcvKey[8:]) != CRYPTO_KEY_LEN) {
			log.Printf(
				"Error: Encap Key lengths should be 32, found encrypt key len %d & icv key length %d and encap key %s, icv key %s\n",
				len(key.EncKey), len(key.IcvKey[8:]), key.EncKey, key.IcvKey[8:])
			// XXX Should we log.Fatal here?
			continue
		}

		encKey := []byte(key.EncKey)
		// XXX lispers.net is sending 8 zeroes in the front
		icvKey := []byte(key.IcvKey[8:])
		encBlock, err := aes.NewCipher(encKey)
		if err != nil {
			log.Printf("Creating of Cipher block for ecnryption key %s failed\n",
				key.EncKey)
			// XXX Should we log.Fatal here?
			continue
		}

		//keys[i] = types.Key {
		keys[keyId-1] = types.Key{
			KeyId:    uint32(keyId),
			EncKey:   encKey,
			IcvKey:   icvKey,
			EncBlock: encBlock,
		}
		log.Printf("Adding enc key %s\n", keys[keyId-1].EncKey)
		log.Printf("Adding icv key %s\n", keys[keyId-1].IcvKey)
	}

	// XXX We are not decoding the keys for now.
	// Will have to add code for key handling in future.

	rlocEntry := types.Rloc{
		Rloc:     rloc,
		Priority: priority,
		Weight:   weight,
		KeyCount: uint32(len(rlocStr.Keys)),
		Keys:     keys,
		Family:   uint32(family),
	}
	return rlocEntry, true
}

func isAddressIPv6(eid net.IP) bool {

	if eid.To4() == nil {
		return true
	}
	return false
}

func createMapCache(mapCache *MapCacheEntry) {
	rlocs := []types.Rloc{}

	x, err := strconv.ParseUint(mapCache.InstanceId, 10, 32)
	if err != nil {
		return
	}
	iid := uint32(x)
	eid, ipNet, _ := net.ParseCIDR(mapCache.EidPrefix)
	if eid == nil {
		// XXX Should we log.Fatal here?
		return
	}
	v6 := isAddressIPv6(eid)
	maskLen, _ := ipNet.Mask.Size()

	if (maskLen != 128) && ((maskLen != 0) || !v6) {
		// We are not interested in prefixes shorter than 128 except 0 prefix length
		// If we do not find a more specific route (prefix length 128), we forward
		// our packets to the default route.
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
			// XXX Should we log.Fatal here?
			continue
		}
		rlocs = append(rlocs, rlocEntry)
	}

	// Add this map-cache entry to database
	//fib.LookupAndUpdate(iid, eid, rlocs)
	fib.UpdateMapCacheEntry(iid, eid, rlocs)
}

func handleMapCacheTable(msg []byte) {
	var mapCacheTable EntireMapCache

	err := json.Unmarshal(msg, &mapCacheTable)
	if err != nil {
		log.Fatal("handleMapCacheTable: Error: Unknown json message format: %s: %s",
			string(msg), err)
		return
	}

	for _, mapCache := range mapCacheTable.MapCaches {
		createMapCache(&mapCache)
	}
	return
}

// Extract map cache message and add to our database
func handleMapCache(msg []byte) {
	var mapCache MapCacheEntry

	log.Printf("Handling the following map-cache message:\n%s\n", string(msg))
	err := json.Unmarshal(msg, &mapCache)
	if err != nil {
		log.Fatal("handleMapCache: Error: Unknown json message format: %s: %s",
			string(msg), err)
		return
	}
	/*
		//log.Println("map-cache is", mapCache)
		log.Println("Opcode:", mapCache.Opcode)
		log.Println("eid-prefix:", mapCache.EidPrefix)
		log.Println("IID:", mapCache.InstanceId)
		log.Println()
	*/

	createMapCache(&mapCache)
}

func parseDatabaseMappings(databaseMappings DatabaseMappings) map[uint32][]net.IP {
	tmpMap := make(map[uint32][]net.IP)

	for _, entry := range databaseMappings.Mappings {
		/*
			log.Println("IID:", entry.InstanceId)
			log.Println("Eid prefix:", entry.EidPrefix)
			log.Println()
		*/

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
		log.Fatal("handleDatabaseMappings: Error: Unknown json message format: %s: %s",
			string(msg), err)
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
		log.Fatal("handleInterfaces: Error: Unknown json message format: %s: %s",
			string(msg), err)
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
		//x := iface.InstanceId
		x, err := strconv.ParseUint(iface.InstanceId, 10, 32)
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
		log.Fatal("handleDecapKeys: Error: Unknown json message format: %s: %s",
			string(msg), err)
		return
	}

	rloc := net.ParseIP(decapMsg.Rloc)
	if rloc == nil {
		return
	}

	keys := make([]types.DKey, len(decapMsg.Keys))

	//for i, key := range decapMsg.Keys {
	for _, key := range decapMsg.Keys {
		keyId, err := strconv.ParseUint(key.KeyId, 10, 32)
		if err != nil {
			continue
		}
		if (len(key.DecKey) != CRYPTO_KEY_LEN) ||
			(len(key.IcvKey[8:]) != CRYPTO_KEY_LEN) {
			log.Printf("XXXXX Decap-key is %s\n", key.DecKey)
			log.Printf("XXXXX ICV-key is %s\n", key.IcvKey[8:])
			log.Printf(
				"Error: Decap/ICV Key lengths should be 32, found encrypt key len %d & icv key length %d\n",
				len(key.DecKey), len(key.IcvKey[8:]))
			continue
		}
		decKey := []byte(key.DecKey)
		// XXX lispers.net sends 8 zeroes in the beginning
		icvKey := []byte(key.IcvKey[8:])
		decBlock, err := aes.NewCipher(decKey)
		if err != nil {
			log.Printf("Creating of Cipher block for decryption key %s failed\n",
				key.DecKey)
			continue
		}
		keys[keyId-1] = types.DKey{
			KeyId:    uint32(keyId),
			DecKey:   decKey,
			IcvKey:   icvKey,
			DecBlock: decBlock,
		}
		log.Printf("Adding Decap key[%d] %s\n", keyId-1, keys[keyId-1].DecKey)
		log.Printf("Adding Decap icv[%d] %s\n", keyId-1, keys[keyId-1].IcvKey)
	}

	// Parse and store the decap keys.
	decapEntry := types.DecapKeys{
		Rloc: rloc,
		Keys: keys,
	}
	fib.UpdateDecapKeys(&decapEntry)
}

func handleEtrNatPort(msg []byte) {
	var etrNatPort EtrNatPort
	log.Println(string(msg))

	err := json.Unmarshal(msg, &etrNatPort)
	if err != nil {
		log.Fatal("handleEtrNatPort: Error: Unknown json message format: %s: %s",
			string(msg), err)
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
