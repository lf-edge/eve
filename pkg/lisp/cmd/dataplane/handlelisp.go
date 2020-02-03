// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Decode messages from lispers.net and update fibs.

package dataplane

import (
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"github.com/lf-edge/eve/pkg/lisp/dataplane/dptypes"
	"github.com/lf-edge/eve/pkg/lisp/dataplane/etr"
	"github.com/lf-edge/eve/pkg/lisp/dataplane/fib"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"time"
)

// Parse the json RLOC message and extract ip addresses along
// with respective priorities and weights.
func parseRloc(rlocStr *Rloc) (dptypes.Rloc, bool) {
	rloc := net.ParseIP(rlocStr.Rloc)
	if rloc == nil {
		// XXX Should we log.Fatal here?
		log.Errorf("parseRloc: RLOC: %s is invalid", rlocStr.Rloc)
		return dptypes.Rloc{}, false
	}
	x, err := strconv.ParseUint(rlocStr.Port, 10, 32)
	if err != nil {
		return dptypes.Rloc{}, false
	}
	port := uint16(x)

	x, err = strconv.ParseUint(rlocStr.Priority, 10, 32)
	if err != nil {
		// XXX Should we log.Fatal here?
		return dptypes.Rloc{}, false
	}
	priority := uint32(x)

	x, err = strconv.ParseUint(rlocStr.Weight, 10, 32)
	if err != nil {
		// XXX Should we log.Fatal here?
		return dptypes.Rloc{}, false
	}
	weight := uint32(x)
	if weight == 0 {
		weight = 1
	}

	// find the family of Rloc

	family := dptypes.MAP_CACHE_FAMILY_UNKNOWN
	for i := 0; i < len(rlocStr.Rloc); i++ {
		switch rlocStr.Rloc[i] {
		case '.':
			family = dptypes.MAP_CACHE_FAMILY_IPV4
		case ':':
			family = dptypes.MAP_CACHE_FAMILY_IPV6
		}
	}
	if family == dptypes.MAP_CACHE_FAMILY_UNKNOWN {
		// This ip address is not correct
		// XXX Should we log.Fatal here?
		return dptypes.Rloc{}, false
	}

	// Max number of keys per RLOC can only be 3. Look at RFC 8061 lisp header
	keys := make([]dptypes.Key, 3)

	//for i, key := range rlocStr.Keys {
	for _, key := range rlocStr.Keys {
		keyId, err := strconv.ParseUint(key.KeyId, 10, 32)
		if err != nil {
			// XXX Should we log.Fatal here?
			continue
		}

		//encKey := []byte(key.EncKey)
		encKey, err := hex.DecodeString(key.EncKey)
		if err != nil {
			log.Errorf("parseRloc: Decoding encrypt key to binary from string failed: %s", err)
			continue
		}
		// XXX lispers.net is sending 8 zeroes in the front
		/*
			if len(key.IcvKey) == 40 {
				key.IcvKey = key.IcvKey[8:]
			}
		*/
		icvKey, err := hex.DecodeString(key.IcvKey)
		if err != nil {
			log.Errorf("parseRloc: Decoding ICV key to binary from string failed: %s", err)
			continue
		}
		encBlock, err := aes.NewCipher(encKey)
		if err != nil {
			log.Errorf(
				"parseRloc: Creating of Cipher block for ecnryption key %s failed",
				key.EncKey)
			// XXX Should we log.Fatal here?
			continue
		}

		keys[keyId-1] = dptypes.Key{
			KeyId:    uint32(keyId),
			EncKey:   encKey,
			IcvKey:   icvKey,
			EncBlock: encBlock,
		}
		log.Debugf("Adding enc key 0x%x\n", keys[keyId-1].EncKey)
		log.Debugf("Adding icv key 0x%x\n", keys[keyId-1].IcvKey)
	}

	// XXX We are not decoding the keys for now.
	// Will have to add code for key handling in future.

	rlocEntry := dptypes.Rloc{
		Rloc:        rloc,
		Port:        port,
		Priority:    priority,
		Weight:      weight,
		KeyCount:    uint32(len(rlocStr.Keys)),
		Keys:        keys,
		Family:      uint32(family),
		Packets:     new(uint64),
		Bytes:       new(uint64),
		LastPktTime: new(int64),
	}

	defaultTime := time.Now()
	unixSeconds := defaultTime.Unix()
	*rlocEntry.LastPktTime = unixSeconds
	v4Addr := rloc.To4()
	if v4Addr == nil {
		var destAddr [16]byte

		// This is IPv6 Rloc address
		v6Addr := rloc.To16()
		for i := range destAddr {
			destAddr[i] = v6Addr[i]
		}
		rlocEntry.IPv6SockAddr.Port = 0
		rlocEntry.IPv6SockAddr.ZoneId = 0
		rlocEntry.IPv6SockAddr.Addr = destAddr
	} else {
		// This is IPv4 Rloc address
		rlocEntry.IPv4SockAddr.Port = 0
		rlocEntry.IPv4SockAddr.Addr = [4]byte{v4Addr[0], v4Addr[1], v4Addr[2], v4Addr[3]}
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
	rlocs := []dptypes.Rloc{}

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
	maskLen, _ := ipNet.Mask.Size()

	//if (maskLen != 128) && ((maskLen != 0) || !v6) {
	if (maskLen != 128) && (maskLen != 0) && (maskLen != 32) {
		// We are not interested in prefixes shorter than 128 except 0 and 32 (IPv4)
		// prefix length.
		// If we do not find a more specific route (prefix length 128(v6) or 32(v4)), we forward
		// our packets to the default route.
		log.Infof("createMapCache: Ignoring EID with mask length: %v", maskLen)
		return
	}

	// if the opcode is delete we do not have to parse
	if mapCache.Opcode == "delete" {
		log.Infof("Deleting map-cache entry for IID %v, EID %s", iid, eid.String())
		fib.DeleteMapCacheEntry(iid, eid)
		return
	}

	// If rlocs are empty bail
	if len(mapCache.Rlocs) == 0 {
		log.Infof("Received empty Rloc list for map-cache entry with IID %v, EID %s",
			iid, eid.String())
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
		log.Fatal("handleMapCacheTable: Error: Unknown json message format: " +
			string(msg) + ": " + err.Error())
	}

	numEntries := len(mapCacheTable.MapCaches)
	if numEntries == 0 {
		// This is a special case where lispers.net wants data plane
		// to flush/clear all map-cache entries.
		fib.FlushMapCache()
	}

	for _, mapCache := range mapCacheTable.MapCaches {
		createMapCache(&mapCache)
	}
	return
}

// Extract map cache message and add to our database
func handleMapCache(msg []byte) {
	var mapCache MapCacheEntry

	log.Debugf("handleMapCache: Handling the following map-cache message:\n%s", string(msg))
	err := json.Unmarshal(msg, &mapCache)
	if err != nil {
		log.Fatal("handleMapCache: Error: Unknown json message format: " +
			string(msg) + ": " + err.Error())
	}

	createMapCache(&mapCache)
}

func parseDatabaseMappings(databaseMappings DatabaseMappings) map[uint32][]net.IP {
	tmpMap := make(map[uint32][]net.IP)

	for _, entry := range databaseMappings.Mappings {
		x, err := strconv.ParseUint(entry.InstanceId, 10, 32)
		if err != nil {
			continue
		}
		iid := uint32(x)
		eid, _, err := net.ParseCIDR(entry.EidPrefix)
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

	log.Debugf("handleDatabaseMappings: Handling the following Database map message:\n%s\n",
		string(msg))
	err := json.Unmarshal(msg, &databaseMappings)
	if err != nil {
		log.Fatal("handleDatabaseMappings: Error: Unknown json message format: " +
			string(msg) + ": " + err.Error())
	}

	// lispers.net sends database-mappings as an array of iid to individual eid
	// pairs. It may have multiple rows for the same iid with different EIDs.
	// We have to convert these rows to a map of IID to list of EIDs.
	tmpMap := parseDatabaseMappings(databaseMappings)
	eidEntries := []dptypes.EIDEntry{}

	if eidEntries == nil {
		log.Errorf("handleDatabaseMappings: Allocation of EID entry slice failed")
		return
	}

	for key, data := range tmpMap {
		eidEntries = append(eidEntries, dptypes.EIDEntry{
			InstanceId: key,
			Eids:       data,
		})
	}
	fib.UpdateIfaceEids(eidEntries)
}

func handleInterfaces(msg []byte) {
	var interfaces Interfaces

	log.Debugf("handleInterfaces: Handling the following Interfaces message:\n%s\n", string(msg))
	err := json.Unmarshal(msg, &interfaces)
	if err != nil {
		log.Fatal("handleInterfaces: Error: Unknown json message format: " +
			string(msg) + ": " + err.Error())
	}
	ifaces := []dptypes.Interface{}

	if ifaces == nil {
		log.Errorf("handleInterfaces: Allocation of Interface slice failed")
		return
	}

	for _, iface := range interfaces.Interfaces {
		log.Infof("Interface: %s, Instance Id: %v", iface.Interface, iface.InstanceId)
		//x := iface.InstanceId
		x, err := strconv.ParseUint(iface.InstanceId, 10, 32)
		if err != nil {
			continue
		}
		iid := uint32(x)
		ifaces = append(ifaces, dptypes.Interface{
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

	log.Debugf("handleDecapKeys: Handling the following Decaps message:\n%s\n",
		string(msg))
	err := json.Unmarshal(msg, &decapMsg)
	if err != nil {
		log.Fatal("handleDecapKeys: Error: Unknown json message format: " +
			string(msg) + ": " + err.Error())
	}

	rloc := net.ParseIP(decapMsg.Rloc)
	if rloc == nil {
		log.Errorf("handleDecapKeys: Unparsable decap IP address %s",
			decapMsg.Rloc)
		return
	}
	port, err := strconv.Atoi(decapMsg.Port)
	if err != nil {
		log.Errorf("handleDecapKeys: Invalid decap port %s", decapMsg.Port)
		return
	}

	keys := make([]dptypes.DKey, len(decapMsg.Keys))

	for _, key := range decapMsg.Keys {
		keyId, err := strconv.ParseUint(key.KeyId, 10, 32)
		if err != nil {
			log.Errorf("handleDecapKeys: Parsing key id failed (%v), skipping current decap key\n",
				key.KeyId)
			continue
		}

		// XXX Some times lispers.net sends icv key of 40 bytes
		// with first eight bytes as zeroes.
		// Some times it sendis the right length.
		// This is a hack from our side for the time being.
		// lispers.net should fix this eventually.
		/*
			if len(key.IcvKey) == 40 {
				key.IcvKey = key.IcvKey[8:]
			}
			if (len(key.DecKey) != CRYPTO_KEY_LEN) ||
				(len(key.IcvKey) != CRYPTO_KEY_LEN) {
				log.Errorf(
					"Error: Decap/ICV Key lengths should be 32, " +
					"found encrypt key len %d & icv key length %d",
					len(key.DecKey), len(key.IcvKey))
				continue
			}
		*/
		//decKey := []byte(key.DecKey)
		decKey, err := hex.DecodeString(key.DecKey)
		if err != nil {
			log.Errorf("handleDecapKeys: Decoding decrypt key "+
				"from string to binary failed: %s",
				err)
			continue
		}
		//icvKey := []byte(key.IcvKey)
		icvKey, err := hex.DecodeString(key.IcvKey)
		if err != nil {
			log.Errorf("handleDecapKeys: Decoding ICV key from "+
				"string to binary failed: %s",
				err)
			continue
		}
		decBlock, err := aes.NewCipher(decKey)
		if err != nil {
			log.Errorf(
				"handleDecapKeys: Creating of Cipher block for "+
					"decryption key %s failed",
				key.DecKey)
			continue
		}
		keys[keyId-1] = dptypes.DKey{
			KeyId:    uint32(keyId),
			DecKey:   decKey,
			IcvKey:   icvKey,
			DecBlock: decBlock,
		}
		log.Infof("handleDecapKeys: Adding Decap key[%d] 0x%x for Rloc %s",
			keyId-1, keys[keyId-1].DecKey, decapMsg.Rloc)
		log.Infof("handleDecapKeys: Adding Decap icv[%d] 0x%x for Rloc %s",
			keyId-1, keys[keyId-1].IcvKey, decapMsg.Rloc)
	}

	// Parse and store the decap keys.
	decapEntry := dptypes.DecapKeys{
		Rloc: rloc,
		Port: port,
		Keys: keys,
	}
	fib.UpdateDecapKeys(&decapEntry)
}

func handleEtrNatPort(msg []byte) {
	var etrNatPort EtrNatPort

	log.Debugf("handleEtrNatPort: Handling the following ETR Nat port message:\n%s\n", string(msg))
	err := json.Unmarshal(msg, &etrNatPort)
	if err != nil {
		log.Fatal("handleEtrNatPort: Error: Unknown json message format: " +
			string(msg) + ": " + err.Error())
	}
	etr.HandleEtrEphPort(etrNatPort.Port)
}

func handleItrCryptoPort(msg []byte) {
	var itrCryptoPort ItrCryptoPort

	log.Debugf("handleItrCryptoPort: Handling the following ITR crypto port message:\n%s\n", string(msg))
	err := json.Unmarshal(msg, &itrCryptoPort)
	if err != nil {
		log.Fatal("handleItrCryptoPort: Error: Unknown json message format: " +
			string(msg) + ": " + err.Error())
	}
	HandleItrCryptoPort(uint(itrCryptoPort.Port))
}
