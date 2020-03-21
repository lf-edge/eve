// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Code to Add/Chance/Update map-cache entries. Also has code for storing the uplink
// ipv4/ipv6 addresses to be used for sending out LISP packets.

package fib

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/lf-edge/eve/pkg/lisp/dataplane/dptypes"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// 5 minutes scrub threshold
const SCRUBTHRESHOLD = 5 * 60
const DATABASEWRITEFILE = "/show-ztr"
const STATSPUNTINTERVAL = 10

var cache *dptypes.MapCacheTable
var decaps *dptypes.DecapTable
var upLinks dptypes.Uplinks

// presently this structure only has ITR crypto source port
var itrGlobalData dptypes.ITRGlobalData

var debug bool = false
var lispLocation string = ""
var pktBuf []byte

// ipv4 and ipv6 raw sockets respectively
var fd4 int
var fd6 int

func InitItrCryptoPort() {
	itrGlobalData.LockMe.Lock()
	defer itrGlobalData.LockMe.Unlock()
	itrGlobalData.ItrCryptoPort = 0
}

func GetItrCryptoPort() uint {
	itrGlobalData.LockMe.RLock()
	defer itrGlobalData.LockMe.RUnlock()
	return itrGlobalData.ItrCryptoPort
}

func PutItrCryptoPort(port uint) {
	itrGlobalData.LockMe.Lock()
	defer itrGlobalData.LockMe.Unlock()
	itrGlobalData.ItrCryptoPort = port
}

func newMapCache() *dptypes.MapCacheTable {
	return &dptypes.MapCacheTable{
		MapCache: make(map[dptypes.MapCacheKey]*dptypes.MapCacheEntry),
	}
}

func newDecapTable() *dptypes.DecapTable {
	return &dptypes.DecapTable{
		DecapEntries: make(map[string]*dptypes.DecapKeys),
	}
}

func InitMapCache(debugFlag bool, lispDir string) {
	var err error

	debug = debugFlag
	lispLocation = lispDir
	cache = newMapCache()

	// Init buffered packet processing buffer
	pktBuf = make([]byte, 65536)

	// create required raw sockets
	fd4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		log.Errorf("InitMapCache: FIB ipv4 raw socket creation failed")
	}
	err = syscall.SetsockoptInt(fd4, syscall.SOL_SOCKET, syscall.IP_MTU_DISCOVER,
		syscall.IP_PMTUDISC_DONT)
	if err != nil {
		log.Errorf("InitMapCache: Disabling path mtu discovery failed")
	}
	err = syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 0)
	if err != nil {
		log.Errorf("InitMapCache: Disabling IP_HDRINCL failed")
	}
	fd6, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Errorf("InitMapCache: FIB ipv6 raw socket creation failed")
	}
	// XXX We should close these sockets somewhere. Where?

	// Initialize the uplink addresses
	SetUplinkAddrs(net.IP{}, net.IP{})
}

func InitDecapTable() {
	decaps = newDecapTable()

	if decaps == nil {
		return
	}

	// Initialize ETR statistics
	currUnixSeconds := time.Now().Unix()
	decaps.NoDecryptKey = dptypes.PktStat{Pkts: 0, Bytes: 0, LastPktTime: currUnixSeconds}
	decaps.OuterHeaderError = dptypes.PktStat{Pkts: 0, Bytes: 0, LastPktTime: currUnixSeconds}
	decaps.BadInnerVersion = dptypes.PktStat{Pkts: 0, Bytes: 0, LastPktTime: currUnixSeconds}
	decaps.GoodPackets = dptypes.PktStat{Pkts: 0, Bytes: 0, LastPktTime: currUnixSeconds}
	decaps.ICVError = dptypes.PktStat{Pkts: 0, Bytes: 0, LastPktTime: currUnixSeconds}
	decaps.LispHeaderError = dptypes.PktStat{Pkts: 0, Bytes: 0, LastPktTime: currUnixSeconds}
	decaps.ChecksumError = dptypes.PktStat{Pkts: 0, Bytes: 0, LastPktTime: currUnixSeconds}
}

// Control thread looks for changes to /var/run/zedrouter/DeviceNetworkStatus/global.json
// and selects uplinks for ipv4 & ipv6 addresses. We store these uplink addresses at a
// global location. ITR threads will make READ accesses for uplink addresses simultaneously.
// Control thread can change these uplink addresses any time. Since it is not possible to
// change all the fields of UpLinkAddress structure, we allocate a new structure
// (initialize it) and then atomically change the global pointer such that it points
// to the newly allocated data structure.
//
// At the same time ITR threads atomically load the pointer to global location. Atomic read
// ensures that the pointer value is loaded from memory location rather from local storage
// (register).
func SetUplinkAddrs(ipv4 net.IP, ipv6 net.IP) {
	// Get the current uplink address and compare
	v4Addr := GetIPv4UplinkAddr()
	v6Addr := GetIPv6UplinkAddr()
	if v4Addr.Equal(ipv4) && v6Addr.Equal(ipv6) {
		log.Infof("SetUplinkAddrs: No change in Uplink addresses")
		return
	}
	upLinks.Lock()
	defer upLinks.Unlock()
	uplinks := new(dptypes.UplinkAddress)
	if uplinks == nil {
		log.Fatal("SetUplinkAddrs: Uplink address memory allocation failed.\n")
	}
	uplinks.Ipv4 = ipv4
	uplinks.Ipv6 = ipv6
	if debug {
		log.Debugf("SetUplinkAddrs: Storing pointer %p with ip4 %s, ipv6 %s",
			&uplinks, uplinks.Ipv4, uplinks.Ipv6)
	}
	upLinks.UpLinks = uplinks
}

func GetIPv4UplinkAddr() net.IP {
	upLinks.RLock()
	defer upLinks.RUnlock()
	uplinks := upLinks.UpLinks
	if uplinks == nil {
		return net.IP{}
	}
	return uplinks.Ipv4
}

func GetIPv6UplinkAddr() net.IP {
	upLinks.RLock()
	defer upLinks.RUnlock()
	uplinks := upLinks.UpLinks
	if uplinks == nil {
		return net.IP{}
	}
	return uplinks.Ipv6
}

func makeMapCacheKey(iid uint32, eid net.IP) dptypes.MapCacheKey {
	return dptypes.MapCacheKey{
		IID: iid,
		Eid: eid.String(),
	}
}

// This function will delete all map-cache entries that we have.
func FlushMapCache() {
	cache.LockMe.Lock()
	defer cache.LockMe.Unlock()

	for key := range cache.MapCache {
		delete(cache.MapCache, key)
	}
}

// Do a lookup into map cache database. If a resolved entry is not found,
// create and add an un-resolved entry for buffering packets.
func LookupAndAdd(iid uint32,
	eid net.IP, timeStamp time.Time) (*dptypes.MapCacheEntry, bool) {
	if debug {
		log.Debugf("LookupAndAdd: Adding EID %s with IID %v", eid, iid)
	}
	key := makeMapCacheKey(iid, eid)

	// we take a read lock and check if the entry that we are looking for
	// is already present in MapCacheTable
	cache.LockMe.RLock()
	entry, ok := cache.MapCache[key]
	cache.LockMe.RUnlock()

	if ok {
		if entry.Resolved {
			return entry, false
		}
		// When it is decided to make a punt, return true for the punt status
		punt := false
		var puntInterval time.Duration = 5000

		// elapsed time is in Nano seconds
		elapsed := timeStamp.Sub(entry.LastPunt)

		// convert elapsed time to milli seconds
		elapsed = (elapsed / 1000000)

		// if elapsed time is greater than 5000ms send a punt request
		// XXX Is 5 seconds for punt too high?
		if elapsed >= puntInterval {
			log.Infof("LookupAndAdd: Sending punt entry at %s for EID %s, IID %v",
				timeStamp, eid, iid)
			punt = true
			entry.LastPunt = timeStamp
		}
		return entry, punt
	}

	// if the entry is not present already, we take write lock to map cache
	// and try to add an unresolved entry (destination RLOCs still not known)
	cache.LockMe.Lock()
	defer cache.LockMe.Unlock()

	// check if someone else has already added the unresolved entry
	// before we got the write lock
	entry, ok = cache.MapCache[key]

	if ok {
		return entry, false
	} else {
		currTime := time.Now()
		resolveEntry := dptypes.MapCacheEntry{
			InstanceId:  iid,
			Eid:         eid,
			Resolved:    false,
			PktBuffer:   make(chan *dptypes.BufferedPacket, 10),
			LastPunt:    currTime,
			ResolveTime: currTime,
		}
		cache.MapCache[key] = &resolveEntry
		if debug {
			log.Debugf("LookupAndAdd: Added new map-cache entry with EID %s, IID %v",
				eid, iid)
		}
		return &resolveEntry, true
	}
}

// Add/update map cache entry. Along with that, process and send out any
// buffered packets attached to this entry.
func UpdateMapCacheEntry(iid uint32, eid net.IP, rlocs []dptypes.Rloc) {
	log.Debugf("UpdateMapCacheEntry: Updating map-cache entry with EID %s, IID %v",
		eid, iid)
	entry := LookupAndUpdate(iid, eid, rlocs)

	// Create a temporary IV to work with
	rand.Seed(time.Now().UnixNano())
	ivHigh := rand.Uint32()
	ivLow := rand.Uint64()

	itrLocalData := new(dptypes.ITRLocalData)
	itrLocalData.Fd4 = fd4
	itrLocalData.Fd6 = fd6
	itrLocalData.IvHigh = ivHigh
	itrLocalData.IvLow = ivLow

	timeStamp := time.Now()
	for {
		select {
		case pkt, ok := <-entry.PktBuffer:
			if ok {
				// XXX Hmm.. This section of code might need some re-writing, but
				// i'll keep it this way for now.

				// send the packet out
				capLen := uint32(len(pkt.Packet))

				// copy packet bytes into pktBuf at an offset of MAXHEADERLEN bytes
				// ipv6 (40) + UDP (8) + LISP (8) - ETHERNET (14) + LISP IV (16) = 58
				copy(pktBuf[dptypes.MAXHEADERLEN:], pkt.Packet)

				// Send the packet out now
				CraftAndSendLispPacket(pktBuf, uint32(capLen), timeStamp,
					pkt.Hash32, entry, entry.InstanceId, itrLocalData)
				log.Debugf("UpdateMapCacheEntry: Sending out buffered packet for map-cache "+
					"entry with EID %s, IID %v", eid, iid)

				// decrement buffered packet count
				atomic.AddUint64(&entry.BuffdPkts, ^uint64(0))

				// XXX We do not show these counters. We might need these in future.
				//atomic.AddUint64(&entry.Packets, 1)
				//atomic.AddUint64(&entry.Bytes, uint64(capLen))
			} else {
				// channel might have been closed
				return
			}
		default:
			// Do not close the channel. We might have taken the write lock
			// just before another ITR thread adds packet to buffered channel.
			// ITR thread might try adding/reading packet from buffered channel.
			// Keep the channel around and let the GC take care of freeing the
			// memory, when we delete corresponding map cache entry.
			return
		}
	}
}

// Compile the given rlocs according to their priorities and prepare a load
// balance list.
// Note: We only consider the highest priority RLOCs and ignore other priorities
func compileRlocs(rlocs []dptypes.Rloc) ([]dptypes.Rloc, uint32) {
	var highPrio uint32 = 0xFFFFFFFF
	selectRlocs := []dptypes.Rloc{}
	var totWeight uint32 = 0
	var wrStart uint32 = 0

	// Find the highest priority available
	for _, rloc := range rlocs {
		if highPrio > rloc.Priority {
			highPrio = rloc.Priority
		}
	}

	// Create high priority Rloc list
	for _, rloc := range rlocs {
		if rloc.Priority == highPrio {
			selectRlocs = append(selectRlocs, rloc)
			// keep accumulating weights also
			totWeight += rloc.Weight
		}
	}

	// Assign weight ranges to each of the selected rlocs
	// Each RLOC will get a weight range proportional to it's weight.
	// For example if there are three RLOCs (say r1, r2, r3) with weights
	// 10, 30, 60 respectively, then the weight ranges assigned to them will
	// be (0 - 9), (10 - 39), (40 - 99) respectively.
	for i := range selectRlocs {
		low := wrStart
		high := low + selectRlocs[i].Weight - 1
		wrStart = high + 1

		selectRlocs[i].WrLow = low
		selectRlocs[i].WrHigh = high
		log.Debugf("compileRlocs: Adding weights: %v, %v", low, high)
	}

	return selectRlocs, totWeight
}

// Add/update map cache entry. Look at the comments inside this function to understand
// more about what it does.
func LookupAndUpdate(iid uint32, eid net.IP, rlocs []dptypes.Rloc) *dptypes.MapCacheEntry {
	var selectRlocs []dptypes.Rloc
	var totWeight uint32
	var packets, bytes, tailDrops, buffdPkts uint64
	var lastPunt time.Time

	key := makeMapCacheKey(iid, eid)

	selectRlocs, totWeight = compileRlocs(rlocs)

	cache.LockMe.RLock()
	entry, ok := cache.MapCache[key]
	cache.LockMe.RUnlock()

	resolved := true
	// If RLOC list is empty we mark the map-cache entry as un-resolved.
	if len(selectRlocs) == 0 {
		resolved = false

		// There are some packets that come from domU destined to bridge
		// IP address. For such packets lispers.net will never have
		// an answer.
		// Check if the existing entry in map-cache table also has empty RLOC list.
		// If yes, return from here.
		if ok && (len(entry.Rlocs) == 0) {
			return entry
		}
	}
	log.Infof("LookupAndUpdate: Adding map-cache entry with key IID %d, EID %s",
		key.IID, key.Eid)

	if ok && (entry.Resolved == true) {
		// Delete the old map cache entry
		// Another ITR thread might have taken a pointer to this entry
		// and is still working on packet. If we start updating this entry,
		// the other ITR thread will read data in unfinished state (corrupted).
		// To avoid this, we delete the entry and add newly created entry.
		// Since the ITR thread still has pointer to the old entry, it will not
		// be garbage collected. Subsequent packets will hit updated entry.

		// Before deleting the map cache entry copy statistics
		// We do not have to do atomic operation, because we hold write lock
		packets = entry.Packets
		bytes = entry.Bytes
		tailDrops = entry.TailDrops
		buffdPkts = entry.BuffdPkts
		lastPunt = entry.LastPunt

		if debug {
			log.Debugf("LookupAndUpdate: Deleting map-cache entry with EID %s, IID %v "+
				"before adding new entry", key.Eid, key.IID)
		}
	} else if ok {
		// Entry is in unresolved state. Update the RLOCs and mark the entry
		// as resolved.
		if debug {
			log.Debugf("LookupAndUpdate: Resolving unresolved entry with EID %s, IID %v",
				key.Eid, key.IID)
		}

		cache.LockMe.Lock()
		defer cache.LockMe.Unlock()

		entry.Rlocs = selectRlocs
		entry.RlocTotWeight = totWeight
		entry.Resolved = resolved
		entry.LastPunt = time.Now()
		return entry
	}
	// allocate new MapCacheEntry and add to table
	// We will only use the highest priority rlocs and ignore rlocs with
	// other priorities
	newEntry := dptypes.MapCacheEntry{
		InstanceId:    iid,
		Eid:           eid,
		Resolved:      resolved,
		Rlocs:         selectRlocs,
		RlocTotWeight: totWeight,
		PktBuffer:     make(chan *dptypes.BufferedPacket, 10),
		LastPunt:      lastPunt,
		Packets:       packets,
		Bytes:         bytes,
		TailDrops:     tailDrops,
		BuffdPkts:     buffdPkts,
	}
	cache.LockMe.Lock()
	defer cache.LockMe.Unlock()
	delete(cache.MapCache, key)
	cache.MapCache[key] = &newEntry
	return &newEntry
}

func DeleteMapCacheEntry(iid uint32, eid net.IP) {
	key := makeMapCacheKey(iid, eid)
	cache.LockMe.Lock()
	defer cache.LockMe.Unlock()
	delete(cache.MapCache, key)
	// Existing packet buffer channels and any packets will be garbage
	// collected later
}

func AddDecapStatistics(statName string, pkts uint64,
	bytes uint64, unixSeconds int64) {
	switch statName {
	case "no-decrypt-key":
		atomic.AddUint64(&decaps.NoDecryptKey.Pkts, pkts)
		atomic.AddUint64(&decaps.NoDecryptKey.Bytes, bytes)
		atomic.StoreInt64(&decaps.NoDecryptKey.LastPktTime, unixSeconds)
	case "outer-header-error":
		atomic.AddUint64(&decaps.OuterHeaderError.Pkts, pkts)
		atomic.AddUint64(&decaps.OuterHeaderError.Bytes, bytes)
		atomic.StoreInt64(&decaps.OuterHeaderError.LastPktTime, unixSeconds)
	case "bad-inner-version":
		atomic.AddUint64(&decaps.BadInnerVersion.Pkts, pkts)
		atomic.AddUint64(&decaps.BadInnerVersion.Bytes, bytes)
		atomic.StoreInt64(&decaps.BadInnerVersion.LastPktTime, unixSeconds)
	case "good-packets":
		atomic.AddUint64(&decaps.GoodPackets.Pkts, pkts)
		atomic.AddUint64(&decaps.GoodPackets.Bytes, bytes)
		atomic.StoreInt64(&decaps.GoodPackets.LastPktTime, unixSeconds)
	case "ICV-error":
		atomic.AddUint64(&decaps.ICVError.Pkts, pkts)
		atomic.AddUint64(&decaps.ICVError.Bytes, bytes)
		atomic.StoreInt64(&decaps.ICVError.LastPktTime, unixSeconds)
	case "lisp-header-error":
		atomic.AddUint64(&decaps.LispHeaderError.Pkts, pkts)
		atomic.AddUint64(&decaps.LispHeaderError.Bytes, bytes)
		atomic.StoreInt64(&decaps.LispHeaderError.LastPktTime, unixSeconds)
	case "checksum-error":
		atomic.AddUint64(&decaps.ChecksumError.Pkts, pkts)
		atomic.AddUint64(&decaps.ChecksumError.Bytes, bytes)
		atomic.StoreInt64(&decaps.ChecksumError.LastPktTime, unixSeconds)
	}
}

func StoreEtrNatPort(port int32) {
	atomic.StoreInt32(&decaps.EtrNatPort, port)
}

func GetEtrNatPort() int32 {
	return atomic.LoadInt32(&decaps.EtrNatPort)
}

func UpdateDecapKeys(entry *dptypes.DecapKeys) {
	if decaps == nil {
		return
	}
	decaps.LockMe.Lock()
	defer decaps.LockMe.Unlock()
	key := entry.Rloc.String()
	decaps.DecapEntries[key] = entry
}

func LookupDecapKeys(ip net.IP) *dptypes.DecapKeys {
	if decaps == nil {
		return nil
	}
	decaps.LockMe.RLock()
	defer decaps.LockMe.RUnlock()
	key := ip.String()
	decapKeys, ok := decaps.DecapEntries[key]
	if ok {
		return decapKeys
	}
	log.Debugf("LookupDecapKeys: Decap keys cannot be found for %s",
		ip.String())
	return nil
}

func ShowMapCacheEntries() {
	cache.LockMe.RLock()
	defer cache.LockMe.RUnlock()

	log.Println("##### MAP CACHE ENTRIES #####")
	for key, value := range cache.MapCache {
		log.Println("Key IID:", key.IID)
		log.Printf("Key Eid: %s\n", key.Eid)
		log.Println("Rlocs:")
		for _, rloc := range value.Rlocs {
			log.Printf("	RLOC: %s\n", rloc.Rloc)
			log.Printf("	RLOC Packets: %v\n", atomic.LoadUint64(rloc.Packets))
			log.Printf("	RLOC Bytes: %v\n", atomic.LoadUint64(rloc.Bytes))
			log.Printf("	RLOC Keys:\n")
			for _, key := range rloc.Keys {
				keyId := key.KeyId
				if keyId == 0 {
					continue
				}
				log.Printf("		key[%d].EncKey: %x\n", keyId, key.EncKey)
				log.Printf("		key[%d].IcvKey: %x\n", keyId, key.IcvKey)
			}
		}
		log.Printf("Packets: %v\n", value.Packets)
		log.Printf("Bytes: %v\n", value.Bytes)
		log.Printf("TailDrops: %v\n", value.TailDrops)
		log.Printf("BuffdPkts: %v\n", value.BuffdPkts)
		log.Println()
	}
	log.Println()
}

func ShowDecapKeys() {
	if decaps == nil {
		return
	}
	decaps.LockMe.RLock()
	defer decaps.LockMe.RUnlock()

	log.Println("##### DECAP KEYS #####")
	for rloc, entry := range decaps.DecapEntries {
		log.Println("Rloc:", rloc)
		for _, key := range entry.Keys {
			keyId := key.KeyId
			if keyId == 0 {
				continue
			}
			log.Printf("	key[%d].Deckey: %x\n", keyId, key.DecKey)
			log.Printf("	key[%d].Icvkey: %x\n", keyId, key.IcvKey)
		}
	}
	log.Println()
}

// This thread wakes up every minute, to find the map cache entries that are
// in resolve state for more than 5 minutes. Resolve entries that are older than
// 5 minutes will be deleted.
func MapcacheScrubThread() {
	log.Infof("Starting map-cache scrubber thread")
	// scrubber thread wakes up every 1 minute and scrubs
	// map-cache entries in resolve status for more than 5 minutes.
	for {
		time.Sleep(60 * time.Second)
		delList := []dptypes.MapCacheKey{}

		cache.LockMe.RLock()

		// Iterate through the map-cache table and make note of the entries
		// that need removal (entries in resolve state for more than 5 minutes).
		// We take write lock later and delete the required entries.
		for key, entry := range cache.MapCache {
			if entry.Resolved == false {

				currTime := time.Now()

				// SCRUBTHRESHOLD * 1000 milli seconds threshold interval
				var scrubThreshold time.Duration = SCRUBTHRESHOLD * 1000

				// elapsed time is in Nano seconds
				elapsed := currTime.Sub(entry.ResolveTime)

				// convert elapsed time to milli seconds
				elapsed = (elapsed / 1000000)

				// if elapsed time is greater than scrub threshold
				// send delete resolve entry
				if elapsed >= scrubThreshold {
					// mark the resolve entry for deletion
					delList = append(delList, key)
				}
			}
		}
		cache.LockMe.RUnlock()

		// take write lock and delete the stale entries
		cache.LockMe.Lock()
		for _, key := range delList {
			log.Infof("MapcacheScrubThread: Removing resolve entry with iid %v, eid %s",
				key.IID, key.Eid)
			delete(cache.MapCache, key)
		}
		cache.LockMe.Unlock()
	}
}

func sendEncapStatistics(puntChannel chan []byte) *dptypes.LispStatistics {
	// Take read lock of map cache table
	// and go through each entry while preparing statistics message
	// We hold the lock while we iterate through the table.

	cache.LockMe.RLock()

	var lispStatistics dptypes.LispStatistics
	lispStatistics.Type = "statistics"

	for key, value := range cache.MapCache {
		var eidStats dptypes.EidStatsEntry
		eidStats.InstanceId = strconv.FormatUint(uint64(key.IID), 10)
		prefixLength := "/128"
		if key.Eid == "::" {
			prefixLength = "/0"
		}
		eidStats.EidPrefix = key.Eid + prefixLength
		eidStats.Rlocs = []dptypes.RlocStatsEntry{}
		for _, rloc := range value.Rlocs {

			var rlocStats dptypes.RlocStatsEntry
			rlocStats.Rloc = rloc.Rloc.String()
			rlocStats.PacketCount = atomic.SwapUint64(rloc.Packets, 0)
			rlocStats.ByteCount = atomic.SwapUint64(rloc.Bytes, 0)
			currUnixSecs := time.Now().Unix()
			lastPktSecs := atomic.LoadInt64(rloc.LastPktTime)
			rlocStats.SecondsSinceLastPkt = currUnixSecs - lastPktSecs

			eidStats.Rlocs = append(eidStats.Rlocs, rlocStats)
		}
		lispStatistics.Entries = append(lispStatistics.Entries, eidStats)
	}
	cache.LockMe.RUnlock()

	// Send out ITR encap statistics to lispers.net
	statsMsg, err := json.Marshal(lispStatistics)
	log.Debugf("sendEncapStatistics: %s", string(statsMsg))
	if err != nil {
		log.Errorf("Error: Encoding encap statistics")
	} else {
		puntChannel <- statsMsg
	}
	return &lispStatistics
}

func sendDecapStatistics(puntChannel chan []byte) *dptypes.DecapStatistics {
	var decapStatistics dptypes.DecapStatistics
	decapStatistics.Type = "decap-statistics"
	currUnixSecs := time.Now().Unix()
	decapStatistics.NoDecryptKey.Pkts = atomic.SwapUint64(&decaps.NoDecryptKey.Pkts, 0)
	decapStatistics.NoDecryptKey.Bytes = atomic.SwapUint64(&decaps.NoDecryptKey.Bytes, 0)
	lastPktTime := atomic.LoadInt64(&decaps.NoDecryptKey.LastPktTime)
	decapStatistics.NoDecryptKey.LastPktTime = currUnixSecs - lastPktTime

	decapStatistics.OuterHeaderError.Pkts = atomic.SwapUint64(&decaps.OuterHeaderError.Pkts, 0)
	decapStatistics.OuterHeaderError.Bytes = atomic.SwapUint64(&decaps.OuterHeaderError.Bytes, 0)
	lastPktTime = atomic.LoadInt64(&decaps.OuterHeaderError.LastPktTime)
	decapStatistics.OuterHeaderError.LastPktTime = currUnixSecs - lastPktTime

	decapStatistics.BadInnerVersion.Pkts = atomic.SwapUint64(&decaps.BadInnerVersion.Pkts, 0)
	decapStatistics.BadInnerVersion.Bytes = atomic.SwapUint64(&decaps.BadInnerVersion.Bytes, 0)
	lastPktTime = atomic.LoadInt64(&decaps.BadInnerVersion.LastPktTime)
	decapStatistics.BadInnerVersion.LastPktTime = currUnixSecs - lastPktTime

	decapStatistics.GoodPackets.Pkts = atomic.SwapUint64(&decaps.GoodPackets.Pkts, 0)
	decapStatistics.GoodPackets.Bytes = atomic.SwapUint64(&decaps.GoodPackets.Bytes, 0)
	lastPktTime = atomic.LoadInt64(&decaps.GoodPackets.LastPktTime)
	decapStatistics.GoodPackets.LastPktTime = currUnixSecs - lastPktTime

	decapStatistics.ICVError.Pkts = atomic.SwapUint64(&decaps.ICVError.Pkts, 0)
	decapStatistics.ICVError.Bytes = atomic.SwapUint64(&decaps.ICVError.Bytes, 0)
	lastPktTime = atomic.LoadInt64(&decaps.ICVError.LastPktTime)
	decapStatistics.ICVError.LastPktTime = currUnixSecs - lastPktTime

	decapStatistics.LispHeaderError.Pkts = atomic.SwapUint64(&decaps.LispHeaderError.Pkts, 0)
	decapStatistics.LispHeaderError.Bytes = atomic.SwapUint64(&decaps.LispHeaderError.Bytes, 0)
	lastPktTime = atomic.LoadInt64(&decaps.LispHeaderError.LastPktTime)
	decapStatistics.LispHeaderError.LastPktTime = currUnixSecs - lastPktTime

	decapStatistics.ChecksumError.Pkts = atomic.SwapUint64(&decaps.ChecksumError.Pkts, 0)
	decapStatistics.ChecksumError.Bytes = atomic.SwapUint64(&decaps.ChecksumError.Bytes, 0)
	lastPktTime = atomic.LoadInt64(&decaps.ChecksumError.LastPktTime)
	decapStatistics.ChecksumError.LastPktTime = currUnixSecs - lastPktTime

	// Send out ETR decap statistics to lispers.net
	decapStatsMsg, err := json.Marshal(decapStatistics)
	log.Debugf("sendDecapStatistics: %s", string(decapStatsMsg))
	if err != nil {
		log.Errorf("Error: Encoding decap statistics")
	} else {
		puntChannel <- decapStatsMsg
	}
	return &decapStatistics
}

func dumpDatabaseState() {
	// open the database dump file
	dumpFile := lispLocation + DATABASEWRITEFILE
	f, err := os.Create(dumpFile)
	if err != nil {
		log.Errorf("dumpDatabaseState: Failed opening dump file (%s) with err: %s",
			dumpFile, err)
		return
	}
	// Get a buffered writer since we are going go make multiple writes.
	w := bufio.NewWriter(f)

	t := time.Now()
	dataAndTime := fmt.Sprintf("\033[1mZededa LISP Data-plane running at %s\033[0m\n",
		t.UTC().Format(time.UnixDate))
	w.WriteString(dataAndTime)

	w.WriteString("\033[1mLISP zTR state:\033[0m\n")
	msg := fmt.Sprintf("  LISP dataplane debugging enabled: %v\n", debug)
	w.WriteString(msg)

	itrCryptoPort := GetItrCryptoPort()
	msg = fmt.Sprintf("  LISP ITR crypto port: %v\n", itrCryptoPort)
	w.WriteString(msg)

	etrNatPort := GetEtrNatPort()
	msg = fmt.Sprintf("  LISP ETR Nat port: %v\n", etrNatPort)
	w.WriteString(msg)

	interfaces := GetInterfaces()
	ifnameList := "[ "
	for _, ifname := range interfaces {
		ifnameList += ifname + " "
	}
	ifnameList += "]"
	msg = fmt.Sprintf("  LISP Interfaces: %s\n", ifnameList)
	w.WriteString(msg)

	ifaceEids := GetIfaceEIDs()
	eidList := ""
	for _, eid := range ifaceEids {
		eidList += "    [ " + eid + " ]\n"
	}
	msg = fmt.Sprintf("  LISP database mappings:\n%s\n", eidList)
	w.WriteString(msg)

	// Dump map-cache entries
	cache.LockMe.RLock()

	w.WriteString("\033[1mMap-Cache Entries:\033[0m\n")
	for key, value := range cache.MapCache {
		msg = fmt.Sprintf("EID: [%d]%s\n", key.IID, key.Eid)
		w.WriteString(msg)

		rlocStrs := []string{}
		for _, rloc := range value.Rlocs {
			rlocStrs = append(rlocStrs, rloc.Rloc.String())
		}
		rlocList := fmt.Sprintf("%s", rlocStrs)
		rlocSet := strings.Replace(rlocList, " ", ", ", -1)
		msg = "[ " + rlocSet + " ]"
		msg = fmt.Sprintf("  RLOC-set: %s\n", rlocSet)
		w.WriteString(msg)
	}
	cache.LockMe.RUnlock()
	w.WriteString("\n")

	// Dump decap entries
	if decaps == nil {
		return
	}
	decaps.LockMe.RLock()

	w.WriteString("\033[1mDecap-Keys:\033[0m\n")
	for rloc, keys := range decaps.DecapEntries {
		msg = fmt.Sprintf("  RLOC: %s:%d, key-ids [%d]\n",
			rloc, keys.Port, len(keys.Keys))
		w.WriteString(msg)
	}
	decaps.LockMe.RUnlock()

	w.Flush()
}

// Stats thread starts every STATSPUNTINTERVAL seconds
// and punts map cache statistics to lispers.net.
func StatsThread(puntChannel chan []byte,
	ctx *dptypes.DataplaneContext) {
	log.Infof("Starting statistics thread")
	ticker := time.NewTicker(STATSPUNTINTERVAL * time.Second)
	for {
		for range ticker.C {
			// Send out encap & decap statistics to lispers.net
			encapStats := sendEncapStatistics(puntChannel)
			decapStats := sendDecapStatistics(puntChannel)
			PublishLispMetrics(ctx, encapStats, decapStats)

			// Keep dumping our encap & decap state to a file on disk
			// Do it only when the debug flag is enabled
			//if debug {
			dumpDatabaseState()
			//}
		}
	}
}

func publishLispInfoStatus(ctx *dptypes.DataplaneContext,
	status *types.LispInfoStatus) {
	// XXX What key should I use?
	// It is just one message for all services.
	// Hardcoded for now.
	key := "global"
	pub := ctx.PubLispInfoStatus
	pub.Publish(key, *status)
	log.Infof("publishLispInfoStatus: Done")
}

func unpublishLispInfoStatus(ctx *dptypes.DataplaneContext,
	status *types.LispInfoStatus) {
	// XXX What key should I use?
	// It is just one message for all services.
	// Hardcoded for now.
	key := "global"
	pub := ctx.PubLispInfoStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishLispInfoStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Infof("unpublishLispInfoStatus: Done")
}

func PublishLispInfoStatus(ctx *dptypes.DataplaneContext) {
	// Prepare Lisp info status and publish to zedrouter
	etrNatPort := GetEtrNatPort()
	if etrNatPort == -1 {
		etrNatPort = 0
	}
	status := &types.LispInfoStatus{
		ItrCryptoPort: uint64(GetItrCryptoPort()),
		EtrNatPort:    uint64(etrNatPort),
		Interfaces:    GetInterfaces(),
	}

	// Fill map cache entries
	dbMap := make(map[uint32]*types.LispDatabaseMap)
	if dbMap == nil {
		return
	}
	cache.LockMe.RLock()
	for key, value := range cache.MapCache {
		var mapEntry *types.LispDatabaseMap
		ok := false
		mapEntry, ok = dbMap[key.IID]
		if !ok {
			mapEntry = &types.LispDatabaseMap{
				IID: uint64(key.IID),
			}
			dbMap[key.IID] = mapEntry
		}
		lispRlocs := []types.LispRlocState{}
		for _, rloc := range value.Rlocs {
			lispRloc := types.LispRlocState{
				Rloc: rloc.Rloc,
				// XXX Reachability is always true for now.
				// Later when we have a way to figure out reachability,
				// we should fill the right value.
				Reachable: true,
			}
			lispRlocs = append(lispRlocs, lispRloc)
		}
		mapCacheEntry := types.LispMapCacheEntry{
			EID:   value.Eid,
			Rlocs: lispRlocs,
		}
		mapEntry.MapCacheEntries = append(mapEntry.MapCacheEntries, mapCacheEntry)
	}
	cache.LockMe.RUnlock()

	for _, entry := range dbMap {
		status.DatabaseMaps = append(status.DatabaseMaps, *entry)
	}

	// Fill decap keys
	decaps.LockMe.RLock()
	for _, keys := range decaps.DecapEntries {
		decapEntry := types.LispDecapKey{
			Rloc:     keys.Rloc,
			Port:     uint64(keys.Port),
			KeyCount: uint64(len(keys.Keys)),
		}
		status.DecapKeys = append(status.DecapKeys, decapEntry)
	}
	decaps.LockMe.RUnlock()

	publishLispInfoStatus(ctx, status)
}

func publishLispMetrics(ctx *dptypes.DataplaneContext,
	status *types.LispMetrics) {
	// XXX What key should I use?
	// It is just one message for all services.
	// Hardcoded for now.
	key := "global"
	pub := ctx.PubLispMetrics
	pub.Publish(key, *status)
	log.Debugf("publishLispMetrics: Done")
}

func unpublishLispMetrics(ctx *dptypes.DataplaneContext,
	status *types.LispMetrics) {
	// XXX What key should I use?
	// It is just one message for all services.
	// Hardcoded for now.
	key := "global"
	pub := ctx.PubLispMetrics
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishLispMetrics(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Infof("unpublishLispMetrics: Done")
}

func PublishLispMetrics(ctx *dptypes.DataplaneContext,
	encapStatistics *dptypes.LispStatistics,
	decapStatistics *dptypes.DecapStatistics) {

	// Fill decap statistics
	status := types.LispMetrics{
		NoDecryptKey: types.LispPktStat{
			Pkts:  decapStatistics.NoDecryptKey.Pkts,
			Bytes: decapStatistics.NoDecryptKey.Bytes,
		},
		OuterHeaderError: types.LispPktStat{
			Pkts:  decapStatistics.OuterHeaderError.Pkts,
			Bytes: decapStatistics.OuterHeaderError.Bytes,
		},
		BadInnerVersion: types.LispPktStat{
			Pkts:  decapStatistics.BadInnerVersion.Pkts,
			Bytes: decapStatistics.BadInnerVersion.Bytes,
		},
		GoodPackets: types.LispPktStat{
			Pkts:  decapStatistics.GoodPackets.Pkts,
			Bytes: decapStatistics.GoodPackets.Bytes,
		},
		ICVError: types.LispPktStat{
			Pkts:  decapStatistics.ICVError.Pkts,
			Bytes: decapStatistics.ICVError.Bytes,
		},
		LispHeaderError: types.LispPktStat{
			Pkts:  decapStatistics.LispHeaderError.Pkts,
			Bytes: decapStatistics.LispHeaderError.Bytes,
		},
		CheckSumError: types.LispPktStat{
			Pkts:  decapStatistics.ChecksumError.Pkts,
			Bytes: decapStatistics.ChecksumError.Bytes,
		},
	}
	mapEntries := GetEidMaps()
	var eidMaps []types.EidMap
	for _, mapEntry := range mapEntries {
		eidMap := types.EidMap{
			IID:  uint64(mapEntry.InstanceId),
			Eids: mapEntry.Eids,
		}
		eidMaps = append(eidMaps, eidMap)
	}
	status.EidMaps = eidMaps

	// Parse encap statistics
	for _, entry := range encapStatistics.Entries {
		iid, err := strconv.ParseUint(entry.InstanceId, 10, 64)
		if err != nil {
			continue
		}
		eidAddr, _, err := net.ParseCIDR(entry.EidPrefix)
		if err != nil {
			continue
		}
		rlocStats := []types.LispRlocStatistics{}

		for _, rlocStat := range entry.Rlocs {
			rloc := net.ParseIP(rlocStat.Rloc)
			if rloc == nil {
				continue
			}
			pktCount := rlocStat.PacketCount
			byteCount := rlocStat.ByteCount
			sslp := rlocStat.SecondsSinceLastPkt

			rlocStatEntry := types.LispRlocStatistics{
				Rloc:                   rloc,
				SecondsSinceLastPacket: uint64(sslp),
				Stats: types.LispPktStat{
					Pkts:  pktCount,
					Bytes: byteCount,
				},
			}
			rlocStats = append(rlocStats, rlocStatEntry)
		}
		eidStat := types.EidStatistics{
			IID:       iid,
			Eid:       eidAddr,
			RlocStats: rlocStats,
		}
		status.EidStats = append(status.EidStats, eidStat)
	}
	publishLispMetrics(ctx, &status)
}
