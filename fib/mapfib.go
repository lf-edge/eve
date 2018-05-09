// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Code to Add/Chance/Update map-cache entries. Also has code for storing the uplink
// ipv4/ipv6 addresses to be used for sending out LISP packets.

package fib

import (
	"encoding/json"
	"github.com/zededa/lisp/dataplane/dptypes"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

const SCRUBTHRESHOLD = 5 * 60

var cache *dptypes.MapCacheTable
var decaps *dptypes.DecapTable
var upLinks dptypes.Uplinks

var debug bool = false
var pktBuf []byte

// ipv4 and ipv6 raw sockets respectively
var fd4 int
var fd6 int

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

func InitMapCache(debugFlag bool) {
	var err error

	debug = debugFlag
	cache = newMapCache()

	// Init buffered packet processing buffer
	pktBuf = make([]byte, 65536)

	// create required raw sockets
	fd4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		log.Printf("InitMapCache: FIB ipv4 raw socket creation failed.\n")
	}
	err = syscall.SetsockoptInt(fd4, syscall.SOL_SOCKET, syscall.IP_MTU_DISCOVER,
		syscall.IP_PMTUDISC_DONT)
	if err != nil {
		log.Printf("InitMapCache: Disabling path mtu discovery failed.\n")
	}
	err = syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 0)
	if err != nil {
		log.Printf("InitMapCache: Disabling IP_HDRINCL failed.\n")
	}
	fd6, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("InitMapCache: FIB ipv6 raw socket creation failed.\n")
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

	// Allocate ETR statistics
	decaps.NoDecryptKey = new(uint64)
	decaps.OuterHeaderError = new(uint64)
	decaps.BadInnerVersion = new(uint64)
	decaps.GoodPackets = new(uint64)
	decaps.ICVError = new(uint64)
	decaps.LispHeaderError = new(uint64)
	decaps.ChecksumError = new(uint64)
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
	upLinks.Lock()
	defer upLinks.Unlock()
	uplinks := new(dptypes.UplinkAddress)
	if uplinks == nil {
		log.Fatal("SetUplinkAddrs: Uplink address memory allocation failed.\n")
	}
	uplinks.Ipv4 = ipv4
	uplinks.Ipv6 = ipv6
	log.Printf("XXXXX Storing pointer %p with ip4 %s, ipv6 %s\n",
		&uplinks, uplinks.Ipv4, uplinks.Ipv6)
	if debug {
		log.Printf("SetUplinkAddrs: Storing pointer %p with ip4 %s, ipv6 %s\n",
			&uplinks, uplinks.Ipv4, uplinks.Ipv6)
	}
	upLinks.UpLinks = uplinks
}

func GetIPv4UplinkAddr() net.IP {
	upLinks.RLock()
	defer upLinks.RUnlock()
	uplinks := upLinks.UpLinks
	return uplinks.Ipv4
}

func GetIPv6UplinkAddr() net.IP {
	upLinks.RLock()
	defer upLinks.RUnlock()
	uplinks := upLinks.UpLinks
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
		log.Printf("LookupAndAdd: Adding EID %s with IID %v\n", eid, iid)
	}
	key := makeMapCacheKey(iid, eid)

	// we take a read look and check if the entry that we are looking for
	// is already present in MapCacheTable
	cache.LockMe.RLock()
	entry, ok := cache.MapCache[key]
	cache.LockMe.RUnlock()

	if ok {
		// XXX Add code to take care of periodic punting of packets
		// to control plane. When it is decided to make a periodic punt
		// return true for the punt status
		punt := false
		var puntInterval time.Duration = 30000

		if entry.Resolved == false {
			if debug {
				log.Printf("LookupAndAdd: Entry with EID %s, IID %v in unresolved state\n",
					eid, iid)
			}
			puntInterval = 5000
		}

		// elapsed time is in Nano seconds
		elapsed := timeStamp.Sub(entry.LastPunt)

		// convert elapsed time to milli seconds
		elapsed = (elapsed / 1000000)

		// if elapsed time is greater than 30000ms send a punt request
		// XXX Is 30 seconds for punt too high?
		if elapsed >= puntInterval {
			if debug {
				log.Printf("LookupAndAdd: Sending punt entry for EID %s, IID %v\n",
					eid, iid)
			}
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
			log.Printf("LookupAndAdd: Added new map-cache entry with EID %s, IID %v\n",
				eid, iid)
		}
		return &resolveEntry, true
	}
}

// Add/update map cache entry. Along with that process and send out and
// buffered packets attached to this entry.
func UpdateMapCacheEntry(iid uint32, eid net.IP, rlocs []dptypes.Rloc) {
	if debug {
		log.Printf("UpdateMapCacheEntry: Updating map-cache entry with EID %s, IID %v\n",
			eid, iid)
	}
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
				pktBytes := pkt.Packet.Data()
				capLen := len(pktBytes)

				// copy packet bytes into pktBuf at an offset of MAXHEADERLEN bytes
				// ipv6 (40) + UDP (8) + LISP (8) - ETHERNET (14) + LISP IV (16) = 58
				copy(pktBuf[dptypes.MAXHEADERLEN:], pktBytes)

				// Send the packet out now
				CraftAndSendLispPacket(pkt.Packet, pktBuf, uint32(capLen), timeStamp,
					pkt.Hash32, entry, entry.InstanceId, itrLocalData)
				if debug {
					log.Printf("UpdateMapCacheEntry: Sending out buffered packet for map-cache "+
						"entry with EID %s, IID %v\n", eid, iid)
				}

				// decrement buffered packet count and increment pkt, byte counts
				atomic.AddUint64(&entry.BuffdPkts, ^uint64(0))
				atomic.AddUint64(&entry.Packets, 1)
				atomic.AddUint64(&entry.Bytes, uint64(capLen))
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
	for i, _ := range selectRlocs {
		low := wrStart
		high := low + selectRlocs[i].Weight - 1
		wrStart = high + 1

		selectRlocs[i].WrLow = low
		selectRlocs[i].WrHigh = high
		if debug {
			log.Println("compileRlocs: Adding weights:", low, high)
		}
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
	cache.LockMe.Lock()
	defer cache.LockMe.Unlock()
	entry, ok := cache.MapCache[key]

	log.Printf("LookupAndUpdate: Adding map-cache entry with key IID %d, EID %s\n",
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
			log.Printf("LookupAndUpdate: Deleting map-cache entry with EID %s, IID %v "+
				"before adding new entry\n", key.Eid, key.IID)
		}
		delete(cache.MapCache, key)
	} else if ok {
		// Entry is in unresolved state. Update the RLOCs and mark the entry
		// as resolved.
		if debug {
			log.Printf("LookupAndUpdate: Resolving unresolved entry with EID %s, IID %v\n",
				key.Eid, key.IID)
		}
		selectRlocs, totWeight = compileRlocs(rlocs)
		entry.Rlocs = selectRlocs
		entry.RlocTotWeight = totWeight
		entry.Resolved = true
		entry.LastPunt = time.Now()
		return entry
	}
	// allocate new MapCacheEntry and add to table
	// We will only use the highest priority rlocs and ignore rlocs with
	// other priorities
	selectRlocs, totWeight = compileRlocs(rlocs)
	newEntry := dptypes.MapCacheEntry{
		InstanceId:    iid,
		Eid:           eid,
		Resolved:      true,
		Rlocs:         selectRlocs,
		RlocTotWeight: totWeight,
		PktBuffer:     make(chan *dptypes.BufferedPacket, 10),
		LastPunt:      lastPunt,
		Packets:       packets,
		Bytes:         bytes,
		TailDrops:     tailDrops,
		BuffdPkts:     buffdPkts,
	}
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

func AddDecapStatistics(statName string, count uint64) {
	switch statName {
	case "no-decrypt-key":
		atomic.SwapUint64(decaps.NoDecryptKey, count)
	case "outer-header-error":
		atomic.SwapUint64(decaps.OuterHeaderError, count)
	case "bad-inner-version":
		atomic.SwapUint64(decaps.BadInnerVersion, count)
	case "good-packets":
		atomic.SwapUint64(decaps.GoodPackets, count)
	case "ICV-error":
		atomic.SwapUint64(decaps.ICVError, count)
	case "lisp-header-error":
		atomic.SwapUint64(decaps.LispHeaderError, count)
	case "checksum-error":
		atomic.SwapUint64(decaps.ChecksumError, count)
	}
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

// This thread wakes up every minutes, to find the map cache entries that are
// in resolve state for more than 5 minutes. Resolve entries that are older than
// 5 minutes will be deleted.
func MapcacheScrubThread() {
	log.Printf("Starting map-cache scrubber thread")
	// scrubber thread wakes up every 1 minute and scrubs
	// map-cache entries in resolve status for more than 5 minutes.
	for {
		time.Sleep(60 * time.Second)
		delList := []dptypes.MapCacheKey{}

		cache.LockMe.RLock()

		// Iterate through the map-cache table and make of note of the entries
		// that need removal (entries in resolve state for more than 5 minutes).
		// We take write lock later and delete the required entries.
		for key, entry := range cache.MapCache {
			if entry.Resolved == false {

				currTime := time.Now()

				// 5 * 50 * 1000 milli seconds threshold interval
				var scrubThreshold time.Duration = SCRUBTHRESHOLD * 1000

				// elapsed time is in Nano seconds
				elapsed := currTime.Sub(entry.ResolveTime)

				// convert elapsed time to milli seconds
				elapsed = (elapsed / 1000000)

				// if elapsed time is greater than 5 minutes
				// send delete resolve entry
				if elapsed >= scrubThreshold {
					// mark the resolve entry for deletion
					delList = append(delList, key)
				}
			}
		}
		cache.LockMe.RUnlock()

		// take write lock and delete the entries necessary
		cache.LockMe.Lock()
		for _, key := range delList {
			log.Printf("MapcacheScrubThread: Removing resolve entry with iid %v, eid %s\n",
				key.IID, key.Eid)
			delete(cache.MapCache, key)
		}
		cache.LockMe.Unlock()
	}
}

// Stats thread starts every 5 seconds and punts map cache statistics to lispers.net.
func StatsThread(puntChannel chan []byte) {
	log.Printf("Starting statistics thread.\n")
	for {
		// We collect and transport statistic to lispers.net every 5 seconds
		time.Sleep(5 * time.Second)

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

		var decapStatistics dptypes.DecapStatistics
		decapStatistics.NoDecryptKey = atomic.SwapUint64(decaps.NoDecryptKey, 0)
		decapStatistics.OuterHeaderError = 0
		decapStatistics.BadInnerVersion = 0
		decapStatistics.GoodPackets = atomic.SwapUint64(decaps.GoodPackets, 0)
		decapStatistics.ICVError = atomic.SwapUint64(decaps.ICVError, 0)
		decapStatistics.LispHeaderError = 0
		decapStatistics.ChecksumError = 0

		lispStatistics.DecapStats = decapStatistics

		statsMsg, err := json.Marshal(lispStatistics)
		log.Println(string(statsMsg))
		if err != nil {
			log.Printf("Error: Encoding encap statistics\n")
		} else {
			puntChannel <- statsMsg
		}
		cache.LockMe.RUnlock()
	}
}
