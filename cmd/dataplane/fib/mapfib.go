package fib

import (
	"encoding/json"
	"github.com/zededa/go-provision/types"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

var cache *types.MapCacheTable
var decaps *types.DecapTable

var pktBuf []byte

// ipv4 and ipv6 raw sockets respectively
var fd4 int
var fd6 int

func newMapCache() *types.MapCacheTable {
	return &types.MapCacheTable{
		MapCache: make(map[types.MapCacheKey]*types.MapCacheEntry),
	}
}

func newDecapTable() *types.DecapTable {
	return &types.DecapTable{
		DecapEntries: make(map[string]*types.DecapKeys),
	}
}

func InitMapCache() {
	var err error
	cache = newMapCache()

	// Init buffered packet processing buffer
	pktBuf = make([]byte, 65536)

	// create required raw sockets
	//fd4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	fd4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		log.Printf("FIB ipv4 raw socket creation failed.\n")
	}
	err = syscall.SetsockoptInt(fd4, syscall.SOL_SOCKET, syscall.IP_MTU_DISCOVER,
		syscall.IP_PMTUDISC_DONT)
	if err != nil {
		log.Printf("Disabling path mtu discovery failed.\n")
	}
	err = syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 0)
	if err != nil {
		log.Printf("Disabling IP_HDRINCL failed.\n")
	}
	fd6, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("FIB ipv6 raw socket creation failed.\n")
	}
	// XXX We should close these sockets somewhere. Where?
}

func InitDecapTable() {
	decaps = newDecapTable()
}

func makeMapCacheKey(iid uint32, eid net.IP) types.MapCacheKey {
	return types.MapCacheKey{
		IID: iid,
		Eid: eid.String(),
	}
}

// Do a lookup into map cache database. If a resolved entry is not found,
// create and add an un-resolved entry for buffering packets.
func LookupAndAdd(iid uint32,
	eid net.IP, timeStamp time.Time) (*types.MapCacheEntry, bool) {
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
			puntInterval = 5000
		}

		// elapsed time is in Nano seconds
		//elapsed := time.Since(entry.LastPunt)
		elapsed := timeStamp.Sub(entry.LastPunt)

		// convert elapsed time to milli seconds
		elapsed = (elapsed / 1000000)

		// if elapsed time is greater than 30000ms send a punt request
		// XXX Is 30 seconds for punt too high?
		if elapsed >= puntInterval {
			punt = true
			//entry.LastPunt = time.Now()
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
		resolveEntry := types.MapCacheEntry{
			InstanceId: iid,
			Eid:        eid,
			Resolved:   false,
			PktBuffer:  make(chan *types.BufferedPacket, 10),
			LastPunt:   time.Now(),
		}
		cache.MapCache[key] = &resolveEntry
		return &resolveEntry, true
	}
}

// Add/update map cache entry. Along with that process and send out and
// buffered packets attached to this entry.
func UpdateMapCacheEntry(iid uint32, eid net.IP, rlocs []types.Rloc) {
	entry := LookupAndUpdate(iid, eid, rlocs)

	// Create a temporary IV to work with
	rand.Seed(time.Now().UnixNano())
	ivHigh := rand.Uint64()
	ivLow := rand.Uint64()

	itrLocalData := new(types.ITRLocalData)
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
				copy(pktBuf[types.MAXHEADERLEN:], pktBytes)

				// Send the packet out now
				CraftAndSendLispPacket(pkt.Packet, pktBuf, uint32(capLen), timeStamp,
					pkt.Hash32, entry, entry.InstanceId, itrLocalData)

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
// XXX We only consider the highest priority RLOCs and ignore other priorities
func compileRlocs(rlocs []types.Rloc) ([]types.Rloc, uint32) {
	var highPrio uint32 = 0xFFFFFFFF
	selectRlocs := []types.Rloc{}
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
		log.Println("Adding weights:", low, high)
	}

	return selectRlocs, totWeight
}

// Add/update map cache entry. Look at the comments inside this function to understand
// more about what it does.
func LookupAndUpdate(iid uint32, eid net.IP, rlocs []types.Rloc) *types.MapCacheEntry {
	key := makeMapCacheKey(iid, eid)
	cache.LockMe.Lock()
	defer cache.LockMe.Unlock()
	entry, ok := cache.MapCache[key]
	var selectRlocs []types.Rloc
	var totWeight uint32
	var packets, bytes, tailDrops, buffdPkts uint64
	var lastPunt time.Time

	log.Printf("Adding map-cache entry with key %d, %s\n", key.IID, key.Eid)

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

		delete(cache.MapCache, key)
	} else if ok {
		// Entry is in unresolved state. Update the RLOCs and mark the entry
		// as resolved.
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
	newEntry := types.MapCacheEntry{
		InstanceId:    iid,
		Eid:           eid,
		Resolved:      true,
		Rlocs:         selectRlocs,
		RlocTotWeight: totWeight,
		PktBuffer:     make(chan *types.BufferedPacket, 10),
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

func UpdateDecapKeys(entry *types.DecapKeys) {
	decaps.LockMe.Lock()
	defer decaps.LockMe.Unlock()
	key := entry.Rloc.String()
	decaps.DecapEntries[key] = entry
}

func LookupDecapKeys(ip net.IP) *types.DecapKeys {
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

	for key, value := range cache.MapCache {
		log.Println("Key IID:", key.IID)
		log.Printf("Key Eid: %s\n", key.Eid)
		log.Println("Rlocs:")
		for _, rloc := range value.Rlocs {
			log.Printf("	RLOC: %s\n", rloc.Rloc)
			log.Printf("	RLOC Packets: %v\n", atomic.LoadUint64(&rloc.Packets))
			log.Printf("	RLOC Bytes: %v\n", atomic.LoadUint64(&rloc.Bytes))
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
	decaps.LockMe.RLock()
	defer decaps.LockMe.RUnlock()

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

func StatsThread(puntChannel chan []byte) {
	log.Printf("Starting statistics thread.\n")
	for {
		// We collect and transport statistic to lispers.net every 30 seconds
		time.Sleep(30 * time.Second)

		// take read lock of map cache table
		// and go through each entry while preparing statistics message
		log.Printf("XXXXX Stats cycle\n")

		cache.LockMe.RLock()

		var encapStatistics types.EncapStatistics
		encapStatistics.Type = "statistics"

		for key, value := range cache.MapCache {
			//log.Println("Key IID:", key.IID)
			//log.Printf("Key Eid: %s\n", key.Eid)
			//log.Println("Rlocs:")

			var eidStats types.EidStatsEntry
			eidStats.InstanceId = strconv.FormatUint(uint64(key.IID), 10)
			eidStats.EidPrefix = key.Eid
			for _, rloc := range value.Rlocs {
				//log.Printf("	RLOC: %s\n", rloc.Rloc)
				//log.Printf("	RLOC Packets: %v\n", atomic.LoadUint64(&rloc.Packets))
				//log.Printf("	RLOC Bytes: %v\n", atomic.LoadUint64(&rloc.Bytes))

				var rlocStats types.RlocStatsEntry
				rlocStats.Rloc = rloc.Rloc.String()
				rlocStats.PacketCount = atomic.LoadUint64(&rloc.Packets)
				rlocStats.ByteCount = atomic.LoadUint64(&rloc.Bytes)
				currUnixSecs := time.Now().Unix()
				lastPktSecs  := atomic.LoadInt64(&rloc.LastPktTime)
				rlocStats.SecondsSinceLastPkt = currUnixSecs - lastPktSecs

				eidStats.Rlocs = append(eidStats.Rlocs, rlocStats)
			}
			/*
			log.Printf("Packets: %v\n", value.Packets)
			log.Printf("Bytes: %v\n", value.Bytes)
			log.Printf("TailDrops: %v\n", value.TailDrops)
			log.Printf("BuffdPkts: %v\n", value.BuffdPkts)
			log.Println()
			*/
			encapStatistics.Entries = append(encapStatistics.Entries, eidStats)
		}
		statsMsg, err := json.Marshal(encapStatistics)
		log.Println(string(statsMsg))
		if err != nil {
			log.Printf("Error: Encoding encap statistics\n")
		} else {
			puntChannel <- statsMsg
		}
		cache.LockMe.RUnlock()
	}
}
