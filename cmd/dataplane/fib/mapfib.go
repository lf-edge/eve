package fib

import (
	"os"
    "fmt"
	"net"
	"time"
	"syscall"
    "github.com/zededa/go-provision/types"
	//"github.com/google/gopacket"
)

var cache *types.MapCacheTable
var decaps *types.DecapTable

var pktBuf []byte
//var conn4  net.PacketConn
//var conn6  net.PacketConn
var fd4 int
var fd6 int

func newMapCache() *types.MapCacheTable {
    return &types.MapCacheTable {
	MapCache: make(map[types.MapCacheKey]*types.MapCacheEntry),
    }
}

func newDecapTable() *types.DecapTable {
	return &types.DecapTable {
		DecapEntries: make(map[string]types.DecapKeys),
	}
}

func InitMapCache() {
	var err error
    cache = newMapCache()

	// Init buffered packet processing buffer
	pktBuf = make([]byte, 65536)

	// create raw sockets required
	//conn4, err = net.ListenPacket("ip4:udp", "0.0.0.0")
	fd4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FIB ipv4 raw socket creation failed.\n")
	}
	//conn6, err = net.ListenPacket("ip6:udp", "")
	fd6, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FIB ipv6 raw socket creation failed.\n")
	}
	// XXX We should close these sockets somewhere. Where?
}

func InitDecapTable() {
	decaps = newDecapTable()
}

func makeMapCacheKey(iid uint32, eid net.IP) types.MapCacheKey {
	return types.MapCacheKey {
		IID: iid,
		Eid: eid.String(),
	}
}

func LookupAndAdd(iid uint32,
				eid net.IP) (*types.MapCacheEntry, bool) {
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
		// elapsed time is in Nano seconds
		elapsed := time.Since(entry.LastPunt)

		// convert elapsed time to milli seconds
		elapsed = (elapsed / 1000000)

		// if elapsed time is greater than 30000ms send a punt request
		if elapsed >= 30000 {
			punt = true
			entry.LastPunt = time.Now()
		}
		return entry , punt
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
		resolveEntry := types.MapCacheEntry {
			InstanceId: iid,
			Eid: eid,
			Resolved: false,
			PktBuffer: make(chan *types.BufferedPacket, 10),
			LastPunt: time.Now(),
		}
		cache.MapCache[key] = &resolveEntry
		return &resolveEntry, true
	}
}

func UpdateMapCacheEntry(iid uint32, eid net.IP, rlocs []types.Rloc) {
	entry := LookupAndUpdate(iid, eid, rlocs)

	for {
		select {
		case pkt, ok := <-entry.PktBuffer:
			if ok {
				// send the packet out
				pktBytes := pkt.Packet.Data()
				capLen := len(pktBytes)

				// copy packet bytes into pktBuf at an offset of 42 bytes
				// ipv6 (40) + UDP (8) + LISP (8) - ETHERNET (14) = 42
				copy(pktBuf[42:], pktBytes)

				fmt.Println("Sending packet from buffered channel")
				// Send the packet out now
				CraftAndSendLispPacket(pkt.Packet, pktBuf, uint32(capLen), pkt.Hash32,
										entry, entry.InstanceId, fd4, fd6)
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

func compileRlocs(rlocs []types.Rloc) ([]types.Rloc, uint32){
	var highPrio uint32 = 0xFFFFFFFF
	selectRlocs := []types.Rloc{}
	var totWeight uint32 = 0
	var wrStart   uint32 = 0

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
	for i, _ := range selectRlocs {
		low := wrStart
		high := low + selectRlocs[i].Weight - 1
		wrStart = high + 1

		selectRlocs[i].WrLow = low
		selectRlocs[i].WrHigh = high
		fmt.Println("Adding weights:", low, high)
	}

	return selectRlocs, totWeight
}

func LookupAndUpdate(iid uint32, eid net.IP, rlocs []types.Rloc) *types.MapCacheEntry {
	key := makeMapCacheKey(iid, eid)
	cache.LockMe.Lock()
	defer cache.LockMe.Unlock()
	entry, ok := cache.MapCache[key]
	var selectRlocs []types.Rloc
	var totWeight uint32

	fmt.Printf("Adding map-cache entry with key %d, %s\n", key.IID, key.Eid)

	if ok  && (entry.Resolved == true) {
		// Delete the old map cache entry
		// Another ITR thread might have taken a pointer to this entry
		// and is still working on packet. If we start updating this entry,
		// the other ITR thread will read data in unfinished state (corrupted).
		// To avoid this, we delete the entry and add newly created entry.
		// Since the ITR thread still has pointer to the old entry, it will not
		// be garbage collected. Subsequent packets will hit updated entry.
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
	newEntry := types.MapCacheEntry {
		InstanceId: iid,
		Eid: eid,
		Resolved: true,
		Rlocs: selectRlocs,
		RlocTotWeight: totWeight,
		PktBuffer: make(chan *types.BufferedPacket, 10),
		LastPunt: time.Now(),
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

func UpdateDecapKeys(entry types.DecapKeys) {
	decaps.LockMe.Lock()
	defer decaps.LockMe.Unlock()
	key := entry.Rloc.String()
	decaps.DecapEntries[key] = entry
}

func ShowMapCacheEntries() {
	cache.LockMe.RLock()
	defer cache.LockMe.RUnlock()

	for key, value := range cache.MapCache {
		fmt.Println("Key IID:", key.IID)
		fmt.Printf("Key Eid: %s\n", key.Eid)
		fmt.Println("Rlocs:")
		for _, rloc := range value.Rlocs {
			fmt.Printf("%s\n", rloc.Rloc)
		}
		fmt.Println()
	}
	fmt.Println()
}

func ShowDecapKeys() {
	decaps.LockMe.RLock()
	defer decaps.LockMe.RUnlock()

	for key, _ := range decaps.DecapEntries {
		fmt.Println("Rloc:", key)
	}
	fmt.Println()
}
