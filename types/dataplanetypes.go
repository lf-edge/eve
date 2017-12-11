
// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	//"log"
	"time"
	"net"
	"sync"
	"github.com/google/gopacket"
)

const (
	MAP_CACHE_FAMILY_IPV4 = 1
	MAP_CACHE_FAMILY_IPV6 = 2
	MAP_CACHE_FAMILY_UNKNOWN = 3
)

type Key struct {
    KeyId uint32
    Key   net.IP
}

type Rloc struct {
    Rloc     net.IP
    Priority uint32
    Weight   uint32
	Family   uint32
    Keys     []Key

	// Weight range
	WrLow    uint32
	WrHigh   uint32
}

type BufferedPacket struct {
	Packet gopacket.Packet
	Hash32 uint32
}

type MapCacheEntry struct {
    InstanceId uint32
    Eid        net.IP
    Rlocs      []Rloc
    Resolved   bool
    PktBuffer  chan *BufferedPacket
	LastPunt   time.Time
	RlocTotWeight uint32
}

type MapCacheKey struct {
	IID uint32
	Eid string
}

type MapCacheTable struct {
    LockMe   sync.RWMutex
    MapCache map[MapCacheKey]*MapCacheEntry
}

type Interface struct {
	Name       string
	InstanceId uint32
}

type InterfaceMap struct {
	LockMe      sync.RWMutex
	InterfaceDB map[string]Interface
}

type EIDEntry struct {
	InstanceId uint32
	Eids       []net.IP
}

type EIDMap struct {
	LockMe     sync.RWMutex
	EidEntries map[uint32]EIDEntry
}

type DecapKeys struct {
	Rloc net.IP
	Keys []Key
}

type DecapTable struct {
	LockMe sync.RWMutex
	DecapEntries map[string]DecapKeys
}

type PuntEntry struct {
	Seid net.IP
	Deid net.IP
	Iface string
}
