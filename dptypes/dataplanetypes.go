// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package dptypes

import (
	"crypto/cipher"
	"github.com/google/gopacket"
	"net"
	"sync"
	"time"
	//"github.com/google/gopacket/pfring"
	"github.com/google/gopacket/afpacket"
	"syscall"
)

const (
	MAP_CACHE_FAMILY_IPV4    = 1
	MAP_CACHE_FAMILY_IPV6    = 2
	MAP_CACHE_FAMILY_UNKNOWN = 3
	// max header len is ip6 hdr len (40) +
	// udp (8) + lisp (8) - eth hdr (14) + crypto iv len (16 for CBC and 12 for GCM)
	//MAXHEADERLEN             = 58 // max header len with CBC
	MAXHEADERLEN  = 54
	ETHHEADERLEN  = 14
	UDPHEADERLEN  = 8
	ICVLEN        = 20
	IVLEN         = 16
	IP4HEADERLEN  = 20
	IP6HEADERLEN  = 40
	LISPHEADERLEN = 8
	GCMIVLENGTH   = 12
)

type Key struct {
	KeyId  uint32
	EncKey []byte
	IcvKey []byte

	EncBlock cipher.Block
}

// Decrypt key information
type DKey struct {
	KeyId    uint32
	DecKey   []byte
	IcvKey   []byte
	DecBlock cipher.Block
}

type Rloc struct {
	Rloc     net.IP
	Port     uint16
	Priority uint32
	Weight   uint32
	Family   uint32
	KeyCount uint32
	Keys     []Key

	// Destination socket addresses.
	// Used for sending packets out.
	IPv4SockAddr syscall.SockaddrInet4
	IPv6SockAddr syscall.SockaddrInet6

	// Weight range
	WrLow  uint32
	WrHigh uint32

	// Packet statistics
	Packets     *uint64
	Bytes       *uint64
	LastPktTime *int64
}

type BufferedPacket struct {
	Packet gopacket.Packet
	Hash32 uint32
}

type MapCacheEntry struct {
	InstanceId    uint32
	Eid           net.IP
	Rlocs         []Rloc
	Resolved      bool
	PktBuffer     chan *BufferedPacket
	LastPunt      time.Time
	ResolveTime   time.Time
	RlocTotWeight uint32

	// Packet statistics
	Packets   uint64
	Bytes     uint64
	BuffdPkts uint64
	TailDrops uint64
}

type MapCacheKey struct {
	IID uint32
	Eid string
}

type UplinkAddress struct {
	Ipv4 net.IP
	Ipv6 net.IP
}

type Uplinks struct {
	sync.RWMutex
	UpLinks *UplinkAddress
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
	Keys []DKey
}

type PktStat struct {
	Pkts        uint64 `json:"packet-count"`
	Bytes       uint64 `json:"byte-count"`
	LastPktTime int64  `json:"seconds-last-packet"`
}

type DecapTable struct {
	LockMe       sync.RWMutex
	DecapEntries map[string]*DecapKeys

	// ETR statistics
	NoDecryptKey     PktStat
	OuterHeaderError PktStat
	BadInnerVersion  PktStat
	GoodPackets      PktStat
	ICVError         PktStat
	LispHeaderError  PktStat
	ChecksumError    PktStat
}

type PuntEntry struct {
	Type  string `json:"type"`
	Seid  net.IP `json:"source-eid"`
	Deid  net.IP `json:"dest-eid"`
	Iface string `json:"interface"`
}

type RestartEntry struct {
	Type string `json:"type"`
}

type RlocStatsEntry struct {
	Rloc                string `json:"rloc"`
	PacketCount         uint64 `json:"packet-count"`
	ByteCount           uint64 `json:"byte-count"`
	SecondsSinceLastPkt int64  `json:"seconds-last-packet"`
}

type EidStatsEntry struct {
	InstanceId string           `json:"instance-id"`
	EidPrefix  string           `json:"eid-prefix"`
	Rlocs      []RlocStatsEntry `json:"rlocs"`
}

type DecapStatistics struct {
	NoDecryptKey     PktStat `json:"no-decrypt-key"`
	OuterHeaderError PktStat `json:"outer-header-error"`
	BadInnerVersion  PktStat `json:"bad-inner-version"`
	GoodPackets      PktStat `json:"good-packets"`
	ICVError         PktStat `json:"ICV-error"`
	LispHeaderError  PktStat `json:"lisp-header-error"`
	ChecksumError    PktStat `json:"checksum-error"`
}

type LispStatistics struct {
	Type       string          `json:"type"`
	Entries    []EidStatsEntry `json:"entries"`
	DecapStats DecapStatistics `json:"decap-stats"`
}

type EtrRunStatus struct {
	// Name of the interface to capture packets from
	IfName string

	// Kill message channel
	KillChannel chan bool

	//Ring    *pfring.Ring

	// ETR Natted packet capture ring
	Handle *afpacket.TPacket
	// Raw socket FD used by ETR packet capture thread
	// for injecting decapsulated packets
	RingFD int
}

type EtrTable struct {
	// Destination ephemeral port
	EphPort  int
	EtrTable map[string]*EtrRunStatus
}

type ITRLocalData struct {
	// crypto initialization vector data (IV)
	//IvHigh uint64
	IvHigh uint32
	IvLow  uint64

	// Raw sockets for sending out LISP encapsulted packets
	Fd4 int
	Fd6 int
}

type ITRGlobalData struct {
	ItrCryptoPort int
	LockMe        sync.RWMutex
}
