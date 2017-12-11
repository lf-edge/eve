package fib

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/zededa/go-provision/types"
	"math/rand"
	"net"
	"os"
	"syscall"
)

const MAXHEADERLEN = 42
const ETHHEADERLEN = 14

func CraftAndSendLispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	hash32 uint32,
	mapEntry *types.MapCacheEntry,
	iid uint32,
	//conn4 net.PacketConn, conn6 net.PacketConn) {
	fd4 int, fd6 int) {
	// XXX
	// For now, we use the first Rloc entry from map cache.
	// It has to be changed to load balance between available Rlocs
	rloc := mapEntry.Rlocs[0]

	// Check the family and create appropriate IP header
	switch rloc.Family {
	case types.MAP_CACHE_FAMILY_IPV4:
		//craftAndSendIPv4LispPacket(packet, pktBuf, capLen, mapEntry, iid, conn4)
		craftAndSendIPv4LispPacket(packet, pktBuf, capLen, hash32, mapEntry, iid, fd4)
	case types.MAP_CACHE_FAMILY_IPV6:
		//craftAndSendIPv6LispPacket(packet, pktBuf, capLen, mapEntry, iid, conn6)
		craftAndSendIPv6LispPacket(packet, pktBuf, capLen, hash32, mapEntry, iid, fd6)
	case types.MAP_CACHE_FAMILY_UNKNOWN:
		fmt.Fprintf(os.Stderr, "Unkown family found for rloc %s\n",
			rloc.Rloc)
	}
}

func craftAndSendIPv4LispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	hash32 uint32,
	mapEntry *types.MapCacheEntry,
	iid uint32,
	//conn4 net.PacketConn) {
	fd4 int) {
	// XXX calculate a hash and use it for load balancing accross entries
	var rloc types.Rloc
	totWeight := mapEntry.RlocTotWeight

	// Get map cache slot from hash and weight
	mapSlot := hash32 % totWeight
	//fmt.Println("Slot selected is:", mapSlot)
	//fmt.Println("Total weight is:", totWeight)

	// get the map entry that this slot falls into
	for _, rloc = range mapEntry.Rlocs {
		//fmt.Println("Checking range", rloc.WrLow, rloc.WrHigh)
		if (mapSlot < rloc.WrLow) || (mapSlot > rloc.WrHigh) {
			continue
		}
		//fmt.Println("Range selected is:", rloc.WrLow, rloc.WrHigh)
		break
	}

	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	srcAddr := net.ParseIP("0.0.0.0")
	ip := &layers.IPv4{
		DstIP:    rloc.Rloc,
		SrcIP:    srcAddr,
		Flags:    0,
		TTL:      64,
		IHL:      5,
		Version:  4,
		Protocol: layers.IPProtocolUDP,
	}

	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	var srcPort uint16 = 0xC000
	srcPort = (srcPort | (uint16(hash32) & 0x3FFF))
	//fmt.Println("hash32 is:", hash32)
	//fmt.Println("Source port is:", srcPort)
	udp := &layers.UDP{
		// XXX Source port should be a hash from packet
		// Hard coding for now.
		SrcPort: layers.UDPPort(srcPort),
		DstPort: 4341,
		Length:  uint16(16 + capLen - 14),
	}

	udp.SetNetworkLayerForChecksum(ip)

	// Create a custom LISP header
	lispHdr := make([]byte, 8)
	SetLispIID(lispHdr, iid)

	nonce := rand.Intn(0xffffff)
	//fmt.Println("XXX Writing nonce", nonce)
	SetLispNonce(lispHdr, uint32(nonce))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       false,
	}

	if err := gopacket.SerializeLayers(buf, opts, ip, udp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed serializing packet: %s", err)
		return
	}

	outerHdr := buf.Bytes()
	outerHdr = append(outerHdr, lispHdr...)
	outerHdrLen := len(outerHdr)
	//fmt.Println("Outer header length is", outerHdrLen)
	offset := MAXHEADERLEN + ETHHEADERLEN - outerHdrLen
	//fmt.Println("Offset is", offset)

	for i := 0; i < outerHdrLen; i++ {
		pktBuf[i+offset] = outerHdr[i]
	}

	// output slice starts after "offset" and the length of it
	// will be len(outerHdr) + capture length - 14 (ethernet header)
	outputSlice := pktBuf[offset : uint32(offset)+uint32(outerHdrLen)+capLen-14]

	//_, err := conn4.WriteTo(buf.Bytes(), &net.IPAddr{IP: rloc.Rloc})
	//_, err := conn4.WriteTo(outputSlice, &net.IPAddr{IP: rloc.Rloc})
	v4Addr := rloc.Rloc.To4()
	err := syscall.Sendto(fd4, outputSlice, 0, &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{v4Addr[0], v4Addr[1], v4Addr[2], v4Addr[3]},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Packet send ERROR: %s", err)
	}
}

func craftAndSendIPv6LispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	hash32 uint32,
	mapEntry *types.MapCacheEntry,
	iid uint32,
	//conn6 net.PacketConn) {
	fd6 int) {
	rloc := mapEntry.Rlocs[0]
	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	srcAddr := net.ParseIP("")
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		DstIP:      rloc.Rloc,
		SrcIP:      srcAddr,
		NextHeader: layers.IPProtocolUDP,
	}

	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	udp := &layers.UDP{
		// XXX Source port should be a hash from packet
		// Hard coding for now.
		SrcPort: 1434,
		DstPort: 4341,
		Length:  uint16(16 + capLen - 14),
	}

	udp.SetNetworkLayerForChecksum(ip)

	// Create a custom LISP header
	lispHdr := make([]byte, 8)
	SetLispIID(lispHdr, iid)

	nonce := rand.Intn(0xffffff)
	SetLispNonce(lispHdr, uint32(nonce))

	// get bytes starting from the IP header of captured packet
	linkLayer := packet.LinkLayer()
	payload := linkLayer.LayerPayload()

	// Prepend the lisp header
	payload = append(lispHdr, payload...)

	data := gopacket.Payload(payload)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		//ComputeChecksums: true,
		FixLengths: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, ip, udp, data); err != nil {
		fmt.Fprintf(os.Stderr, "Failed serializing packet")
		return
	}

	outerHdr := buf.Bytes()
	outerHdr = append(outerHdr, lispHdr...)
	outerHdrLen := len(outerHdr)
	//fmt.Println("Outer header length is", outerHdrLen)
	offset := MAXHEADERLEN + ETHHEADERLEN - outerHdrLen
	//fmt.Println("Offset is", offset)

	for i := 0; i < outerHdrLen; i++ {
		pktBuf[i+offset] = outerHdr[i]
	}
	outputSlice := pktBuf[offset : uint32(offset)+uint32(outerHdrLen)+capLen-14]

	//_, err := conn6.WriteTo(buf.Bytes(), &net.IPAddr{IP: rloc.Rloc})
	v6Addr := rloc.Rloc.To16()
	var destAddr [16]byte
	for i, _ := range destAddr {
		destAddr[i] = v6Addr[i]
	}

	err := syscall.Sendto(fd6, outputSlice, 0, &syscall.SockaddrInet6{
		Port:   0,
		ZoneId: 0,
		Addr:   destAddr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Packet send ERROR: %s", err)
	}
}
