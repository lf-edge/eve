// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// LISP packet creation code. Supports GCM/sha256 crypto encryption.

package fib

import (
	//"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/zededa/lisp/dataplane/dptypes"
	"log"
	"math/rand"
	"sync/atomic"
	"syscall"
	"time"
)

func CraftAndSendLispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	timeStamp time.Time,
	hash32 uint32,
	mapEntry *dptypes.MapCacheEntry,
	iid uint32,
	itrLocalData *dptypes.ITRLocalData) {

	// calculate a hash and use it for load balancing accross entries
	totWeight := mapEntry.RlocTotWeight

	// Get map cache slot from hash and weight
	mapSlot := hash32 % totWeight

	// get the map Rloc entry that has the weight slow we are interested
	rlocIndex := 0
	for i, rloc := range mapEntry.Rlocs {
		if (mapSlot < rloc.WrLow) || (mapSlot > rloc.WrHigh) {
			continue
		}
		rlocIndex = i
		break
	}
	rlocPtr := &mapEntry.Rlocs[rlocIndex]

	// Check the family and create appropriate IP header
	switch rlocPtr.Family {
	case dptypes.MAP_CACHE_FAMILY_IPV4:
		craftAndSendIPv4LispPacket(packet, pktBuf, capLen, timeStamp,
			hash32, rlocPtr, iid, itrLocalData)
	case dptypes.MAP_CACHE_FAMILY_IPV6:
		craftAndSendIPv6LispPacket(packet, pktBuf, capLen, timeStamp,
			hash32, rlocPtr, iid, itrLocalData)
	case dptypes.MAP_CACHE_FAMILY_UNKNOWN:
		log.Printf("CraftAndSendLispPacket: Unkown family found for rloc %s\n",
			rlocPtr.Rloc)
	}
}

// payload slice does not end at the packet length. It extends till
// the end of the original packet buffer. This way we do not have to
// allocate/re-slice for padding packets or adding icv to the end.
// We take payloadLen that indicates the length of original packet.
//
// NOTE: payload slice that is passed here should have some extra space
// at the end of packet(for Padding and ICV).
func encryptPayload(payload []byte,
	payloadLen uint32, encKey []byte,
	block cipher.Block, ivArray []byte) (bool, uint32) {

	if len(encKey) == 0 {
		log.Printf("encryptPayload: Invalid encrypt key lenght: %s\n", len(encKey))
		return false, 0
	}

	//var remainder uint32 = 0

	packet := payload[:payloadLen]

	// We do not pad packet with GCM
	/*
	// Pad the payload if it's length is not a multiple of 16.
	if (payloadLen % aes.BlockSize) != 0 {
		remainder = (payloadLen % aes.BlockSize)
		packet = payload[:payloadLen+aes.BlockSize-remainder]
		log.Printf("XXXXX Padded packet with %d bytes\n",
			aes.BlockSize-remainder)

		// Now fill the padding with zeroes
		for i := payloadLen; i < uint32(len(packet)); i++ {
			packet[i] = 0
		}
	}
	*/

	// XXX Check with Dino, how his code treats IV.
	// String(ascii) or binary?
	// For now, convert the IV into byte array

	// second argument to NewCBCEncrypter is IV
	//mode := cipher.NewCBCEncrypter(block, packet[:aes.BlockSize])
	//mode.CryptBlocks(packet[aes.BlockSize:], packet[aes.BlockSize:])
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("encryptPayload: Packet encryption failed: %s\n", err)
		return false, 0
	}
	aesGcm.Seal(packet[dptypes.GCMIVLENGTH:], packet[:dptypes.GCMIVLENGTH],
		packet[dptypes.GCMIVLENGTH:], nil)
	//return true, (aes.BlockSize - remainder)
	return true, 0
}

func GenerateIVByteArray(ivHigh uint32, ivLow uint64, ivArray []byte) []byte {
	// XXX Suggest if there is a better way of doing this.

	// Write individual bytes from ivHigh and ivLow into IV byte array
	// Doesn't look good, but couldn't find a more elegant way of doing it.
	//for i := 0; i < 8; i++ {
	/*
	for i := 0; i < 4; i++ {
		ivArray[i] = byte((ivHigh >> uint((4-i-1)*8)) & 0xff)
	}
	for i := 0; i < 8; i++ {
		ivArray[4+i] = byte((ivLow >> uint((8-i-1)*8)) & 0xff)
	}
	*/
	binary.BigEndian.PutUint32(ivArray[0:4], ivHigh)
	binary.BigEndian.PutUint64(ivArray[4:12], ivLow)

	return ivArray
}

// Get IV as a byte array
func GetIVArray(itrLocalData *dptypes.ITRLocalData, ivArray []byte) []byte {
	ivHigh := itrLocalData.IvHigh
	ivLow := itrLocalData.IvLow
	itrLocalData.IvLow += 1

	if itrLocalData.IvLow == 0 {
		// Lower 64 bits value has rolled over
		// allocate a new IV
		rand.Seed(time.Now().UnixNano())
		ivHigh = rand.Uint32()
		ivLow = rand.Uint64()

		itrLocalData.IvHigh = ivHigh
		itrLocalData.IvLow = ivLow
	}
	return GenerateIVByteArray(ivHigh, ivLow, ivArray)
}

func ComputeICV(buf []byte, icvKey []byte) []byte {
	//mac := hmac.New(sha1.New, icvKey)
	mac := hmac.New(sha256.New, icvKey)
	mac.Write(buf)
	icv := mac.Sum(nil)
	// we only use the first 20 bytes as ICV
	return icv[:20]
}

func computeAndWriteICV(packet []byte, icvKey []byte) {
	pktLen := len(packet)
	icv := ComputeICV(packet[:pktLen-dptypes.ICVLEN], icvKey)

	// Write ICV to packet
	startIdx := pktLen - dptypes.ICVLEN
	for i, b := range icv {
		packet[startIdx+i] = b
	}
}

func craftAndSendIPv4LispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	timeStamp time.Time,
	hash32 uint32,
	//mapEntry *dptypes.MapCacheEntry,
	rloc *dptypes.Rloc,
	iid uint32,
	itrLocalData *dptypes.ITRLocalData) {

	var fd4 int = itrLocalData.Fd4
	var useCrypto bool = false
	var keyId byte = 0
	var padLen uint32 = 0
	var icvKey []byte

	srcAddr := GetIPv4UplinkAddr()
	log.Printf("XXXXX craftAndSendIPv4LispPacket: UPLINK address is %s.\n", srcAddr)
	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	ip := &layers.IPv4{
		DstIP:    rloc.Rloc,
		SrcIP:    srcAddr,
		Flags:    0,
		TTL:      64,
		IHL:      5,
		Version:  4,
		Protocol: layers.IPProtocolUDP,
	}

	// Check if the RLOC expects encryption
	if rloc.KeyCount != 0 {
		// Call the encrypt function here.
		// We should not encrypt the outer IP and lisp headers.
		// Also set the LISP key id here. May be always use 1.
		// Pass the IV from map cache entry.
		// Also we have to increment the IV.
		useCrypto = true

		// use keyid 1 for now
		keyId = 1

		key := rloc.Keys[keyId-1]
		encKey := key.EncKey
		icvKey = key.IcvKey

		// Get the offset where IV would start.
		// Inner payload (encrypted) would follow the IV
		//offsetStart := dptypes.MAXHEADERLEN + dptypes.ETHHEADERLEN - uint32(aes.BlockSize)
		offsetStart := dptypes.MAXHEADERLEN + dptypes.ETHHEADERLEN - uint32(dptypes.GCMIVLENGTH)
		offsetEnd := dptypes.MAXHEADERLEN + capLen
		payloadLen := offsetEnd - offsetStart

		ok := false
		ok, padLen = encryptPayload(
			pktBuf[offsetStart:offsetEnd],
			payloadLen, encKey, key.EncBlock,
			//GetIVArray(itrLocalData, pktBuf[offsetStart:offsetStart+dptypes.IVLEN]))
			GetIVArray(itrLocalData,
			pktBuf[offsetStart:offsetStart+dptypes.GCMIVLENGTH]))
		if ok == false {
			keyId = 0
			useCrypto = false
		} else {
			log.Println("XXXXX Using CRYPTO")
		}
	}

	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?

	// make sure the source port is one of the ephemeral one's
	var srcPort uint16 = 0xC000
	srcPort = (srcPort | (uint16(hash32) & 0x3FFF))

	udpLen := dptypes.UDPHEADERLEN + dptypes.LISPHEADERLEN + capLen - dptypes.ETHHEADERLEN
	udp := &layers.UDP{
		// Source port is a hash from packet
		SrcPort: layers.UDPPort(srcPort),
		DstPort: 4341,
		Length:  uint16(udpLen),
	}

	udp.SetNetworkLayerForChecksum(ip)

	// Create a custom LISP header
	lispHdr := make([]byte, 8)
	SetLispIID(lispHdr, iid)

	nonce := rand.Intn(0xffffff)
	SetLispNonce(lispHdr, uint32(nonce))

	// XXX Check if crypto is enabled for this EID and set
	// the key id as required
	if useCrypto == true {
		SetLispKeyId(lispHdr, keyId)

		// UDP length changes with crypto
		// original length + any padding + 20 bytes ICV
		udp.Length += dptypes.GCMIVLENGTH + uint16(padLen) + dptypes.ICVLEN
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       false,
	}

	if err := gopacket.SerializeLayers(buf, opts, ip, udp); err != nil {
		log.Printf("craftAndSendIPv4LispPacket: Failed serializing packet: %s", err)
		return
	}

	outerHdr := buf.Bytes()
	outerHdr = append(outerHdr, lispHdr...)
	outerHdrLen := len(outerHdr)
	offset := dptypes.MAXHEADERLEN + dptypes.ETHHEADERLEN - outerHdrLen

	// output slice starts after "offset" and the length of output slice
	// will be len(outerHdr) + capture length - 14 (ethernet header)
	offsetEnd := uint32(offset) + uint32(outerHdrLen) + capLen - dptypes.ETHHEADERLEN
	if useCrypto == true {
		//offset = offset - aes.BlockSize
		offset = offset - dptypes.GCMIVLENGTH

		// add IV, padding and ICV lengths
		//offsetEnd = offsetEnd + aes.BlockSize + padLen + dptypes.ICVLEN
		offsetEnd = offsetEnd + dptypes.GCMIVLENGTH + padLen + dptypes.ICVLEN

		// We do not include outer UDP header for ICV computation
		icvStartOffset := offset + dptypes.IP4HEADERLEN + dptypes.UDPHEADERLEN
		computeAndWriteICV(pktBuf[icvStartOffset:offsetEnd], icvKey)
	}

	for i := 0; i < outerHdrLen; i++ {
		pktBuf[i+offset] = outerHdr[i]
	}

	outputSlice := pktBuf[offset:offsetEnd]

	log.Printf("XXXXX Writing %d bytes into ITR socket\n", len(outputSlice))
	err := syscall.Sendto(fd4, outputSlice, 0, &rloc.IPv4SockAddr)
	if err != nil {
		log.Printf("craftAndSendIPv4LispPacket: Packet send ERROR: %s", err)
		return
	}

	// Increment RLOC packet & byte count statistics
	totalBytes := offsetEnd - uint32(offset) + dptypes.IP4HEADERLEN
	atomic.AddUint64(&rloc.Packets, 1)
	atomic.AddUint64(&rloc.Bytes, uint64(totalBytes))

	// Atomically store time stamp
	unixSeconds := timeStamp.Unix()
	atomic.StoreInt64(&rloc.LastPktTime, unixSeconds)
}

func craftAndSendIPv6LispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	timeStamp time.Time,
	hash32 uint32,
	rloc *dptypes.Rloc,
	iid uint32,
	itrLocalData *dptypes.ITRLocalData) {

	var fd6 int = itrLocalData.Fd6
	var useCrypto bool = false
	var keyId byte = 0
	var padLen uint32 = 0
	var icvKey []byte

	srcAddr := GetIPv6UplinkAddr()
	log.Printf("XXXXX craftAndSendIPv6LispPacket: UPLINK address is %s.\n", srcAddr)

	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		DstIP:      rloc.Rloc,
		SrcIP:      srcAddr,
		NextHeader: layers.IPProtocolUDP,
	}

	// Check if the RLOC expects encryption
	if rloc.KeyCount != 0 {
		// Call the encrypt function here.
		// We should not encrypt the outer IP and lisp headers.
		// Also set the LISP key id here. May be always use 1.
		// Pass the IV from map cache entry, packet buffer.
		// Also we have to increment the IV.
		useCrypto = true

		// use keyid 1 for now
		keyId = 1

		key := rloc.Keys[keyId-1]
		encKey := key.EncKey
		icvKey = key.IcvKey

		//offsetStart := dptypes.MAXHEADERLEN + dptypes.ETHHEADERLEN - uint32(aes.BlockSize)
		offsetStart := dptypes.MAXHEADERLEN + dptypes.ETHHEADERLEN - uint32(dptypes.GCMIVLENGTH)
		offsetEnd := dptypes.MAXHEADERLEN + capLen
		payloadLen := offsetEnd - offsetStart

		ok := false
		ok, padLen = encryptPayload(pktBuf[offsetStart:offsetEnd], payloadLen,
			encKey, key.EncBlock,
			//GetIVArray(itrLocalData, pktBuf[offsetStart:offsetStart+dptypes.IVLEN]))
			GetIVArray(itrLocalData, pktBuf[offsetStart:offsetStart+dptypes.GCMIVLENGTH]))
		if ok == false {
			keyId = 0
			useCrypto = false
		} else {
			log.Println("XXXXX Using CRYPTO")
		}
	}

	// make sure the source port is one of the ephemeral one's
	var srcPort uint16 = 0xC000
	srcPort = (srcPort | (uint16(hash32) & 0x3FFF))

	udpLen := dptypes.UDPHEADERLEN + dptypes.LISPHEADERLEN + capLen - dptypes.ETHHEADERLEN
	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	udp := &layers.UDP{
		// XXX Source port should be a hash from packet
		// Hard coding for now.
		SrcPort: layers.UDPPort(srcPort),
		DstPort: 4341,
		Length:  uint16(udpLen),
	}

	udp.SetNetworkLayerForChecksum(ip)

	// Create a custom LISP header
	lispHdr := make([]byte, 8)
	SetLispIID(lispHdr, iid)

	nonce := rand.Intn(0xffffff)
	SetLispNonce(lispHdr, uint32(nonce))

	// XXX Check if crypto is enabled for this EID and set
	// the key id as required
	if useCrypto == true {
		SetLispKeyId(lispHdr, keyId)

		// UDP length changes with crypto
		// original length + any padding + 20 bytes ICV
		//udp.Length += aes.BlockSize + uint16(padLen) + dptypes.ICVLEN
		udp.Length += dptypes.GCMIVLENGTH + uint16(padLen) + dptypes.ICVLEN
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       false,
	}

	if err := gopacket.SerializeLayers(buf, opts, ip, udp); err != nil {
		log.Printf("craftAndSendIPv6LispPacket: Failed serializing packet")
		return
	}

	outerHdr := buf.Bytes()
	outerHdr = append(outerHdr, lispHdr...)
	outerHdrLen := len(outerHdr)
	offset := dptypes.MAXHEADERLEN + dptypes.ETHHEADERLEN - outerHdrLen

	// output slice starts after "offset" and the length of output slice
	// will be len(outerHdr) + capture length - 14 (ethernet header)
	offsetEnd := uint32(offset) + uint32(outerHdrLen) + capLen - dptypes.ETHHEADERLEN
	if useCrypto == true {
		//offset = offset - aes.BlockSize
		offset = offset - dptypes.GCMIVLENGTH

		// add IV length
		//offsetEnd = offsetEnd + aes.BlockSize + padLen + dptypes.ICVLEN
		offsetEnd = offsetEnd + dptypes.GCMIVLENGTH + padLen + dptypes.ICVLEN

		// We do not include outer IP/UDP headers for ICV computation
		icvStartOffset := offset + dptypes.IP6HEADERLEN + dptypes.UDPHEADERLEN
		computeAndWriteICV(pktBuf[icvStartOffset:offsetEnd], icvKey)
	}

	for i := 0; i < outerHdrLen; i++ {
		pktBuf[i+offset] = outerHdr[i]
	}
	outputSlice := pktBuf[offset:offsetEnd]

	log.Printf("XXXXX Writing %d bytes into ITR socket\n", len(outputSlice))
	err := syscall.Sendto(fd6, outputSlice, 0, &rloc.IPv6SockAddr)

	if err != nil {
		log.Printf("craftAndSendIPv6LispPacket: Packet send ERROR: %s", err)
	}

	// Increment RLOC packet & byte count statistics
	totalBytes := offsetEnd - uint32(offset) + dptypes.IP6HEADERLEN
	atomic.AddUint64(&rloc.Packets, 1)
	atomic.AddUint64(&rloc.Bytes, uint64(totalBytes))

	// Atomically store time stamp
	unixSeconds := timeStamp.Unix()
	atomic.StoreInt64(&rloc.LastPktTime, unixSeconds)
}
