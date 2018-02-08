package fib

import (
	"log"
	"net"
	"time"
	"syscall"
	"math/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/zededa/go-provision/types"
)

func CraftAndSendLispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	hash32 uint32,
	mapEntry *types.MapCacheEntry,
	iid uint32,
	itrLocalData *types.ITRLocalData) {

	var rloc types.Rloc

	// XXX calculate a hash and use it for load balancing accross entries
	totWeight := mapEntry.RlocTotWeight

	// Get map cache slot from hash and weight
	mapSlot := hash32 % totWeight

	// get the map Rloc entry that has the weight slow we are interested
	for _, rloc = range mapEntry.Rlocs {
		if (mapSlot < rloc.WrLow) || (mapSlot > rloc.WrHigh) {
			continue
		}
		break
	}

	// Check the family and create appropriate IP header
	switch rloc.Family {
	case types.MAP_CACHE_FAMILY_IPV4:
		craftAndSendIPv4LispPacket(packet, pktBuf, capLen,
			hash32, &rloc, iid, itrLocalData)
	case types.MAP_CACHE_FAMILY_IPV6:
		craftAndSendIPv6LispPacket(packet, pktBuf, capLen,
			hash32, &rloc, iid, itrLocalData)
	case types.MAP_CACHE_FAMILY_UNKNOWN:
		log.Printf("Unkown family found for rloc %s\n",
			rloc.Rloc)
	}
}

// payload slice does not end at the packet length. It extends till
// the end of the original packet buffer. This way we do not have to
// allocate/re-slice for padding packets or adding icv to the end.
// We take payloadLen that indicates the lenght of original packet.
//
// NOTE: payload slice that is passed here should have a lot of extra space
// after the packet.
func encryptPayload(
	payload []byte, payloadLen uint32,
	encKey []byte, ivArray []byte) (bool, uint32) {

		var remainder uint32 = 0

		packet := payload[:payloadLen]

		// Pad the payload if it's length is not a multiple of 16.
		if (payloadLen % aes.BlockSize) != 0 {
			remainder = (payloadLen % aes.BlockSize)
			packet = payload[:payloadLen + aes.BlockSize - remainder]
			log.Printf("XXXXX Padded packet with %d bytes\n",
				aes.BlockSize - remainder)

			// Now fill the padding with zeroes
			for i := payloadLen; i < uint32(len(packet)); i++ {
				packet[i] = 0
			}
		}

		// XXX Check with Dino, how his code treats IV.
		// String(ascii) or binary?
		// For now, convert the IV into byte array

		// Write IV into packet
		//for i, b := range ivArray {
		//	packet[i] = b
		//}

		// the below block value can be stored in map-cache entry for efficiency
		block, err := aes.NewCipher(encKey)
		if err != nil {
			log.Printf("Error: Creating new AES encryption block from key: %x: %s\n",
			encKey, err)
			return false, 0
		}

		mode := cipher.NewCBCEncrypter(block, packet[:aes.BlockSize])
		mode.CryptBlocks(packet[aes.BlockSize:], packet[aes.BlockSize:])
		return true, (aes.BlockSize - remainder)
}

func GenerateIVByteArray(ivHigh uint64, ivLow uint64, ivArray []byte) []byte {
		// XXX Suggest if there is a better way of doing this.

		// Write individual bytes from ivHigh and ivLow into IV byte array
		// Doesn't look good, but couldn't find a more elegant way of doing it.
		for i := 0; i < 8; i++ {
			ivArray[i] = byte((ivHigh >> uint((8 - i - 1)* 8)) & 0xff)
		}
		for i := 0; i < 8; i++ {
			ivArray[8 + i] = byte((ivLow >> uint((8 - i - 1)* 8)) & 0xff)
		}
		return ivArray
}

// Get IV as a byte array
func GetIVArray(itrLocalData *types.ITRLocalData, ivArray []byte) []byte {
	ivHigh := itrLocalData.IvHigh
	ivLow  := itrLocalData.IvLow
	itrLocalData.IvLow += 1

	if itrLocalData.IvLow == 0 {
		// Lower 64 bits value has rolled over
		// allocate a new IV
		rand.Seed(time.Now().UnixNano())
		ivHigh = rand.Uint64()
		ivLow  = rand.Uint64()

		itrLocalData.IvHigh = ivHigh
		itrLocalData.IvLow  = ivLow
	}
	return GenerateIVByteArray(ivHigh, ivLow, ivArray)
}

func craftAndSendIPv4LispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	hash32 uint32,
	//mapEntry *types.MapCacheEntry,
	rloc *types.Rloc,
	iid uint32,
	itrLocalData *types.ITRLocalData) {

	var fd4       int = itrLocalData.Fd4
	var useCrypto bool = false
	var keyId     byte = 0
	var padLen    uint32 = 0
	var icvKey    []byte

	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?
	/*
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
	*/

	// Check if the RLOC expects encryption
	if rloc.KeyCount != 0 {
		// XXX Call the encrypt function here
		// We should not encrypt the outer IP and lisp headers
		// XXX Also set the LISP key id here. May be always use 1.
		// Pass the IV from map cache entry, packet buffer
		// Also we have to increment the IV

		useCrypto = true

		// use keyid 1 for now
		keyId = 1

		key := rloc.Keys[keyId - 1]
		encKey := key.EncKey
		icvKey = key.IcvKey

		offsetStart := types.MAXHEADERLEN + types.ETHHEADERLEN - uint32(aes.BlockSize)
		offsetEnd   := types.MAXHEADERLEN + capLen
		payloadLen := offsetEnd - offsetStart

		ok := false
		ok, padLen = encryptPayload(pktBuf[offsetStart: offsetEnd], payloadLen,
		encKey, GetIVArray(itrLocalData,
		pktBuf[offsetStart: offsetStart + types.IVLEN]))
		if ok == false {
			keyId = 0
			useCrypto = false
		}
	}
	if useCrypto == true {
		log.Println("XXXXX Using CRYPTO")
	}

	// XXX
	// Should we have a static per-thread entry for this header?
	// Can we have it globally and re-use?

	// make sure the source port is one of the ephemeral one's
	var srcPort uint16 = 0xC000
	srcPort = (srcPort | (uint16(hash32) & 0x3FFF))

	udp := &layers.UDP{
		// XXX Source port should be a hash from packet
		// Hard coding for now.
		SrcPort: layers.UDPPort(srcPort),
		DstPort: 4341,
		Length:  uint16(16 + capLen - 14),
	}

	//udp.SetNetworkLayerForChecksum(ip)

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
		udp.Length += aes.BlockSize + uint16(padLen) + 20
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       false,
	}

	/*
	if err := gopacket.SerializeLayers(buf, opts, ip, udp); err != nil {
		log.Printf("Failed serializing packet: %s", err)
		return
	}
	*/
	if err := gopacket.SerializeLayers(buf, opts, udp); err != nil {
		log.Printf("Failed serializing packet: %s", err)
		return
	}

	outerHdr := buf.Bytes()
	outerHdr = append(outerHdr, lispHdr...)
	outerHdrLen := len(outerHdr)
	offset := types.MAXHEADERLEN + types.ETHHEADERLEN - outerHdrLen
	if useCrypto == true {
		offset = offset - aes.BlockSize
	}

	for i := 0; i < outerHdrLen; i++ {
		pktBuf[i+offset] = outerHdr[i]
	}

	// output slice starts after "offset" and the length of output slice
	// will be len(outerHdr) + capture length - 14 (ethernet header)
	offsetEnd := uint32(offset) + uint32(outerHdrLen) + capLen - 14
	if useCrypto == true {
		// add IV length
		offsetEnd = offsetEnd + aes.BlockSize + padLen + 20

		// We do not compute ICV for the outer UDP header
		computeAndWriteICV(pktBuf[offset + 8: offsetEnd], icvKey)
	}
	//outputSlice := pktBuf[offset : uint32(offset)+uint32(outerHdrLen)+capLen-14]
	outputSlice := pktBuf[offset : offsetEnd]

	v4Addr := rloc.Rloc.To4()
	log.Printf("Writing %d bytes into ITR socket\n", len(outputSlice))
	err := syscall.Sendto(fd4, outputSlice, 0, &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{v4Addr[0], v4Addr[1], v4Addr[2], v4Addr[3]},
	})
	if err != nil {
		log.Printf("Packet send ERROR: %s", err)
	}
}

func ComputeICV(buf []byte, icvKey []byte) []byte {
	mac := hmac.New(sha1.New, icvKey)
	mac.Write(buf)
	icv := mac.Sum(nil)
	return icv
}

func computeAndWriteICV(packet []byte, icvKey []byte) {
	pktLen := len(packet)
	icv := ComputeICV(packet[: pktLen - types.ICVLEN], icvKey)

	// Write ICV to packet
	startIdx := pktLen - types.ICVLEN
	for i, b := range icv {
		packet[startIdx + i] = b
	}
}

func craftAndSendIPv6LispPacket(packet gopacket.Packet,
	pktBuf []byte,
	capLen uint32,
	hash32 uint32,
	//mapEntry *types.MapCacheEntry,
	rloc *types.Rloc,
	iid uint32,
	itrLocalData *types.ITRLocalData) {

	var fd6 int = itrLocalData.Fd6
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
		log.Printf("Failed serializing packet")
		return
	}

	outerHdr := buf.Bytes()
	outerHdr = append(outerHdr, lispHdr...)
	outerHdrLen := len(outerHdr)
	//log.Println("Outer header length is", outerHdrLen)
	offset := types.MAXHEADERLEN + types.ETHHEADERLEN - outerHdrLen
	//log.Println("Offset is", offset)

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
		log.Printf("Packet send ERROR: %s", err)
	}
}
