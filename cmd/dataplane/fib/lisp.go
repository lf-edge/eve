package fib

import (
	"github.com/google/gopacket"
)

var LispLayerType gopacket.LayerType

type LispHdr struct {
	Hdr     []byte
	Payload []byte
}

func RegisterLispHeader() {
	LispLayerType = gopacket.RegisterLayerType(2001,
						gopacket.LayerTypeMetadata {
							"LispLayerType",
							gopacket.DecodeFunc(decodeLispLayer),
						})
}

func (l LispHdr) LayerType() gopacket.LayerType {
	return LispLayerType
}

func (l LispHdr) LayerContents() []byte {
	return l.Hdr
}

func (l LispHdr) LayerPayload() []byte {
	return l.Payload
}

func decodeLispLayer(data []byte, p gopacket.PacketBuilder) error {
	p.AddLayer(&LispHdr{data[:2], data[2:]})
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func SetLispIID(hdr []byte, iid uint32) {
	iidFlagMask := byte(1 << 3)

	// Set instance id present flag
	hdr[0] = byte(hdr[0] | iidFlagMask)

	// Set instance id in lisp header
	hdr[4] = byte(iid >> 16)
	hdr[5] = byte(iid >> 8)
	hdr[6] = byte(iid)
}

func GetLispIID(hdr []byte) uint32 {
	var iid uint32 = 0

	iid = uint32(hdr[4] << 16 | hdr[5] << 8 | hdr[6])
	return iid
}

func SetLispNonce(hdr []byte, nonce uint32) {
	// set the nonce present bit
	nonceFlagMask := byte(1 << 7)
	hdr[0] = byte(hdr[0] | nonceFlagMask)

	// set nonce into header
	hdr[1] = byte(nonce >> 16)
	hdr[2] = byte(nonce >> 8)
	hdr[3] = byte(nonce)
}

func GetLispNonce(hdr []byte) uint32 {
	var nonce uint32 = 0

	nonce = uint32(hdr[1] << 16 | hdr[2] << 8 | hdr[3])
	return nonce
}

