package netfilter

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
)

// NewAttributeDecoder instantiates a new netlink.AttributeDecoder
// configured with a Big Endian byte order.
func NewAttributeDecoder(b []byte) (*netlink.AttributeDecoder, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, err
	}

	// All Netfilter attribute payloads are big-endian. (network byte order)
	ad.ByteOrder = binary.BigEndian

	return ad, nil
}

// NewAttributeEncoder instantiates a new netlink.AttributeEncoder
// configured with a Big Endian byte order.
func NewAttributeEncoder() *netlink.AttributeEncoder {
	ae := netlink.NewAttributeEncoder()

	// All Netfilter attribute payloads are big-endian. (network byte order)
	ae.ByteOrder = binary.BigEndian

	return ae
}

// An Attribute is a copy of a netlink.Attribute that can be nested.
type Attribute struct {

	// The type of this Attribute, typically matched to a constant.
	Type uint16

	// An arbitrary payload which is specified by Type.
	Data []byte

	// Whether the attribute's data contains nested attributes.
	Nested   bool
	Children []Attribute

	// Whether the attribute's data is in network (true) or native (false) byte order.
	NetByteOrder bool
}

func (a Attribute) String() string {
	if a.Nested {
		return fmt.Sprintf("<Length %d, Type %d, Nested %t, %d Children (%v)>", len(a.Data), a.Type, a.Nested, len(a.Children), a.Children)
	}

	return fmt.Sprintf("<Length %d, Type %d, Nested %t, NetByteOrder %t, %v>", len(a.Data), a.Type, a.Nested, a.NetByteOrder, a.Data)

}

// Uint16 interprets a non-nested Netfilter attribute in network byte order as a uint16.
func (a Attribute) Uint16() uint16 {

	if a.Nested {
		panic("Uint16: unexpected Nested attribute")
	}

	if l := len(a.Data); l != 2 {
		panic(fmt.Sprintf("Uint16: unexpected byte slice length: %d", l))
	}

	return binary.BigEndian.Uint16(a.Data)
}

// PutUint16 sets the Attribute's data field to a Uint16 encoded in net byte order.
func (a *Attribute) PutUint16(v uint16) {

	if len(a.Data) != 2 {
		a.Data = make([]byte, 2)
	}

	binary.BigEndian.PutUint16(a.Data, v)
}

// Uint32 interprets a non-nested Netfilter attribute in network byte order as a uint32.
func (a Attribute) Uint32() uint32 {

	if a.Nested {
		panic("Uint32: unexpected Nested attribute")
	}

	if l := len(a.Data); l != 4 {
		panic(fmt.Sprintf("Uint32: unexpected byte slice length: %d", l))
	}

	return binary.BigEndian.Uint32(a.Data)
}

// PutUint32 sets the Attribute's data field to a Uint32 encoded in net byte order.
func (a *Attribute) PutUint32(v uint32) {

	if len(a.Data) != 4 {
		a.Data = make([]byte, 4)
	}

	binary.BigEndian.PutUint32(a.Data, v)
}

// Int32 converts the result of Uint16() to an int32.
func (a Attribute) Int32() int32 {
	return int32(a.Uint32())
}

// Uint64 interprets a non-nested Netfilter attribute in network byte order as a uint64.
func (a Attribute) Uint64() uint64 {

	if a.Nested {
		panic("Uint64: unexpected Nested attribute")
	}

	if l := len(a.Data); l != 8 {
		panic(fmt.Sprintf("Uint64: unexpected byte slice length: %d", l))
	}

	return binary.BigEndian.Uint64(a.Data)
}

// PutUint64 sets the Attribute's data field to a Uint64 encoded in net byte order.
func (a *Attribute) PutUint64(v uint64) {

	if len(a.Data) != 8 {
		a.Data = make([]byte, 8)
	}

	binary.BigEndian.PutUint64(a.Data, v)
}

// Int64 converts the result of Uint16() to an int64.
func (a Attribute) Int64() int64 {
	return int64(a.Uint64())
}

// Uint16Bytes gets the big-endian 2-byte representation of a uint16.
func Uint16Bytes(u uint16) []byte {
	d := make([]byte, 2)
	binary.BigEndian.PutUint16(d, u)
	return d
}

// Uint32Bytes gets the big-endian 4-byte representation of a uint32.
func Uint32Bytes(u uint32) []byte {
	d := make([]byte, 4)
	binary.BigEndian.PutUint32(d, u)
	return d
}

// Uint64Bytes gets the big-endian 8-byte representation of a uint64.
func Uint64Bytes(u uint64) []byte {
	d := make([]byte, 8)
	binary.BigEndian.PutUint64(d, u)
	return d
}

// decode fills the Attribute's Children field with Attributes
// obtained by exhausting ad.
func (a *Attribute) decode(ad *netlink.AttributeDecoder) error {

	for ad.Next() {

		// Copy the netlink attribute's fields into the netfilter attribute.
		nfa := Attribute{
			// Only consider the rightmost 14 bits for Type.
			// ad.Type implicitly masks the Nested and NetByteOrder bits.
			Type: ad.Type(),
			Data: ad.Bytes(),
		}

		// Boolean flags extracted from the two leftmost bits of Type.
		nfa.Nested = ad.TypeFlags()&netlink.Nested != 0
		nfa.NetByteOrder = ad.TypeFlags()&netlink.NetByteOrder != 0

		if nfa.NetByteOrder && nfa.Nested {
			return errInvalidAttributeFlags
		}

		// Unmarshal recursively if the netlink Nested flag is set.
		if nfa.Nested {
			ad.Nested(nfa.decode)
		}

		a.Children = append(a.Children, nfa)
	}

	return ad.Err()
}

// encode returns a function that takes an AttributeEncoder and returns error.
// This function can be passed to AttributeEncoder.Nested for recursively
// encoding Attributes.
func (a *Attribute) encode(attrs []Attribute) func(*netlink.AttributeEncoder) error {

	return func(ae *netlink.AttributeEncoder) error {

		for _, nfa := range attrs {

			if nfa.NetByteOrder && nfa.Nested {
				return errInvalidAttributeFlags
			}

			if nfa.Nested {
				ae.Nested(nfa.Type, nfa.encode(nfa.Children))
				continue
			}

			// Manually set the NetByteOrder flag, since ae.Bytes() can't.
			if nfa.NetByteOrder {
				nfa.Type |= netlink.NetByteOrder
			}
			ae.Bytes(nfa.Type, nfa.Data)
		}

		return nil
	}
}

// decodeAttributes returns an array of netfilter.Attributes decoded from
// a byte array. This byte array should be taken from the netlink.Message's
// Data payload after the nfHeaderLen offset.
func decodeAttributes(ad *netlink.AttributeDecoder) ([]Attribute, error) {

	// Use the Children element of the Attribute to decode into.
	// Attribute already has nested decoding implemented on the type.
	var a Attribute

	// Pre-allocate backing array when there are netlink attributes to decode.
	if ad.Len() != 0 {
		a.Children = make([]Attribute, 0, ad.Len())
	}

	// Catch any errors encountered parsing netfilter structures.
	if err := a.decode(ad); err != nil {
		return nil, err
	}

	return a.Children, nil
}

// encodeAttributes encodes a list of Attributes into the given netlink.AttributeEncoder.
func encodeAttributes(ae *netlink.AttributeEncoder, attrs []Attribute) error {

	if ae == nil {
		return errNilAttributeEncoder
	}

	attr := Attribute{}
	return attr.encode(attrs)(ae)
}

// MarshalAttributes marshals a nested attribute structure into a byte slice.
// This byte slice can then be copied into a netlink.Message's Data field after
// the nfHeaderLen offset.
func MarshalAttributes(attrs []Attribute) ([]byte, error) {

	ae := NewAttributeEncoder()

	if err := encodeAttributes(ae, attrs); err != nil {
		return nil, err
	}

	b, err := ae.Encode()
	if err != nil {
		return nil, err
	}

	return b, nil
}

// UnmarshalAttributes unmarshals a byte slice into a list of Attributes.
func UnmarshalAttributes(b []byte) ([]Attribute, error) {

	ad, err := NewAttributeDecoder(b)
	if err != nil {
		return nil, err
	}

	return decodeAttributes(ad)
}
