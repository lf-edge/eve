package netfilter

import (
	"github.com/pkg/errors"

	"github.com/mdlayher/netlink"
)

// UnmarshalNetlink unmarshals a netlink.Message into a Netfilter Header and Attributes.
func UnmarshalNetlink(msg netlink.Message) (Header, []Attribute, error) {

	h, ad, err := DecodeNetlink(msg)
	if err != nil {
		return Header{}, nil, err
	}

	attrs, err := decodeAttributes(ad)
	if err != nil {
		return Header{}, nil, err
	}

	return h, attrs, nil
}

// DecodeNetlink returns msg's Netfilter header and an AttributeDecoder that can be used
// to iteratively decode all Netlink attributes contained in the message.
func DecodeNetlink(msg netlink.Message) (Header, *netlink.AttributeDecoder, error) {

	var h Header

	err := h.unmarshal(msg)
	if err != nil {
		return Header{}, nil, errors.Wrap(err, "unmarshaling netfilter header")
	}

	ad, err := NewAttributeDecoder(msg.Data[nfHeaderLen:])
	if err != nil {
		return Header{}, nil, errors.Wrap(err, "creating attribute decoder")
	}

	return h, ad, nil
}

// MarshalNetlink takes a Netfilter Header and Attributes and returns a netlink.Message.
func MarshalNetlink(h Header, attrs []Attribute) (netlink.Message, error) {

	ae := NewAttributeEncoder()
	if err := encodeAttributes(ae, attrs); err != nil {
		return netlink.Message{}, err
	}

	return EncodeNetlink(h, ae)
}

// EncodeNetlink generates a netlink.Message based on a given netfilter header h
// and a pre-filled netlink.AttributeEncoder ae.
func EncodeNetlink(h Header, ae *netlink.AttributeEncoder) (netlink.Message, error) {

	if ae == nil {
		return netlink.Message{}, errNilAttributeEncoder
	}

	// Encode the AE into a byte slice.
	b, err := ae.Encode()
	if err != nil {
		return netlink.Message{}, err
	}

	// Allocate space for the marshaled netfilter header.
	nlm := netlink.Message{Data: append(make([]byte, nfHeaderLen), b...)}

	// marshal error ignored, safe to do if msg Data is initialized.
	_ = h.marshal(&nlm)

	return nlm, nil
}
