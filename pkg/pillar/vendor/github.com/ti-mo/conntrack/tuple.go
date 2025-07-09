package conntrack

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/ti-mo/netfilter"
)

// A Tuple holds an IPTuple, ProtoTuple and a Zone.
type Tuple struct {
	IP    IPTuple
	Proto ProtoTuple
	Zone  uint16
}

// Filled returns true if the Tuple's IP and Proto members are filled.
// The Zone attribute is not considered, because it is zero in most cases.
func (t Tuple) filled() bool {
	return t.IP.filled() && t.Proto.filled()
}

// String returns a string representation of a Tuple.
func (t Tuple) String() string {
	return fmt.Sprintf("<%s, Src: %s, Dst: %s>",
		protoLookup(t.Proto.Protocol),
		net.JoinHostPort(t.IP.SourceAddress.String(), strconv.Itoa(int(t.Proto.SourcePort))),
		net.JoinHostPort(t.IP.DestinationAddress.String(), strconv.Itoa(int(t.Proto.DestinationPort))),
	)
}

// unmarshal unmarshals netlink attributes into a Tuple.
func (t *Tuple) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() < 2 {
		return errNeedChildren
	}

	for ad.Next() {
		tt := tupleType(ad.Type())
		switch tt {
		case ctaTupleIP:
			var ti IPTuple
			ad.Nested(ti.unmarshal)
			t.IP = ti
		case ctaTupleProto:
			var tp ProtoTuple
			ad.Nested(tp.unmarshal)
			t.Proto = tp
		case ctaTupleZone:
			t.Zone = ad.Uint16()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}

		if err := ad.Err(); err != nil {
			return fmt.Errorf("unmarshal %s: %w", tt, err)
		}
	}

	return ad.Err()
}

// marshal marshals a Tuple to a netfilter.Attribute.
func (t Tuple) marshal(at uint16) (netfilter.Attribute, error) {
	nfa := netfilter.Attribute{Type: at, Nested: true, Children: make([]netfilter.Attribute, 2, 3)}

	ipt, err := t.IP.marshal()
	if err != nil {
		return netfilter.Attribute{}, err
	}

	nfa.Children[0] = ipt
	nfa.Children[1] = t.Proto.marshal()

	if t.Zone != 0 {
		nfa.Children = append(nfa.Children, netfilter.Attribute{
			Type: uint16(ctaTupleZone), Data: netfilter.Uint16Bytes(t.Zone),
		})
	}

	return nfa, nil
}

// An IPTuple encodes a source and destination address.
type IPTuple struct {
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
}

// Filled returns true if the IPTuple's fields are non-zero.
func (ipt IPTuple) filled() bool {
	return ipt.SourceAddress.IsValid() && ipt.DestinationAddress.IsValid()
}

// unmarshal unmarshals netlink attributes into an IPTuple.
func (ipt *IPTuple) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() != 2 {
		return errNeedChildren
	}

	for ad.Next() {
		addr, ok := netip.AddrFromSlice(ad.Bytes())
		if !ok {
			return errIncorrectSize
		}

		switch ipTupleType(ad.Type()) {
		case ctaIPv4Src, ctaIPv6Src:
			ipt.SourceAddress = addr
		case ctaIPv4Dst, ctaIPv6Dst:
			ipt.DestinationAddress = addr
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals an IPTuple to a netfilter.Attribute.
func (ipt IPTuple) marshal() (netfilter.Attribute, error) {
	if !ipt.SourceAddress.IsValid() || !ipt.DestinationAddress.IsValid() {
		return netfilter.Attribute{}, errBadIPTuple
	}

	nfa := netfilter.Attribute{Type: uint16(ctaTupleIP), Nested: true, Children: make([]netfilter.Attribute, 2)}

	switch {
	case ipt.SourceAddress.Is4() && ipt.DestinationAddress.Is4():
		nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaIPv4Src), Data: ipt.SourceAddress.AsSlice()}
		nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaIPv4Dst), Data: ipt.DestinationAddress.AsSlice()}
	case ipt.SourceAddress.Is6() && ipt.DestinationAddress.Is6():
		nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaIPv6Src), Data: ipt.SourceAddress.AsSlice()}
		nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaIPv6Dst), Data: ipt.DestinationAddress.AsSlice()}
	default:
		// not the same IP family for source and destination
		return netfilter.Attribute{}, errBadIPTuple
	}

	return nfa, nil
}

// IsIPv6 returns true if the IPTuple contains source and destination addresses that are both IPv6.
func (ipt IPTuple) IsIPv6() bool {
	return ipt.SourceAddress.Is6() && ipt.DestinationAddress.Is6()
}

// A ProtoTuple encodes a protocol number, source port and destination port.
type ProtoTuple struct {
	Protocol        uint8
	SourcePort      uint16
	DestinationPort uint16

	ICMPv4 bool
	ICMPv6 bool

	ICMPID   uint16
	ICMPType uint8
	ICMPCode uint8
}

// Filled returns true if the ProtoTuple's protocol is non-zero.
func (pt ProtoTuple) filled() bool {
	return pt.Protocol != 0
}

// unmarshal unmarshals a netfilter.Attribute into a ProtoTuple.
func (pt *ProtoTuple) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() == 0 {
		return errNeedSingleChild
	}

	for ad.Next() {
		switch protoTupleType(ad.Type()) {
		case ctaProtoNum:
			pt.Protocol = ad.Uint8()

			switch pt.Protocol {
			case syscall.IPPROTO_ICMP:
				pt.ICMPv4 = true
			case syscall.IPPROTO_ICMPV6:
				pt.ICMPv6 = true
			}
		case ctaProtoSrcPort:
			pt.SourcePort = ad.Uint16()
		case ctaProtoDstPort:
			pt.DestinationPort = ad.Uint16()
		case ctaProtoICMPID, ctaProtoICMPv6ID:
			pt.ICMPID = ad.Uint16()
		case ctaProtoICMPType, ctaProtoICMPv6Type:
			pt.ICMPType = ad.Uint8()
		case ctaProtoICMPCode, ctaProtoICMPv6Code:
			pt.ICMPCode = ad.Uint8()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals a ProtoTuple into a netfilter.Attribute.
func (pt ProtoTuple) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaTupleProto), Nested: true, Children: make([]netfilter.Attribute, 3, 4)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaProtoNum), Data: []byte{pt.Protocol}}

	switch pt.Protocol {
	case unix.IPPROTO_ICMP:
		nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaProtoICMPType), Data: []byte{pt.ICMPType}}
		nfa.Children[2] = netfilter.Attribute{Type: uint16(ctaProtoICMPCode), Data: []byte{pt.ICMPCode}}
		nfa.Children = append(nfa.Children, netfilter.Attribute{
			Type: uint16(ctaProtoICMPID), Data: netfilter.Uint16Bytes(pt.ICMPID),
		})
	case unix.IPPROTO_ICMPV6:
		nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaProtoICMPv6Type), Data: []byte{pt.ICMPType}}
		nfa.Children[2] = netfilter.Attribute{Type: uint16(ctaProtoICMPv6Code), Data: []byte{pt.ICMPCode}}
		nfa.Children = append(nfa.Children, netfilter.Attribute{
			Type: uint16(ctaProtoICMPv6ID), Data: netfilter.Uint16Bytes(pt.ICMPID),
		})
	default:
		nfa.Children[1] = netfilter.Attribute{
			Type: uint16(ctaProtoSrcPort), Data: netfilter.Uint16Bytes(pt.SourcePort),
		}
		nfa.Children[2] = netfilter.Attribute{
			Type: uint16(ctaProtoDstPort), Data: netfilter.Uint16Bytes(pt.DestinationPort),
		}
	}

	return nfa
}
