package conntrack

import (
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// nestedFlag returns true if the NLA_F_NESTED flag is set on typ.
func nestedFlag(typ uint16) bool {
	return typ&netlink.Nested != 0
}

// A Helper holds the name and info the helper that creates a related connection.
type Helper struct {
	Name string
	Info []byte
}

// Filled returns true if the Helper's values are non-zero.
func (hlp Helper) filled() bool {
	return hlp.Name != "" || len(hlp.Info) != 0
}

// unmarshal unmarshals netlink attributes into a Helper.
func (hlp *Helper) unmarshal(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch helperType(ad.Type()) {
		case ctaHelpName:
			hlp.Name = ad.String()
		case ctaHelpInfo:
			hlp.Info = ad.Bytes()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals a Helper into a netfilter.Attribute.
func (hlp Helper) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaHelp), Nested: true, Children: make([]netfilter.Attribute, 1, 2)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaHelpName), Data: []byte(hlp.Name)}

	if len(hlp.Info) > 0 {
		nfa.Children = append(nfa.Children, netfilter.Attribute{Type: uint16(ctaHelpInfo), Data: hlp.Info})
	}

	return nfa
}

// The ProtoInfo structure holds a pointer to
// one of ProtoInfoTCP, ProtoInfoDCCP or ProtoInfoSCTP.
type ProtoInfo struct {
	TCP  *ProtoInfoTCP
	DCCP *ProtoInfoDCCP
	SCTP *ProtoInfoSCTP
}

// Filled returns true if one of the ProtoInfo's values are non-zero.
func (pi ProtoInfo) filled() bool {
	return pi.TCP != nil || pi.DCCP != nil || pi.SCTP != nil
}

// unmarshal unmarshals netlink attributes into a ProtoInfo.
// one of three ProtoInfo types; TCP, DCCP or SCTP.
func (pi *ProtoInfo) unmarshal(ad *netlink.AttributeDecoder) error {
	// Make sure we don't unmarshal into the same ProtoInfo twice.
	if pi.filled() {
		return errReusedProtoInfo
	}

	if ad.Len() != 1 {
		return errNeedSingleChild
	}

	// Step into the single nested child, return on error.
	if !ad.Next() {
		return ad.Err()
	}

	t := protoInfoType(ad.Type())
	switch t {
	case ctaProtoInfoTCP:
		var tpi ProtoInfoTCP
		ad.Nested(tpi.unmarshal)
		pi.TCP = &tpi
	case ctaProtoInfoDCCP:
		var dpi ProtoInfoDCCP
		ad.Nested(dpi.unmarshal)
		pi.DCCP = &dpi
	case ctaProtoInfoSCTP:
		var spi ProtoInfoSCTP
		ad.Nested(spi.unmarshal)
		pi.SCTP = &spi
	default:
		return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
	}

	if err := ad.Err(); err != nil {
		return fmt.Errorf("unmarshal %s: %w", t, err)
	}

	return nil
}

// marshal marshals a ProtoInfo into a netfilter.Attribute.
func (pi ProtoInfo) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaProtoInfo), Nested: true, Children: make([]netfilter.Attribute, 0, 1)}

	if pi.TCP != nil {
		nfa.Children = append(nfa.Children, pi.TCP.marshal())
	} else if pi.DCCP != nil {
		nfa.Children = append(nfa.Children, pi.DCCP.marshal())
	} else if pi.SCTP != nil {
		nfa.Children = append(nfa.Children, pi.SCTP.marshal())
	}

	return nfa
}

// A ProtoInfoTCP describes the state of a TCP session in both directions.
// It contains state, window scale and TCP flags.
type ProtoInfoTCP struct {
	State               uint8
	OriginalWindowScale uint8
	ReplyWindowScale    uint8
	OriginalFlags       uint16
	ReplyFlags          uint16
}

// unmarshal unmarshals netlink attributes into a ProtoInfoTCP.
func (tpi *ProtoInfoTCP) unmarshal(ad *netlink.AttributeDecoder) error {
	// Since 86d21fc74745 ("netfilter: ctnetlink: add timeout and protoinfo to
	// destroy events"), ProtoInfoTCP is sent in conntrack events, where
	// previously it was only present in dumps/queries.
	//
	// NEW and UPDATE events potentially contain all attributes, but DESTROY
	// events only contain TCP_STATE. Expect at least one attribute here.
	if ad.Len() == 0 {
		return errNeedSingleChild
	}

	for ad.Next() {
		switch protoInfoTCPType(ad.Type()) {
		case ctaProtoInfoTCPState:
			tpi.State = ad.Uint8()
		case ctaProtoInfoTCPWScaleOriginal:
			tpi.OriginalWindowScale = ad.Uint8()
		case ctaProtoInfoTCPWScaleReply:
			tpi.ReplyWindowScale = ad.Uint8()
		case ctaProtoInfoTCPFlagsOriginal:
			tpi.OriginalFlags = ad.Uint16()
		case ctaProtoInfoTCPFlagsReply:
			tpi.ReplyFlags = ad.Uint16()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals a ProtoInfoTCP into a netfilter.Attribute.
func (tpi ProtoInfoTCP) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaProtoInfoTCP), Nested: true, Children: make([]netfilter.Attribute, 3, 5)}

	nfa.Children[0] = netfilter.Attribute{
		Type: uint16(ctaProtoInfoTCPState), Data: []byte{tpi.State},
	}
	nfa.Children[1] = netfilter.Attribute{
		Type: uint16(ctaProtoInfoTCPWScaleOriginal), Data: []byte{tpi.OriginalWindowScale},
	}
	nfa.Children[2] = netfilter.Attribute{
		Type: uint16(ctaProtoInfoTCPWScaleReply), Data: []byte{tpi.ReplyWindowScale},
	}

	// Only append TCP flags to attributes when either of them is non-zero.
	if tpi.OriginalFlags != 0 || tpi.ReplyFlags != 0 {
		nfa.Children = append(nfa.Children,
			netfilter.Attribute{Type: uint16(ctaProtoInfoTCPFlagsOriginal), Data: netfilter.Uint16Bytes(tpi.OriginalFlags)},
			netfilter.Attribute{Type: uint16(ctaProtoInfoTCPFlagsReply), Data: netfilter.Uint16Bytes(tpi.ReplyFlags)})
	}

	return nfa
}

// ProtoInfoDCCP describes the state of a DCCP connection.
type ProtoInfoDCCP struct {
	State, Role  uint8
	HandshakeSeq uint64
}

// unmarshal unmarshals netlink attributes into a ProtoInfoDCCP.
func (dpi *ProtoInfoDCCP) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() == 0 {
		return errNeedSingleChild
	}

	for ad.Next() {
		switch protoInfoDCCPType(ad.Type()) {
		case ctaProtoInfoDCCPState:
			dpi.State = ad.Uint8()
		case ctaProtoInfoDCCPRole:
			dpi.Role = ad.Uint8()
		case ctaProtoInfoDCCPHandshakeSeq:
			dpi.HandshakeSeq = ad.Uint64()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals a ProtoInfoDCCP into a netfilter.Attribute.
func (dpi ProtoInfoDCCP) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaProtoInfoDCCP), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaProtoInfoDCCPState), Data: []byte{dpi.State}}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaProtoInfoDCCPRole), Data: []byte{dpi.Role}}
	nfa.Children[2] = netfilter.Attribute{Type: uint16(ctaProtoInfoDCCPHandshakeSeq),
		Data: netfilter.Uint64Bytes(dpi.HandshakeSeq)}

	return nfa
}

// ProtoInfoSCTP describes the state of an SCTP connection.
type ProtoInfoSCTP struct {
	State                   uint8
	VTagOriginal, VTagReply uint32
}

// unmarshal unmarshals netlink attributes into a ProtoInfoSCTP.
func (spi *ProtoInfoSCTP) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() == 0 {
		return errNeedSingleChild
	}

	for ad.Next() {
		switch protoInfoSCTPType(ad.Type()) {
		case ctaProtoInfoSCTPState:
			spi.State = ad.Uint8()
		case ctaProtoInfoSCTPVTagOriginal:
			spi.VTagOriginal = ad.Uint32()
		case ctaProtoInfoSCTPVtagReply:
			spi.VTagReply = ad.Uint32()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals a ProtoInfoSCTP into a netfilter.Attribute.
func (spi ProtoInfoSCTP) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaProtoInfoSCTP), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaProtoInfoSCTPState), Data: []byte{spi.State}}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaProtoInfoSCTPVTagOriginal),
		Data: netfilter.Uint32Bytes(spi.VTagOriginal)}
	nfa.Children[2] = netfilter.Attribute{Type: uint16(ctaProtoInfoSCTPVtagReply),
		Data: netfilter.Uint32Bytes(spi.VTagReply)}

	return nfa
}

// A Counter holds a pair of counters that represent packets and bytes sent over
// a Conntrack connection. Direction is true when it's a reply counter.
// This attribute cannot be changed on a connection and thus cannot be marshaled.
type Counter struct {

	// true means it's a reply counter,
	// false is the original direction
	Direction bool

	Packets uint64
	Bytes   uint64
}

func (ctr Counter) String() string {
	dir := "orig"
	if ctr.Direction {
		dir = "reply"
	}

	return fmt.Sprintf("[%s: %d pkts/%d B]", dir, ctr.Packets, ctr.Bytes)
}

// Filled returns true if the counter's values are non-zero.
func (ctr Counter) filled() bool {
	return ctr.Bytes != 0 && ctr.Packets != 0
}

// unmarshal unmarshals netlink attributes into a Counter.
func (ctr *Counter) unmarshal(ad *netlink.AttributeDecoder) error {
	// A Counter consists of packet and byte attributes but may have
	// help attributes as well if nf_conntrack_helper enabled
	if ad.Len() < 2 {
		return errNeedChildren
	}

	for ad.Next() {
		switch counterType(ad.Type()) {
		case ctaCountersPackets:
			ctr.Packets = ad.Uint64()
		case ctaCountersBytes:
			ctr.Bytes = ad.Uint64()
		case ctaCountersPad:
			// Ignore padding attributes that show up if nf_conntrack_helper is enabled.
			continue
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// A Timestamp represents the start and end time of a flow.
// The timer resolution in the kernel is in nanosecond-epoch.
// This attribute cannot be changed on a connection and thus cannot be marshaled.
type Timestamp struct {
	Start time.Time
	Stop  time.Time
}

// unmarshal unmarshals netlink attributes into a Timestamp.
func (ts *Timestamp) unmarshal(ad *netlink.AttributeDecoder) error {
	// A Timestamp will always have at least a start time
	if ad.Len() == 0 {
		return errNeedSingleChild
	}

	for ad.Next() {
		switch timestampType(ad.Type()) {
		case ctaTimestampStart:
			ts.Start = time.Unix(0, int64(ad.Uint64()))
		case ctaTimestampStop:
			ts.Stop = time.Unix(0, int64(ad.Uint64()))
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// A Security structure holds the security info belonging to a connection.
// Kernel uses this to store and match SELinux context name.
// This attribute cannot be changed on a connection and thus cannot be marshaled.
type Security string

// unmarshal unmarshals netlink attributes into a Security.
func (sec *Security) unmarshal(ad *netlink.AttributeDecoder) error {
	// A SecurityContext has at least a name
	if ad.Len() == 0 {
		return errNeedChildren
	}

	for ad.Next() {
		switch securityType(ad.Type()) {
		case ctaSecCtxName:
			*sec = Security(ad.Bytes())
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// SequenceAdjust represents a TCP sequence number adjustment event.
// Direction is true when it's a reply adjustment.
type SequenceAdjust struct {
	// true means it's a reply adjustment,
	// false is the original direction
	Direction bool

	Position     uint32
	OffsetBefore uint32
	OffsetAfter  uint32
}

func (seq SequenceAdjust) String() string {
	dir := "orig"
	if seq.Direction {
		dir = "reply"
	}

	return fmt.Sprintf("[dir: %s, pos: %d, before: %d, after: %d]", dir, seq.Position, seq.OffsetBefore, seq.OffsetAfter)
}

// Filled returns true if the SequenceAdjust's values are non-zero.
// SeqAdj qualify as filled if all of its members are non-zero.
func (seq SequenceAdjust) filled() bool {
	return seq.Position != 0 && seq.OffsetAfter != 0 && seq.OffsetBefore != 0
}

// unmarshal unmarshals netlink attributes into a SequenceAdjust.
func (seq *SequenceAdjust) unmarshal(ad *netlink.AttributeDecoder) error {
	// A SequenceAdjust message should come with at least 1 child.
	if ad.Len() == 0 {
		return errNeedSingleChild
	}

	for ad.Next() {
		switch seqAdjType(ad.Type()) {
		case ctaSeqAdjCorrectionPos:
			seq.Position = ad.Uint32()
		case ctaSeqAdjOffsetBefore:
			seq.OffsetBefore = ad.Uint32()
		case ctaSeqAdjOffsetAfter:
			seq.OffsetAfter = ad.Uint32()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals a SequenceAdjust into a netfilter.Attribute.
func (seq SequenceAdjust) marshal(reply bool) netfilter.Attribute {
	// Set orig/reply AttributeType
	at := ctaSeqAdjOrig
	if seq.Direction || reply {
		at = ctaSeqAdjReply
	}

	nfa := netfilter.Attribute{Type: uint16(at), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaSeqAdjCorrectionPos),
		Data: netfilter.Uint32Bytes(seq.Position)}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaSeqAdjOffsetBefore),
		Data: netfilter.Uint32Bytes(seq.OffsetBefore)}
	nfa.Children[2] = netfilter.Attribute{Type: uint16(ctaSeqAdjOffsetAfter),
		Data: netfilter.Uint32Bytes(seq.OffsetAfter)}

	return nfa
}

// SynProxy represents the SYN proxy parameters of a Conntrack flow.
type SynProxy struct {
	ISN   uint32
	ITS   uint32
	TSOff uint32
}

// Filled returns true if the SynProxy's values are non-zero.
// SynProxy qualifies as filled if one of its members is non-zero.
func (sp SynProxy) filled() bool {
	return sp.ISN != 0 || sp.ITS != 0 || sp.TSOff != 0
}

// unmarshal unmarshals netlink attributes into a SynProxy.
func (sp *SynProxy) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() == 0 {
		return errNeedSingleChild
	}

	for ad.Next() {
		switch synProxyType(ad.Type()) {
		case ctaSynProxyISN:
			sp.ISN = ad.Uint32()
		case ctaSynProxyITS:
			sp.ITS = ad.Uint32()
		case ctaSynProxyTSOff:
			sp.TSOff = ad.Uint32()
		default:
			return fmt.Errorf("child type %d: %w", ad.Type(), errUnknownAttribute)
		}
	}

	return ad.Err()
}

// marshal marshals a SynProxy into a netfilter.Attribute.
func (sp SynProxy) marshal() netfilter.Attribute {
	nfa := netfilter.Attribute{Type: uint16(ctaSynProxy), Nested: true, Children: make([]netfilter.Attribute, 3)}

	nfa.Children[0] = netfilter.Attribute{Type: uint16(ctaSynProxyISN), Data: netfilter.Uint32Bytes(sp.ISN)}
	nfa.Children[1] = netfilter.Attribute{Type: uint16(ctaSynProxyITS), Data: netfilter.Uint32Bytes(sp.ITS)}
	nfa.Children[2] = netfilter.Attribute{Type: uint16(ctaSynProxyTSOff), Data: netfilter.Uint32Bytes(sp.TSOff)}

	return nfa
}

// TODO: ctaStats
// TODO: ctaStatsGlobal
// TODO: ctaStatsExp
