// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// tracedConn wraps net.Conn to publish traces for socket read/write operations
// and DNS queries.
type tracedConn struct {
	tracer       networkTracer
	connID       TraceID
	conn         net.Conn
	log          Logger
	forResolver  bool
	withDNSTrace bool
}

// socketOpTrace is published for every socket read/write operation.
type socketOpTrace struct {
	SocketOp
	conn   net.Conn
	connID TraceID
	closed bool // true if the socket was closed
}

func (socketOpTrace) isInternalNetTrace() {}

// socketOpTrace is published for every DNS query sent over the connection.
type dnsQueryTrace struct {
	DNSQueryMsg
	conn   net.Conn
	connID TraceID
}

func (dnsQueryTrace) isInternalNetTrace() {}

// dnsReplyTrace is published for every DNS reply received over the connection.
type dnsReplyTrace struct {
	DNSReplyMsg
	conn   net.Conn
	connID TraceID
}

func (dnsReplyTrace) isInternalNetTrace() {}

func newTracedConn(tracer networkTracer, connID TraceID, conn net.Conn, log Logger,
	forResolver, withDNSTrace bool) *tracedConn {
	return &tracedConn{
		tracer:       tracer,
		connID:       connID,
		conn:         conn,
		log:          log,
		forResolver:  forResolver,
		withDNSTrace: withDNSTrace,
	}
}

func (tc *tracedConn) String() string {
	return fmt.Sprintf("%v - %v", tc.LocalAddr(), tc.RemoteAddr())
}

func (tc *tracedConn) parseDNSQuery(data []byte, sentAt Timestamp) {
	var p dnsmessage.Parser
	header, err := p.Start(data)
	if err != nil {
		tc.log.Warningf(
			"nettrace: networkTracer id=%s: failed to parse DNS query: %v (conn %v)",
			tc.tracer.getTracerID(), err, tc)
		return
	}
	var questions []DNSQuestion
	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			tc.log.Warningf(
				"nettrace: networkTracer id=%s: failed to parse DNS query question: %v "+
					"(conn %v)", tc.tracer.getTracerID(), err, tc)
			continue
		}
		resType := DNSResType(q.Type)
		if _, recognized := DNSResTypeToString[resType]; !recognized {
			resType = DNSResTypeUnrecognized
		}
		questions = append(questions, DNSQuestion{
			Name:  q.Name.String(),
			Type:  resType,
			Class: uint16(q.Class),
		})
	}
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	var udpMaxSize uint16
	for {
		ad, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if ad.Type == dnsmessage.TypeOPT {
			udpMaxSize = uint16(ad.Class)
		}
		_ = p.SkipAdditional()
	}
	tc.tracer.publishTrace(dnsQueryTrace{
		DNSQueryMsg: DNSQueryMsg{
			SentAt:            sentAt,
			ID:                header.ID,
			RecursionDesired:  header.RecursionDesired,
			Truncated:         header.Truncated,
			Size:              uint32(len(data)),
			Questions:         questions,
			OptUDPPayloadSize: udpMaxSize,
		},
		conn:   tc.conn,
		connID: tc.connID,
	})
}

func (tc *tracedConn) parseDNSReply(data []byte, recvAt Timestamp) {
	var p dnsmessage.Parser
	header, err := p.Start(data)
	if err != nil {
		tc.log.Warningf(
			"nettrace: networkTracer id=%s: failed to parse DNS reply: %v (conn %v)",
			tc.tracer.getTracerID(), err, tc)
		return
	}
	_ = p.SkipAllQuestions()
	var answers []DNSAnswer
	for {
		a, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			tc.log.Warningf(
				"nettrace: networkTracer id=%s: failed to parse DNS reply answer: %v "+
					"(conn %v)", tc.tracer.getTracerID(), err, tc)
			continue
		}
		var resolvedVal string
		switch a.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				tc.log.Warningf(
					"nettrace: networkTracer id=%s: failed to parse A resource from DNS "+
						"reply: %v (conn %v)", tc.tracer.getTracerID(), err, tc)
				continue
			}
			resolvedVal = net.IP(r.A[:]).String()
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				tc.log.Warningf(
					"nettrace: networkTracer id=%s: failed to parse AAAA resource from DNS "+
						"reply: %v (conn %v)", tc.tracer.getTracerID(), err, tc)
				continue
			}
			resolvedVal = net.IP(r.AAAA[:]).String()
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				tc.log.Warningf(
					"nettrace: networkTracer id=%s: failed to parse CNAME resource from DNS "+
						"reply: %v (conn %v)", tc.tracer.getTracerID(), err, tc)
				continue
			}
			resolvedVal = r.CNAME.String()
		case dnsmessage.TypeNS:
			r, err := p.NSResource()
			if err != nil {
				tc.log.Warningf(
					"nettrace: networkTracer id=%s: failed to parse NS resource from DNS "+
						"reply: %v (conn %v)", tc.tracer.getTracerID(), err, tc)
				continue
			}
			resolvedVal = r.NS.String()
		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				tc.log.Warningf(
					"nettrace: networkTracer id=%s: failed to parse PTR resource from DNS "+
						"reply: %v (conn %v)", tc.tracer.getTracerID(), err, tc)
				continue
			}
			resolvedVal = r.PTR.String()
		case dnsmessage.TypeMX:
			r, err := p.MXResource()
			if err != nil {
				tc.log.Warningf(
					"nettrace: networkTracer id=%s: failed to parse MX resource from DNS "+
						"reply: %v (conn %v)", tc.tracer.getTracerID(), err, tc)
				continue
			}
			resolvedVal = r.MX.String()
		default:
			_ = p.SkipAnswer()
			continue
		}
		resType := DNSResType(a.Type)
		if _, recognized := DNSResTypeToString[resType]; !recognized {
			resType = DNSResTypeUnrecognized
		}
		answers = append(answers, DNSAnswer{
			Name:        a.Name.String(),
			Type:        resType,
			Class:       uint16(a.Class),
			TTL:         a.TTL,
			ResolvedVal: resolvedVal,
		})
	}
	var rCode DNSRCode
	rCode = DNSRCode(header.RCode)
	if _, recognized := DNSRCodeToString[rCode]; !recognized {
		rCode = DNSRCodeUnrecognized
	}
	tc.tracer.publishTrace(dnsReplyTrace{
		DNSReplyMsg: DNSReplyMsg{
			RecvAt:             recvAt,
			ID:                 header.ID,
			Authoritative:      header.Authoritative,
			RecursionAvailable: header.RecursionAvailable,
			Truncated:          header.Truncated,
			Size:               uint32(len(data)),
			RCode:              rCode,
			Answers:            answers,
		},
		conn:   tc.conn,
		connID: tc.connID,
	})
}

func (tc *tracedConn) Read(b []byte) (n int, err error) {
	callAt := tc.tracer.getRelTimestamp()
	n, err = tc.conn.Read(b)
	returnAt := tc.tracer.getRelTimestamp()
	tc.tracer.publishTrace(socketOpTrace{
		SocketOp: SocketOp{
			Type:      SocketOpTypeRead,
			CallAt:    callAt,
			ReturnAt:  returnAt,
			ReturnErr: errToString(err),
			DataLen:   uint32(n),
		},
		conn:   tc.conn,
		connID: tc.connID,
	})
	if err == nil && tc.forResolver && tc.withDNSTrace {
		// XXX Large DNS reply could be in theory split across multiple reads.
		//     (when DNS over TCP is used)
		tc.parseDNSReply(b[:n], returnAt)
	}
	return n, err
}

func (tc *tracedConn) Write(b []byte) (n int, err error) {
	callAt := tc.tracer.getRelTimestamp()
	n, err = tc.conn.Write(b)
	returnAt := tc.tracer.getRelTimestamp()
	tc.tracer.publishTrace(socketOpTrace{
		SocketOp: SocketOp{
			Type:      SocketOpTypeWrite,
			CallAt:    callAt,
			ReturnAt:  returnAt,
			ReturnErr: errToString(err),
			DataLen:   uint32(n),
		},
		conn:   tc.conn,
		connID: tc.connID,
	})
	if err == nil && tc.forResolver && tc.withDNSTrace {
		tc.parseDNSQuery(b[:n], returnAt)
	}
	return n, err
}

func (tc *tracedConn) Close() error {
	callAt := tc.tracer.getRelTimestamp()
	err := tc.conn.Close()
	returnAt := tc.tracer.getRelTimestamp()
	tc.tracer.publishTrace(socketOpTrace{
		SocketOp: SocketOp{
			CallAt:    callAt,
			ReturnAt:  returnAt,
			ReturnErr: errToString(err),
		},
		conn:   tc.conn,
		connID: tc.connID,
		closed: true,
	})
	return err
}

func (tc *tracedConn) LocalAddr() net.Addr {
	return tc.conn.LocalAddr()
}

func (tc *tracedConn) RemoteAddr() net.Addr {
	return tc.conn.RemoteAddr()
}

func (tc *tracedConn) SetDeadline(t time.Time) error {
	return tc.conn.SetDeadline(t)
}

func (tc *tracedConn) SetReadDeadline(t time.Time) error {
	return tc.conn.SetReadDeadline(t)
}

func (tc *tracedConn) SetWriteDeadline(t time.Time) error {
	return tc.conn.SetWriteDeadline(t)
}

// tracedPacketConn is used when connection also implements net.PacketConn (e.g. for UDP).
type tracedPacketConn struct {
	*tracedConn
	packetConn net.PacketConn
}

func (tpc *tracedPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	callAt := tpc.tracer.getRelTimestamp()
	n, addr, err = tpc.packetConn.ReadFrom(b)
	returnAt := tpc.tracer.getRelTimestamp()
	tpc.tracer.publishTrace(socketOpTrace{
		SocketOp: SocketOp{
			Type:       SocketOpTypeReadFrom,
			CallAt:     callAt,
			ReturnAt:   returnAt,
			ReturnErr:  errToString(err),
			RemoteAddr: addr.String(),
			DataLen:    uint32(n),
		},
		conn:   tpc.conn,
		connID: tpc.connID,
	})
	if err == nil && tpc.forResolver {
		tpc.parseDNSReply(b[:n], returnAt)
	}
	return
}

func (tpc *tracedPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	callAt := tpc.tracer.getRelTimestamp()
	n, err = tpc.packetConn.WriteTo(b, addr)
	returnAt := tpc.tracer.getRelTimestamp()
	tpc.tracer.publishTrace(socketOpTrace{
		SocketOp: SocketOp{
			Type:       SocketOpTypeWriteTo,
			CallAt:     callAt,
			ReturnAt:   returnAt,
			ReturnErr:  errToString(err),
			RemoteAddr: addr.String(),
			DataLen:    uint32(n),
		},
		conn:   tpc.conn,
		connID: tpc.connID,
	})
	if err == nil && tpc.forResolver {
		tpc.parseDNSQuery(b[:n], returnAt)
	}
	return
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
