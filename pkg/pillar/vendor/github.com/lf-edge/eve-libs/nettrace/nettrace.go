// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package nettrace allows to trace (monitor and record a summary of)
// network operations that happen behind the scenes during e.g. an HTTP
// request processing as executed by http.Client.
package nettrace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lithammer/shortuuid/v4"
)

// PacketCapture is a recording of all/some packets that arrived or left through
// a given interface.
// This is typically included alongside NetTrace and captured packets are filtered
// to contain only those that correspond with the traced connections.
type PacketCapture struct {
	// InterfaceName : name of the interface on which the packets were captured
	// (on either direction).
	InterfaceName string
	// SnapLen is the maximum number of bytes captured for each packet.
	// Larger packets are (silently) returned truncated.
	SnapLen uint32
	// Packets : captured packets.
	Packets []gopacket.Packet
	// Truncated is returned as true if the capture does not contain all packets
	// because the maximum allowed total size would be exceeded otherwise.
	Truncated bool
	// WithTCPPayload : true if packet capture was configured to include also
	// TCP packets with non empty payload.
	WithTCPPayload bool
}

// WriteTo writes packet capture to a file or a buffer or whatever w represents.
func (pc PacketCapture) WriteTo(w io.Writer) (n int64, err error) {
	pw := pcapgo.NewWriter(w)
	err = pw.WriteFileHeader(pc.SnapLen, layers.LinkTypeEthernet)
	if err != nil {
		return n, err
	}
	n += 24 // header always is 24; it would be nice if this were a constant in github.com/google/gopacket
	for _, packet := range pc.Packets {
		b := packet.Data()
		err = pw.WritePacket(packet.Metadata().CaptureInfo, b)
		if err != nil {
			return n, err
		}
		n += int64(len(b))
	}
	return n, nil
}

// WriteToFile saves packet capture to a given file.
func (pc PacketCapture) WriteToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = pc.WriteTo(f)
	return err
}

// AnyNetTrace is implemented by NetTrace and all its extensions (like HTTPTrace).
// Can be used as a data type for methods that accept any kind network trace as an input.
type AnyNetTrace interface {
	isNetTrace()
}

// NetTrace : recording of network operations performed by a client program
// (e.g. HTTP client).
type NetTrace struct {
	// Description provided by the caller.
	Description string `json:"description"`
	// TraceBeginAt : (absolute) timestamp of the moment when the tracing started.
	TraceBeginAt Timestamp `json:"traceBeginAt"`
	// TraceEndAt : time (relative to TraceBeginAt) when the tracing ended.
	TraceEndAt Timestamp `json:"traceEndAt"`
	// Dials : all attempts to establish connection with a remote endpoint.
	Dials DialTraces `json:"dials"`
	// TCPConns : all established or failed TCP connections.
	TCPConns TCPConnTraces `json:"tcpConns"`
	// UDPConns : all UDP connections (successful or failed exchanges of UDP datagrams).
	UDPConns UDPConnTraces `json:"udpConns"`
	// DNSQueries : all performed DNS queries.
	// Empty if WithDNSQueryTrace is not enabled.
	DNSQueries DNSQueryTraces `json:"dnsQueries"`
	// TLSTunnels : all opened (or attempted to open) TLS tunnels.
	TLSTunnels TLSTunnelTraces `json:"tlsTunnels"`
}

func (NetTrace) isNetTrace() {}

// HTTPTrace : recording of network operations performed by an HTTP client.
type HTTPTrace struct {
	NetTrace
	// HTTPRequests : all executed HTTP requests.
	HTTPRequests HTTPReqTraces `json:"httpRequests"`
}

// DialTrace : recording of an attempt to establish TCP connection with a remote endpoint.
// The endpoint can be addressed using an IP address or a domain name.
type DialTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// DialBeginAt : time when the dial attempt started.
	DialBeginAt Timestamp `json:"dialBeginAt"`
	// DialEndAt : time when the dial attempt ended - either successfully with an established
	// connection or when it failed and gave up.
	DialEndAt Timestamp `json:"dialEndAt"`
	// DialErr : if dial failed, here is the reason.
	DialErr string `json:"dialErr,omitempty"`
	// CtxCloseAt : time when the context assigned to the dial attempt was closed/canceled
	// by the caller.
	CtxCloseAt Timestamp `json:"ctxCloseAt"`
	// DstAddress : address of the remote endpoint in the format <host>:<port>
	// where <host> is either IP address or a domain name.
	DstAddress string `json:"dstAddress"`
	// ResolverDials : connection attempts made by the resolver towards nameservers with
	// the aim of resolving <host> from DstAddress.
	ResolverDials []ResolverDialTrace `json:"resolverDials,omitempty"`
	// SkippedNameservers : nameservers which were configured in the OS but got skipped
	// (i.e. not used for DstAddress resolution) based on the user config
	// (for example using HTTPClientCfg.SkipNameserver).
	SkippedNameservers []string `json:"skippedNameservers,omitempty"`
	// SourceIP : source IP address statically configured for the dial request.
	// Empty if the source IP was not selected statically.
	SourceIP string `json:"sourceIP,omitempty"`
	// EstablishedConn : reference to an established TCP connection.
	EstablishedConn TraceID `json:"establishedConn,omitempty"`
}

// DialTraces is a list of Dial traces.
type DialTraces []DialTrace

// Get pointer to the Dial trace with the given ID.
func (traces DialTraces) Get(id TraceID) *DialTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// ResolverDialTrace : recording of a resolver's attempt to establish UDP or TCP connection
// with a nameserver.
type ResolverDialTrace struct {
	// DialBeginAt : time when the dial attempt started.
	DialBeginAt Timestamp `json:"dialBeginAt"`
	// DialEndAt : time when the dial attempt ended - either successfully with an established
	// connection or when it failed and gave up.
	DialEndAt Timestamp `json:"dialEndAt"`
	// DialErr : if dial failed, here is the reason.
	DialErr string `json:"dialErr,omitempty"`
	// Nameserver : destination nameserver address in the format <host>:<port>.
	Nameserver string `json:"nameserver"`
	// EstablishedConn : reference to an established UDP or TCP connection.
	EstablishedConn TraceID `json:"establishedConn,omitempty"`
}

// TCPConnTrace : recording of an established or even just attempted but not completed
// TCP connection.
type TCPConnTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// FromDial : Reference to Dial where this originated from.
	FromDial TraceID `json:"fromDial"`
	// FromResolver : true if this connection was opened from the resolver
	// and towards a nameserver.
	FromResolver bool `json:"fromResolver,omitempty"`
	// HandshakeBeginAt : time when the TCP handshake process started (SYN packet was sent).
	HandshakeBeginAt Timestamp `json:"handshakeBeginAt"`
	// HandshakeEndAt : time when the handshake process ended - either successfully with
	// an established TCP connection or with a failure (canceled, timeouted, refused, ...).
	HandshakeEndAt Timestamp `json:"handshakeEndAt"`
	// Connected is true if the handshake succeeded to establish connection.
	// If this is false, reason of the failure can be available as part of DialTrace (.DialErr).
	Connected bool `json:"connected"`
	// ConnCloseAt : time when the connection was closed (from our side).
	ConnCloseAt Timestamp `json:"connCloseAt"`
	// AddrTuple : 4-tuple with source + destination addresses identifying the TCP connection.
	AddrTuple AddrTuple `json:"addrTuple"`
	// Reused : was this TCP connection reused between separately recorded NetTrace records?
	// For example, if two HTTP requests are separately traced (producing two NetTrace instances),
	// the first one will have recording of a new TCP connection, while the second one will
	// repeat the same TCPConnTrace, with some updates for the second request and Reused=true.
	Reused bool `json:"reused"`
	// TotalSentBytes : total number of bytes sent as a TCP payload through this connection.
	// (i.e. TCP header and lower-layer headers are not included)
	TotalSentBytes uint64 `json:"totalSentBytes"`
	// TotalRecvBytes : total number of bytes received as a TCP payload through this connection.
	// (i.e. TCP header and lower-layer headers are not included)
	TotalRecvBytes uint64 `json:"totalRecvBytes"`
	// Conntract : conntrack entry (provided by Netfilter connection tracking system) corresponding
	// to this connection.
	// Nil if not available or if conntrack tracing was disabled.
	// Conntrack entry is taken as late as possible, i.e. preferably after the connection closes
	// but before the conntrack entry timeouts and is removed. This is to ensure that packet/byte
	// counters and conntrack/TCP states cover the entirety of the connection.
	Conntract *ConntractEntry `json:"conntrack,omitempty"`
	// SocketTrace : recording of socket operations (read, write).
	// Nil if socket tracing was not enabled.
	SocketTrace *SocketTrace `json:"socketTrace,omitempty"`
}

// TCPConnTraces is a list of TCP connection traces.
type TCPConnTraces []TCPConnTrace

// Get pointer to the TCP connection trace with the given ID.
func (traces TCPConnTraces) Get(id TraceID) *TCPConnTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// UDPConnTrace : recording of a UDP connection (unreliable exchange of UDP datagrams between
// our UDP client and a remote UDP peer).
type UDPConnTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// FromDial : Reference to Dial where this originated from.
	FromDial TraceID `json:"fromDial"`
	// FromResolver : true if this connection was opened from the resolver
	// and towards a nameserver.
	FromResolver bool `json:"fromResolver,omitempty"`
	// SocketCreateAt : time when the UDP socket was created.
	SocketCreateAt Timestamp `json:"socketCreateAt"`
	// ConnCloseAt : time when the connection was closed (from our side).
	ConnCloseAt Timestamp `json:"connCloseAt"`
	// AddrTuple : 4-tuple with source + destination addresses identifying the UDP connection.
	AddrTuple AddrTuple `json:"addrTuple"`
	// TotalSentBytes : total number of bytes sent as a UDP payload through this connection.
	// (i.e. UDP header and lower-layer headers are not included)
	TotalSentBytes uint64 `json:"totalSentBytes"`
	// TotalRecvBytes : total number of bytes received as a UDP payload through this connection.
	// (i.e. UDP header and lower-layer headers are not included)
	TotalRecvBytes uint64 `json:"totalRecvBytes"`
	// Conntract : conntrack entry (provided by Netfilter connection tracking system) corresponding
	// to this connection.
	// Nil if not available or if conntrack tracing was disabled.
	// Conntrack entry is taken as late as possible, i.e. preferably after the connection closes
	// but before the conntrack entry timeouts and is removed. This is to ensure that packet/byte
	// counters and conntrack/UDP states cover the entirety of the connection.
	Conntract *ConntractEntry `json:"conntrack,omitempty"`
	// SocketTrace : recording of socket operations (read, write).
	// Nil if socket tracing was not enabled.
	SocketTrace *SocketTrace `json:"socketTrace,omitempty"`
}

// UDPConnTraces is a list of UDP connection traces.
type UDPConnTraces []UDPConnTrace

// Get pointer to the UDP connection trace with the given ID.
func (traces UDPConnTraces) Get(id TraceID) *UDPConnTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// DNSQueryTrace : recording of a DNS query.
type DNSQueryTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// FromDial : Reference to Dial where this originated from.
	FromDial TraceID `json:"fromDial"`
	// Connection : Reference to the trace record of the underlying UDP or TCP connection,
	// which was used to carry DNS request(s)/response(s).
	Connection TraceID `json:"connection"`
	// DNSQueryMsgs : all DNS query messages sent within this connection.
	DNSQueryMsgs []DNSQueryMsg `json:"dnsQueryMsgs"`
	// DNSReplyMsgs : all DNS reply messages received within this connection.
	DNSReplyMsgs []DNSReplyMsg `json:"dnsReplyMsgs"`
}

// DNSQueryTraces is a list of DNS query traces.
type DNSQueryTraces []DNSQueryTrace

// Get pointer to the DNS query trace with the given ID.
func (traces DNSQueryTraces) Get(id TraceID) *DNSQueryTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// DNSQueryMsg : a single DNS query message.
type DNSQueryMsg struct {
	// SentAt : time when the message was sent (wrote into the socket).
	SentAt Timestamp `json:"sentAt"`
	// ID : identifier used to match DNS query with DNS reply.
	ID uint16 `json:"id"`
	// RecursionDesired : indicates if the client means a recursive query.
	RecursionDesired bool `json:"recursionDesired"`
	// Truncated : indicates that this message was truncated due to excessive length.
	Truncated bool `json:"truncated"`
	// Size of the message in bytes.
	Size uint32 `json:"size"`
	// Questions : DNS questions.
	Questions []DNSQuestion `json:"questions"`
	// OptUDPPayloadSize : the maximum UDP payload size that the requestor accepts.
	// It is specified inside the query message using EDNS (RFC 6891).
	OptUDPPayloadSize uint16 `json:"optUDPPayloadSize,omitempty"`
}

// DNSQuestion : single question from DNS query message.
type DNSQuestion struct {
	// Name of the requested resource.
	Name string `json:"name"`
	// Type of RR (A, AAAA, MX, TXT, etc.)
	Type DNSResType `json:"type"`
	// Class code.
	Class uint16 `json:"class"`
}

// DNSReplyMsg : a single DNS reply message.
type DNSReplyMsg struct {
	// RecvAt : time when the message was received (read from the socket).
	RecvAt Timestamp `json:"recvAt"`
	// ID : identifier used to match DNS query with DNS reply.
	ID uint16 `json:"id"`
	// Authoritative : indicates if the DNS server is authoritative for the queried hostname.
	Authoritative bool `json:"authoritative"`
	// RecursionAvailable : indicates if the replying DNS server supports recursion.
	RecursionAvailable bool `json:"recursionAvailable"`
	// Truncated : indicates that this message was truncated due to excessive length.
	Truncated bool `json:"truncated"`
	// Size of the message in bytes.
	Size uint32 `json:"size"`
	// RCode : Response code.
	RCode DNSRCode `json:"rCode"`
	// Answers : DNS answers.
	Answers []DNSAnswer `json:"answers"`
}

// DNSAnswer : single answer from DNS reply message.
type DNSAnswer struct {
	// Name of the resource to which this record pertains.
	Name string `json:"name"`
	// Type of RR (A, AAAA, MX, TXT, etc.)
	Type DNSResType `json:"type"`
	// Class is the class of network to which this DNS resource record pertains.
	Class uint16 `json:"class"`
	// TTL is the length of time (measured in seconds) which this resource
	// record is valid for (time to live).
	TTL uint32 `json:"ttl"`
	// ResolvedVal content depends on the resource type. It can be an IP address
	// (A/AAAA), CNAME, NS, PTR, or MX (for others we do not include type-specific
	// answer attributes).
	ResolvedVal string `json:"resolvedVal,omitempty"`
}

// TLSTunnelTrace : recording of a TLS tunnel establishment
// (successful or a failed attempt).
type TLSTunnelTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// TCPConn : reference to TCP connection over which the tunnel was established
	// (or attempted to be established).
	TCPConn TraceID `json:"tcpConn"`
	// HandshakeBeginAt : time when the TLS handshake process started (ClientHello was sent).
	HandshakeBeginAt Timestamp `json:"handshakeBeginAt"`
	// HandshakeEndAt : time when the handshake process ended - either successfully with
	// an established TLS tunnel or with a failure (canceled, timeouted, refused, ...).
	HandshakeEndAt Timestamp `json:"handshakeEndAt"`
	// HandshakeErr : if handshake failed to establish, here is the reason.
	HandshakeErr string `json:"handshakeErr,omitempty"`
	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool `json:"didResume"`
	// PeerCerts are the certificates sent by the peer, in the order in which they were sent.
	// (When TLS handshake succeeds) The first element is the leaf certificate that
	// the connection is verified against.
	// However, when TLS handshake fails it might not be possible to obtain all certificates
	// and typically only one will be included (e.g. the problematic one).
	PeerCerts []PeerCert `json:"peerCerts"`
	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	// See: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4
	CipherSuite uint16 `json:"cipherSuite"`
	// NegotiatedProtocol is the application protocol negotiated with ALPN.
	// (e.g. HTTP/1.1, h2)
	NegotiatedProto string `json:"negotiatedProto,omitempty"`
	// ServerName is the value of the Server name Indication (SNI) extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string `json:"serverName"`
}

// TLSTunnelTraces is a list of TLS tunnel traces.
type TLSTunnelTraces []TLSTunnelTrace

// Get pointer to the TLS tunnel trace with the given ID.
func (traces TLSTunnelTraces) Get(id TraceID) *TLSTunnelTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// HTTPReqTrace : recording of an HTTP request.
type HTTPReqTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// TCPConn : reference to the underlying TCP connection used by the HTTP request.
	TCPConn TraceID `json:"tcpConn"`
	// TLSTunnel : TLS tunnel opened with the destination HTTPS server.
	TLSTunnel TraceID `json:"tlsTunnel,omitempty"`
	// ProxyTLSTunnel : TLS tunnel opened with an HTTPS proxy (if used, see NetworkProxy).
	ProxyTLSTunnel TraceID `json:"proxyTLSTunnel,omitempty"`
	// ProtoMajor : major number of the HTTP protocol version used for
	// request & response.
	ProtoMajor uint8 `json:"protoMajor"`
	// ProtoMinor : minor number of the HTTP protocol version used for
	// request & response.
	ProtoMinor uint8 `json:"protoMinor"`
	// NetworkProxy : address of a network proxy in the format scheme://host:port
	// Empty string if the HTTP request was not (explicitly) proxied.
	NetworkProxy string `json:"networkProxy,omitempty"`

	// Request:

	// ReqSentAt : time when the HTTP request was sent.
	ReqSentAt Timestamp `json:"reqSentAt"`
	// ReqMethod specifies the HTTP method of the request (GET, POST, PUT, etc.).
	// List of all standardized methods: https://www.iana.org/assignments/http-methods/http-methods.xhtml
	ReqMethod string `json:"reqMethod"`
	// ReqURL specifies the resource addressed by the request.
	ReqURL string `json:"reqURL"`
	// ReqHeader : request header.
	// If tracing of HTTP header fields is disabled (which it is by default), then this is
	// an empty slice.
	ReqHeader HTTPHeader `json:"reqHeader,omitempty"`
	// ReqContentLen : size of the HTTP request body content.
	// This may be available even if Content-Length header field is not.
	// But note that this only counts the part of the content that was actually loaded
	// by the HTTP client (if it was interrupted or the content transport failed and
	// the client gave up, this would not count the whole message body).
	// This is before transfer encoding is applied on the message body.
	ReqContentLen uint64 `json:"reqContentLen"`
	// ReqError : if the HTTP request failed, this is the reason.
	ReqError string `json:"reqError,omitempty"`

	// Response:

	// RespRecvAt : time when the HTTP response was received.
	RespRecvAt Timestamp `json:"respRecvAt"`
	// RespRecvAt : response status code.
	RespStatusCode int `json:"respStatusCode"`
	// RespHeader : response header.
	// If tracing of HTTP header fields is disabled (which it is by default), then this is
	// an empty slice.
	RespHeader HTTPHeader `json:"respHeader,omitempty"`
	// RespContentLen : number of bytes of the HTTP response body received and read
	// by the caller. This may be available even if Content-Length header field is not.
	// But note that if the caller didn't read all bytes until EOF and didn't close
	// the response body, this will not count the whole message body.
	// This is after the received content is decoded (HTTP transfer encoding).
	RespContentLen uint64 `json:"RespContentLen"`
}

// HTTPReqTraces is a list of HTTP request traces.
type HTTPReqTraces []HTTPReqTrace

// Get pointer to the HTTP request trace with the given ID.
func (traces HTTPReqTraces) Get(id TraceID) *HTTPReqTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// HTTPHeaderKV : a single HTTP message header field (a key-value pair).
type HTTPHeaderKV struct {
	// FieldName : Field name.
	FieldName string `json:"fieldName"`
	// FieldVal : Field value.
	// This can be hidden (returned as empty string even if the actual value is not empty)
	// by tracing options (can contain sensitive data).
	FieldVal string `json:"fieldVal,omitempty"`
	// FieldValLen : Length of the (actual, possibly hidden) field value (in characters).
	// Just like field value, this can be also hidden (returned as zero) using tracing
	// options (e.g. if knowing value length is enough to raise security concern).
	FieldValLen uint32 `json:"fieldValLen,omitempty"`
}

// HTTPHeader represents the key-value pairs in an HTTP header.
type HTTPHeader []HTTPHeaderKV

// Get pointer to the HTTP header field with the given name.
func (header HTTPHeader) Get(name string) *HTTPHeaderKV {
	// According to RFC2616, field names are case-insensitive.
	name = strings.ToLower(name)
	for i := range header {
		if strings.ToLower(header[i].FieldName) == name {
			return &header[i]
		}
	}
	return nil
}

// PeerCert : description of a peer certificate.
type PeerCert struct {
	// Subject describes the certificate subject (roughly following
	// the RFC 2253 Distinguished Names syntax).
	Subject string `json:"subject"`
	// Issuer describes the certificate issuer (roughly following
	// the RFC 2253 Distinguished Names syntax).
	Issuer string `json:"issuer"`
	// NotBefore : date and time on which the certificate becomes valid.
	NotBefore Timestamp `json:"notBefore"`
	// NotAfter : date and time after which the certificate is no longer valid.
	NotAfter Timestamp `json:"notAfter"`
	// IsCA : true if this certificate corresponds to a certificate authority.
	IsCA bool `json:"isCA"`
}

// AddrTuple : source + destination addresses fully identifying a network connection.
// Whether this is from our side or a remote side, before or after NAT, depends
// on the context.
type AddrTuple struct {
	// SrcIP : source IP address.
	SrcIP string `json:"srcIP"`
	// SrcPort : source port.
	SrcPort uint16 `json:"srcPort"`
	// DstIP : destination IP address.
	DstIP string `json:"dstIP"`
	// DstPort : destination port.
	DstPort uint16 `json:"dstPort"`
}

// ConntractEntry : single conntrack entry (one tracked connection).
// L4 protocol depends on the context, i.e. whether it is under TCPConnTrace or UDPConnTrace.
type ConntractEntry struct {
	// CapturedAt : time when this conntrack entry was obtained.
	CapturedAt Timestamp `json:"capturedAt"`
	// Status : conntrack connection's status flags.
	Status ConntrackStatus `json:"status"`
	// TCPState : state of the TCP connection.
	// TCPStateNone if this is a non-TCP (UDP) conntrack.
	TCPState TCPState `json:"tcpState,omitempty"`
	// Mark assigned to the connection by conntrack (CONNMARK).
	Mark uint32 `json:"mark"`
	// AddrOrig : source+dest addresses in the direction from the origin,
	// i.e. client->server, before NAT.
	AddrOrig AddrTuple `json:"addrOrig"`
	// AddrReply : source+dest addresses in the reply direction,
	// i.e. server->client, after NAT.
	AddrReply AddrTuple `json:"addrReply"`
	// PacketsSent : number of packets sent out towards the remote endpoint.
	PacketsSent uint64 `json:"packetsSent"`
	// PacketsRecv : number of packets received from the remote endpoint.
	PacketsRecv uint64 `json:"packetsRecv"`
	// BytesSent : number of bytes sent out towards the remote endpoint.
	BytesSent uint64 `json:"bytesSent"`
	// BytesRecv : number of bytes received from the remote endpoint.
	BytesRecv uint64 `json:"bytesRecv"`
}

// SocketTrace : recording of I/O operations performed over AF_INET(6) socket.
type SocketTrace struct {
	SocketOps []SocketOp `json:"socketOps"`
}

// SocketOp : single I/O operation performed over AF_INET(6) socket.
type SocketOp struct {
	// Type of the operation.
	Type SocketOpType `json:"type"`
	// CallAt : Time when the socket operation was initiated by the caller.
	CallAt Timestamp `json:"callAt"`
	// ReturnAt : Time when the socket operation returned.
	ReturnAt Timestamp `json:"returnAt"`
	// ReturnErr : error returned by the operation (if any).
	ReturnErr string `json:"returnErr,omitempty"`
	// RemoteAddr : with packet-oriented operation (readFrom, writeTo), this field
	// will contain address of the remote endpoint from which the packet was received
	// or to which it was sent. The address is in the format host:port.
	RemoteAddr string `json:"remoteAddr,omitempty"`
	// DataLen : number of read/written bytes.
	DataLen uint32 `json:"dataLen"`
}

// TraceID : identifier for a trace record (of any type - can be DialTrace, TCPConnTrace, etc.).
type TraceID string

// Undefined returns true if the ID is not defined (empty).
func (t TraceID) Undefined() bool {
	return t == ""
}

// TIDGenerator is a function that generates unique IDs for network traces.
type TIDGenerator func() TraceID

// IDGenerator by default uses AtomicCounterID to generate network trace IDs.
// It is exported and can be changed.
var IDGenerator TIDGenerator = AtomicCounterID

var idCounter uint64

// AtomicCounterID atomically increments integer and returns it as the trace ID
// in the decimal format and prefixed with "tid-".
// Generated IDs are very concise but guarantee uniqueness only within a single
// execution of one process (which is the minimum requirement for TraceID).
func AtomicCounterID() TraceID {
	id := atomic.AddUint64(&idCounter, 1)
	return TraceID("tid-" + strconv.FormatUint(id, 10))
}

// ShortUUID can be used as IDGenerator to produce a shorter variant of universally
// unique identifiers for network traces.
// To use this instead of the default AtomicCounterID, add to your code:
//
//	func init() {
//	    nettrace.IDGenerator = nettrace.ShortUUID
//	}
func ShortUUID() TraceID {
	return TraceID(shortuuid.New())
}

// Timestamp : absolute or relative timestamp for a traced event.
// Zero value (IsRel is False && Abs.IsZero() is true) represents undefined
// timestamp.
type Timestamp struct {
	// Abs : Absolute time. Used when absolute time is needed (e.g. start of tracing)
	// or when relative time is not appropriate (e.g. reused connection would have
	// negative Rel time).
	// Ignore if IsRel=true.
	Abs time.Time
	// IsRel : true if this timestamp is relative (Rel should be read instead of Abs)
	IsRel bool
	// Number of milliseconds elapsed since NetTrace.TraceBeginAt.
	Rel uint32
}

// Undefined returns true when timestamp is not defined.
func (t Timestamp) Undefined() bool {
	return !t.IsRel && t.Abs.IsZero()
}

// Add relative timestamp to absolute timestamp and get absolute timestamp.
func (t Timestamp) Add(relT Timestamp) Timestamp {
	if t.IsRel {
		panic("t is not absolute")
	}
	if !relT.IsRel {
		panic("relT is not relative")
	}
	return Timestamp{
		Abs: t.Abs.Add(time.Duration(relT.Rel) * time.Millisecond),
	}
}

// Sub returns the duration t-t2.
// It is required that timestamps are of the same type - either both relative
// or both absolute.
func (t Timestamp) Sub(t2 Timestamp) time.Duration {
	if t.IsRel != t2.IsRel {
		panic("t and t2 are timestamps of different type")
	}
	if t.IsRel {
		return time.Duration(t.Rel-t2.Rel) * time.Millisecond
	}
	return t.Abs.Sub(t2.Abs)
}

// Elapsed returns how much time elapsed since t.
// t must be absolute timestamp.
// Returned timestamp is relative.
func (t Timestamp) Elapsed() Timestamp {
	if t.IsRel {
		panic("t is not absolute")
	}
	return Timestamp{
		IsRel: true,
		Rel:   uint32(time.Since(t.Abs) / time.Millisecond),
	}
}

// MarshalJSON marshals Timestamp as a quoted json string.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	if t.Undefined() {
		return []byte("\"undefined\""), nil
	}
	if t.IsRel {
		return []byte(fmt.Sprintf("\"%+dms\"", t.Rel)), nil
	}
	return t.Abs.MarshalJSON()
}

// UnmarshalJSON un-marshals a quoted json string to Timestamp.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	*t = Timestamp{}
	if string(b) == "null" {
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	if len(str) == 0 || str == "undefined" {
		return nil
	}
	if str[0] == '+' || str[0] == '-' {
		// relative timestamp
		// Cut sign and unit "ms" before calling Atoi.
		if len(str) <= 3 {
			return fmt.Errorf("invalid relative timestamp: %s", str)
		}
		rel, err := strconv.Atoi(str[1 : len(str)-2])
		if err != nil {
			return err
		}
		t.IsRel = true
		t.Rel = uint32(rel)
		return nil
	}
	return t.Abs.UnmarshalJSON(b)
}

// TCPState : TCP connection states as observed by conntrack.
// See tcp_conntrack_names in netfilter/nf_conntrack_proto_tcp.c
type TCPState uint8

const (
	// TCPStateNone : TCP state is not defined/available.
	TCPStateNone TCPState = iota
	// TCPStateSynSent : SYN-only packet seen (TCP establishment 3-way handshake)
	TCPStateSynSent
	// TCPStateSynRecv : SYN-ACK packet seen (TCP establishment 3-way handshake)
	TCPStateSynRecv
	// TCPStateEstablished : ACK packet seen (TCP establishment 3-way handshake)
	TCPStateEstablished
	// TCPStateFinWait : FIN packet seen (TCP termination 4-way handshake)
	TCPStateFinWait
	// TCPStateCloseWait : ACK seen (after FIN) (TCP termination 4-way handshake)
	TCPStateCloseWait
	// TCPStateLastAck :  FIN seen (after FIN) (TCP termination 4-way handshake)
	TCPStateLastAck
	// TCPStateTimeWait : last ACK seen (TCP termination 4-way handshake)
	TCPStateTimeWait
	// TCPStateClose : closed connection (RST)
	TCPStateClose
	// TCPStateSynSent2 : SYN-only packet seen from reply dir, simultaneous open.
	TCPStateSynSent2
)

// TCPStateToString : convert TCPState to string representation
// used in JSON.
var TCPStateToString = map[TCPState]string{
	TCPStateNone:        "none",
	TCPStateSynSent:     "syn-sent",
	TCPStateSynRecv:     "sync-recv",
	TCPStateEstablished: "established",
	TCPStateFinWait:     "fin-wait",
	TCPStateCloseWait:   "close-wait",
	TCPStateLastAck:     "last-ack",
	TCPStateTimeWait:    "time-wait",
	TCPStateClose:       "close",
	TCPStateSynSent2:    "syn-sent2",
}

// TCPStateFromString : get TCPState from a string representation.
var TCPStateFromString = map[string]TCPState{
	"":            TCPStateNone,
	"none":        TCPStateNone,
	"syn-sent":    TCPStateSynSent,
	"syn-recv":    TCPStateSynRecv,
	"established": TCPStateEstablished,
	"fin-wait":    TCPStateFinWait,
	"close-wait":  TCPStateCloseWait,
	"last-ack":    TCPStateLastAck,
	"time-wait":   TCPStateTimeWait,
	"close":       TCPStateClose,
	"syn-sent2":   TCPStateSynSent2,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s TCPState) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(TCPStateToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *TCPState) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = TCPStateFromString[j]
	return nil
}

// ConntrackStatus : status of a conntrack entry (combination of flags, not enum).
type ConntrackStatus uint32

// ConntrackFlags : conntrack connection's status flags, from enum ip_conntrack_status.
// See uapi/linux/netfilter/nf_conntrack_common.h
var ConntrackFlags = map[string]uint32{
	// IPS_EXPECTED : it's an expected connection.
	"expected": 1,
	// IPS_SEEN_REPLY : we've seen packets both ways.
	"seen-reply": 1 << 1,
	// IPS_ASSURED : conntrack should never be early-expired.
	"assured": 1 << 2,
	// IPS_CONFIRMED : connection is confirmed, originating packet has left box.
	"confirmed": 1 << 3,
	// IPS_SRC_NAT : connection needs src NAT in orig dir.
	"src-nat": 1 << 4,
	// IPS_DST_NAT : connection needs dst NAT in orig dir.
	"dst-nat": 1 << 5,
	// IPS_SEQ_ADJUST : connection needs TCP sequence adjusted.
	"seq-adjust": 1 << 6,
	// IPS_SRC_NAT_DONE : src NAT in orig dir was performed.
	"src-nat-done": 1 << 7,
	// IPS_DST_NAT_DONE : dst NAT in orig dir was performed.
	"dst-nat-done": 1 << 8,
	// IPS_DYING : connection is dying (removed from lists).
	"dying": 1 << 9,
	// IPS_FIXED_TIMEOUT : connection has fixed timeout.
	"fixed-timeout": 1 << 10,
	// IPS_TEMPLATE : conntrack is a template.
	"template": 1 << 11,
	// IPS_UNTRACKED : conntrack is a fake untracked entry. Obsolete and not used anymore.
	"untracked": 1 << 12,
	// IPS_HELPER: conntrack got a helper explicitly attached (ruleset, ctnetlink).
	"helper": 1 << 13,
	// IPS_OFFLOAD: conntrack has been offloaded to flow table.
	"offload": 1 << 14,
}

// MarshalJSON marshals ConntrackStatus (flags) as a quoted json string.
func (s ConntrackStatus) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	firstFlag := true
	for flagStr, flagVal := range ConntrackFlags {
		if uint32(s)&flagVal > 0 {
			if !firstFlag {
				buffer.WriteString(`|`)
			}
			buffer.WriteString(flagStr)
			firstFlag = false
		}
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to ConntrackStatus (flags).
func (s *ConntrackStatus) UnmarshalJSON(b []byte) error {
	var flagsStr string
	if err := json.Unmarshal(b, &flagsStr); err != nil {
		return err
	}
	flags := strings.Split(flagsStr, "|")
	var status uint32
	for _, flagStr := range flags {
		if flagVal, ok := ConntrackFlags[flagStr]; ok {
			status |= flagVal
		}
	}
	*s = ConntrackStatus(status)
	return nil
}

// SocketOpType : operations that can be performed over AF_INET(6) socket.
type SocketOpType uint8

const (
	// SocketOpTypeUnrecognized : operation is not recognized.
	SocketOpTypeUnrecognized SocketOpType = iota
	// SocketOpTypeRead : read bytes from connected socket.
	SocketOpTypeRead
	// SocketOpTypeReadFrom : read packet from connected socket.
	// (also see SocketOp.RemoteAddr)
	SocketOpTypeReadFrom
	// SocketOpTypeWrite : write bytes to connected socket.
	SocketOpTypeWrite
	// SocketOpTypeWriteTo : write packet destined to a given address
	// (see SocketOp.RemoteAddr).
	SocketOpTypeWriteTo
)

// SocketOpTypeToString : convert SocketOpType to string representation
// used in JSON.
var SocketOpTypeToString = map[SocketOpType]string{
	SocketOpTypeUnrecognized: "unrecognized-op",
	SocketOpTypeRead:         "read",
	SocketOpTypeReadFrom:     "read-from",
	SocketOpTypeWrite:        "write",
	SocketOpTypeWriteTo:      "write-to",
}

// SocketOpTypeFromString : get SocketOpType from a string representation.
var SocketOpTypeFromString = map[string]SocketOpType{
	"":                SocketOpTypeUnrecognized,
	"unrecognized-op": SocketOpTypeUnrecognized,
	"read":            SocketOpTypeRead,
	"read-from":       SocketOpTypeReadFrom,
	"write":           SocketOpTypeWrite,
	"write-to":        SocketOpTypeWriteTo,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s SocketOpType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(SocketOpTypeToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *SocketOpType) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = SocketOpTypeFromString[j]
	return nil
}

// DNSRCode : https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
type DNSRCode uint16

const (
	// DNSRCodeNoError : No error.
	DNSRCodeNoError DNSRCode = iota
	// DNSRCodeFormatErr : Format Error.
	DNSRCodeFormatErr
	// DNSRCodeServFail : Server Failure.
	DNSRCodeServFail
	// DNSRCodeNXDomain : Non-Existent Domain.
	DNSRCodeNXDomain
	// DNSRCodeNotImp : Not Implemented.
	DNSRCodeNotImp
	// DNSRCodeRefused : Query Refused.
	DNSRCodeRefused
	// DNSRCodeUnrecognized : used for every other RCode.
	// Note that other types of errors are unlikely to be encountered from a client
	// (and are not recognized by the DNS message parser that we use anyway).
	DNSRCodeUnrecognized = 65534 // not assigned by IANA
)

// DNSRCodeToString : convert DNSRCode to string representation
// used in JSON.
var DNSRCodeToString = map[DNSRCode]string{
	DNSRCodeUnrecognized: "unrecognized-rcode",
	DNSRCodeNoError:      "no-error",
	DNSRCodeFormatErr:    "format-error",
	DNSRCodeServFail:     "server-fail",
	DNSRCodeNXDomain:     "non-existent-domain",
	DNSRCodeNotImp:       "not-implemented",
	DNSRCodeRefused:      "query-refused",
}

// DNSRCodeFromString : get DNSRCode from a string representation.
var DNSRCodeFromString = map[string]DNSRCode{
	"":                    DNSRCodeUnrecognized,
	"unrecognized-rcode":  DNSRCodeUnrecognized,
	"no-error":            DNSRCodeNoError,
	"format-error":        DNSRCodeFormatErr,
	"server-fail":         DNSRCodeServFail,
	"non-existent-domain": DNSRCodeNXDomain,
	"not-implemented":     DNSRCodeNotImp,
	"query-refused":       DNSRCodeRefused,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s DNSRCode) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(DNSRCodeToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *DNSRCode) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = DNSRCodeFromString[j]
	return nil
}

// DNSResType : https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
type DNSResType uint16

const (
	// DNSResTypeUnrecognized : unrecognized Resource Record (RR) type.
	// Note that RR types not listed here are unlikely to be encountered from a client
	// (and are not recognized by the DNS message parser that we use anyway).
	DNSResTypeUnrecognized DNSResType = iota // 0 is reserved

	// DNSResTypeA : 32-bit IPv4 address.
	DNSResTypeA DNSResType = 1
	// DNSResTypeNS : Name server record.
	DNSResTypeNS DNSResType = 2
	// DNSResTypeCNAME : Canonical name record.
	DNSResTypeCNAME DNSResType = 5
	// DNSResTypeSOA : Start of [a zone of] authority record.
	DNSResTypeSOA DNSResType = 6
	// DNSResTypeWKS : Well-known services supported by a host (obsolete record type).
	DNSResTypeWKS DNSResType = 11
	// DNSResTypePTR : Pointer to a canonical name.
	DNSResTypePTR DNSResType = 12
	// DNSResTypeHINFO : Host Information.
	DNSResTypeHINFO DNSResType = 13
	// DNSResTypeMINFO : Subscriber mailing lists (record type unlikely to be ever adopted).
	DNSResTypeMINFO DNSResType = 14
	// DNSResTypeMX : Mail exchange record.
	DNSResTypeMX DNSResType = 15
	// DNSResTypeTXT : Text record.
	DNSResTypeTXT DNSResType = 16
	// DNSResTypeAAAA : IPv6 address record.
	DNSResTypeAAAA DNSResType = 28
	// DNSResTypeSRV : Service locator.
	DNSResTypeSRV DNSResType = 33
	// DNSResTypeOPT : Pseudo-record type needed to support EDNS.
	DNSResTypeOPT DNSResType = 41
	// DNSResTypeAXFR : Authoritative Zone Transfer.
	DNSResTypeAXFR DNSResType = 252
	// DNSResTypeALL : All cached records.
	DNSResTypeALL DNSResType = 255
)

// DNSResTypeToString : convert DNSResType to string representation
// used in JSON.
var DNSResTypeToString = map[DNSResType]string{
	DNSResTypeUnrecognized: "unrecognized-type",
	DNSResTypeA:            "A",
	DNSResTypeNS:           "NS",
	DNSResTypeCNAME:        "CNAME",
	DNSResTypeSOA:          "SOA",
	DNSResTypeWKS:          "WKS",
	DNSResTypePTR:          "PTR",
	DNSResTypeHINFO:        "HINFO",
	DNSResTypeMINFO:        "MINFO",
	DNSResTypeMX:           "MX",
	DNSResTypeTXT:          "TXT",
	DNSResTypeAAAA:         "AAAA",
	DNSResTypeSRV:          "SRV",
	DNSResTypeOPT:          "OPT",
	DNSResTypeAXFR:         "AXFR",
	DNSResTypeALL:          "ALL",
}

// DNSResTypeFromString : get DNSResType from a string representation.
var DNSResTypeFromString = map[string]DNSResType{
	"":                  DNSResTypeUnrecognized,
	"unrecognized-type": DNSResTypeUnrecognized,
	"A":                 DNSResTypeA,
	"NS":                DNSResTypeNS,
	"CNAME":             DNSResTypeCNAME,
	"SOA":               DNSResTypeSOA,
	"WKS":               DNSResTypeWKS,
	"PTR":               DNSResTypePTR,
	"HINFO":             DNSResTypeHINFO,
	"MINFO":             DNSResTypeMINFO,
	"MX":                DNSResTypeMX,
	"TXT":               DNSResTypeTXT,
	"AAAA":              DNSResTypeAAAA,
	"SRV":               DNSResTypeSRV,
	"OPT":               DNSResTypeOPT,
	"AXFR":              DNSResTypeAXFR,
	"ALL":               DNSResTypeALL,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s DNSResType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(DNSResTypeToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *DNSResType) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = DNSResTypeFromString[j]
	return nil
}
