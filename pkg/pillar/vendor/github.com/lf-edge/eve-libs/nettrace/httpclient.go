// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/golang-design/lockfree"
	"github.com/mdlayher/netlink"
	"github.com/sirupsen/logrus"
	"github.com/ti-mo/conntrack"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
)

// BatchSnapshot batch streaming API (server -> client sink) ----
type BatchSnapshot struct {
	Dials      []DialTrace
	HTTPReqs   []HTTPReqTrace
	DNSQueries []DNSQueryTrace
	TLSTunnels []TLSTunnelTrace
	TCPConns   []TCPConnTrace
	UDPConns   []UDPConnTrace
}

// BatchCallback callback signature to receive batches.
type BatchCallback func(BatchSnapshot)

// WithBatchOffload option is used to enable batch offloading. Use in NewHTTPClient(..., &WithBatchOffload{...}).
type WithBatchOffload struct {
	Callback          BatchCallback
	Threshold         int  // per evicting map; default 100 if <= 0
	FinalFlushOnClose bool // emit leftovers on Close()
}

func (*WithBatchOffload) isTraceOpt() {}

// WithBoundedInMemory option is used to enable bounded in-memory storage of traces. Use in NewHTTPClient(..., &WithBoundedInMemory{}).
type WithBoundedInMemory struct{}

func (*WithBoundedInMemory) isTraceOpt() {}

// ---- evictingMap flush payload ----

// Used by evictingMap to pass evicted items to the flush function.
type finalizedTrace struct {
	Bucket string
	Key    TraceID
	Value  interface{}
}

// HTTPClient wraps and enhances the standard HTTP client with tracing
// capabilities, i.e. monitoring and recording of network events related to the operations
// of the HTTP client, including HTTP requests made, TCP connections opened/attempted,
// TLS tunnels established/attempted, DNS queries sent, DNS answers received, etc.
type HTTPClient struct {
	// This lock protects all attributes of the HTTPClient except for lockfree Queues
	// which do not require locking.
	sync.Mutex
	id TraceID

	// The standard HTTP client is embedded and can be accessed simply as .Client
	// DO NOT change the Client.Transport field (to customize the HTTP client
	// behaviour), otherwise tracing functionality may get broken. Instead, configure
	// the desired behaviour of the HTTP client inside the HTTPClientCfg argument
	// of the HTTPClient constructor.
	*http.Client
	httpTransp *http.Transport

	// From the constructor config
	log                  Logger
	sourceIP             net.IP
	skipNameserver       NameserverSelector
	netProxy             func(req *http.Request) (*url.URL, error)
	withSockTrace        bool
	withDNSTrace         bool
	tcpHandshakeTimeout  time.Duration
	tcpKeepAliveInterval time.Duration

	// Network tracing
	nfConn           *conntrack.Conn
	tracingWG        sync.WaitGroup
	tracingCtx       context.Context
	cancelTracing    context.CancelFunc
	tracingStartedAt Timestamp
	pendingTraces    *lockfree.Queue // value: networkTrace
	noConnSockets    []*inetSocket   // not-yet connected AF_INET sockets
	pendingNoConnTCP []TCPConnTrace
	pendingNoConnUDP []UDPConnTrace
	connections      *evictingMap // stores *connection
	dials            *evictingMap // stores *dial
	tlsTuns          *evictingMap // stores *tlsTun
	dnsQueries       *evictingMap // stores *DNSQueryTrace
	httpReqs         *evictingMap // stores *HTTPReqTrace

	// Packet capture
	packetCapturer *packetCapturer // nil if disabled

	// Batch offload (count-based, no timers)
	batchCb           BatchCallback
	batchThreshold    int
	finalFlushOnClose bool
	batchSeq          uint64
	sessionUUID       string
}

const (
	defaultCap            = 5000
	maxMapFlushThreshold  = 10000 // safety cap
	defaultBatchThreshold = 1000
)

// NameserverSelector is a function that for a given nameserver decides
// whether it should be used for name resolution or skipped.
type NameserverSelector func(ipAddr net.IP, port uint16) (skip bool, reason string)

// HTTPClientCfg : configuration for the embedded HTTP client.
// This is not related to tracing but how the standard HTTP client itself should behave.
// Normally, HTTP client is configured by customizing the client's Transport
// (see https://pkg.go.dev/net/http#Transport).
// However, for the HTTP client tracing to function properly, Client.Transport,
// as installed and customized by the NewHTTPClient() constructor, should not be modified.
// The only allowed action is to additionally wrap the Transport with a RoundTripper
// implementation, which is allowed to for example modify HTTP requests/responses,
// but still should call the wrapped Transport for the HTTP request execution.
// An example of this is Transport from the oauth2 package, adding an Authorization
// header with a token: https://pkg.go.dev/golang.org/x/oauth2#Transport
type HTTPClientCfg struct {
	// PreferHTTP2, if true, will make the HTTP client to chose HTTP/2 as the preferred
	// HTTP version during the Application-Layer Protocol Negotiation (ALPN).
	PreferHTTP2 bool
	// SourceIP : source IP address to use for all connections and packets sent.
	// This includes all TCP connections opened for HTTP requests and UDP
	// packets sent with DNS requests.
	// Leave as nil to not bind sockets to any source IP address and instead let
	// the kernel to select the source IP address for each connection based on
	// the routing decision.
	SourceIP net.IP
	// SkipNameserver can be optionally provided as a callback to exclude some
	// of the system-wide configured DNS server(s) that would be otherwise used
	// for DNS queries.
	// The callback is called for every configured DNS server just before it is
	// queried. If the callback returns true, the server is skipped and the resolver
	// moves to the next one.
	// Every skipped nameserver is recorded in DialTrace.SkippedNameservers.
	SkipNameserver NameserverSelector
	// Proxy specifies a callback to return an address of a network proxy that
	// should be used for the given HTTP request.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)
	// TLSClientConfig specifies the TLS configuration to use for TLS tunnels.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config
	// ReqTimeout specifies a time limit for requests made by the HTTP client.
	// The timeout includes connection time, any redirects, and reading the response body.
	// The timer remains running after Get, Head, Post, or Do return and will interrupt
	// reading of the Response.Body.
	ReqTimeout time.Duration
	// TCPHandshakeTimeout specifies the maximum amount of time to wait for a TCP handshake
	// to complete. Zero means no timeout.
	TCPHandshakeTimeout time.Duration
	// TCPKeepAliveInterval specifies the interval between keep-alive probes for an active
	// TCP connection. If zero, keep-alive probes are sent with a default value (15 seconds),
	// if supported by the operating system.
	// If negative, keep-alive probes are disabled.
	TCPKeepAliveInterval time.Duration
	// TLSHandshakeTimeout specifies the maximum amount of time to wait for a TLS handshake
	// to complete. Zero means no timeout.
	TLSHandshakeTimeout time.Duration
	// DisableKeepAlive, if true, disables HTTP keep-alive and will only use the connection
	// to the server for a single HTTP request.
	DisableKeepAlive bool
	// DisableCompression, if true, prevents the Transport from requesting compression with
	// an "Accept-Encoding: gzip" request header when the Request contains no existing
	// Accept-Encoding value.
	DisableCompression bool
	// MaxIdleConns controls the maximum number of idle (keep-alive) connections across
	// all hosts. Zero means no limit.
	MaxIdleConns int
	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle (keep-alive) connections
	// to keep per-host. If zero, DefaultMaxIdleConnsPerHost from the http package is used.
	MaxIdleConnsPerHost int
	// MaxConnsPerHost optionally limits the total number of connections per host,
	// including connections in the dialing, active, and idle states. On limit violation,
	// dials will block.
	// Zero means no limit.
	MaxConnsPerHost int
	// IdleConnTimeout is the maximum amount of time an idle (keep-alive) connection will
	// remain idle before closing itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration
	// ResponseHeaderTimeout, if non-zero, specifies the amount of time to wait for a server's
	// response headers after fully writing the request (including its body, if any).
	// This time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration
	// ExpectContinueTimeout, if non-zero, specifies the amount of time to wait for a server's
	// first response headers after fully writing the request headers if the request has an
	// "Expect: 100-continue" header. Zero means no timeout and causes the body to be sent
	// immediately, without waiting for the server to approve.
	// This time does not include the time to send the request header.
	ExpectContinueTimeout time.Duration
}

// AF_INET socket.
// Used only until connection is made.
type inetSocket struct {
	addrTuple
	addrUpdateAt   Timestamp
	origFD         int
	dupFD          int // duplicated origFD; used to get socket name even after origFD was closed
	fromDial       TraceID
	fromResolvDial TraceID   // undefined if this socket was not opened by resolver
	createdAt      Timestamp // for TCP this is just before handshake
	origClosed     bool
	origClosedAt   Timestamp
	dupClosed      bool
	conntrack      conntrackEntry
}

type conntrackEntry struct {
	flow       *conntrack.Flow
	capturedAt Timestamp
	queriedAt  Timestamp // includes failed attempts
}

// TCP or UDP connection.
// Source/destination is from the client side.
type connection struct {
	addrTuple
	ID             TraceID
	SockCreatedAt  Timestamp
	ConnectedAt    Timestamp // for TCP this is just after handshake
	ClosedAt       Timestamp
	Reused         bool
	Closed         bool
	DialID         TraceID
	FromResolver   bool
	Conntrack      conntrackEntry
	TotalRecvBytes uint64
	TotalSentBytes uint64
	SocketOps      []SocketOp
}

// Single attempt to establish TCP connection.
type dial struct {
	DialTrace
	httpReqID TraceID
}

// Single TLS tunnel.
type tlsTun struct {
	TLSTunnelTrace // TCPConn is not always set here
	httpReqID      TraceID
}

// NewHTTPClient creates a new instance of HTTPClient, enhancing the standard
// http.Client with tracing capabilities.
// Tracing starts immediately:
//   - a background Go routine collecting traces is started
//   - packet capture starts on selected interfaces if WithPacketCapture option was passed
func NewHTTPClient(config HTTPClientCfg, uuid string, traceOpts ...TraceOpt) (*HTTPClient, error) {
	client := &HTTPClient{
		id:             IDGenerator(),
		log:            &nilLogger{},
		sourceIP:       config.SourceIP,
		skipNameserver: config.SkipNameserver,
		netProxy:       config.Proxy,
		pendingTraces:  lockfree.NewQueue(),
		sessionUUID:    uuid,
	}

	var err error

	client.tracingCtx, client.cancelTracing = context.WithCancel(context.Background())
	client.tcpHandshakeTimeout = config.TCPHandshakeTimeout
	client.tcpKeepAliveInterval = config.TCPKeepAliveInterval
	client.httpTransp = &http.Transport{
		Proxy:                 client.proxyForRequest,
		DialContext:           client.dial,
		TLSClientConfig:       config.TLSClientConfig,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		DisableKeepAlives:     config.DisableKeepAlive,
		DisableCompression:    config.DisableCompression,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ForceAttemptHTTP2:     config.PreferHTTP2,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
	}
	if config.PreferHTTP2 {
		err := http2.ConfigureTransport(client.httpTransp)
		if err != nil {
			return nil, err
		}
	}
	var withPcap *WithPacketCapture
	var withHTTP *WithHTTPReqTrace
	for _, traceOpt := range traceOpts {
		if topt, withDefaults := traceOpt.(TraceOptWithDefaults); withDefaults {
			topt.setDefaults()
		}
		switch opt := traceOpt.(type) {
		case *WithLogging:
			if opt.CustomLogger != nil {
				client.log = opt.CustomLogger
			} else {
				client.log = logrus.New()
			}
		case *WithConntrack:
			client.nfConn, err = conntrack.Dial(&netlink.Config{})
			if err != nil {
				return nil, fmt.Errorf("nettrace: failed to connect to netfilter: %v", err)
			}
		case *WithSockTrace:
			client.withSockTrace = true
		case *WithDNSQueryTrace:
			client.withDNSTrace = true
		case *WithHTTPReqTrace:
			withHTTP = opt
		case *WithPacketCapture:
			withPcap = opt
		case *WithBatchOffload:
			if opt.Callback != nil {
				client.batchCb = opt.Callback
				if opt.Threshold > 0 {
					client.batchThreshold = opt.Threshold
				} else {
					client.batchThreshold = defaultBatchThreshold
				}
				client.finalFlushOnClose = opt.FinalFlushOnClose
			}
		case *WithBoundedInMemory:
			client.batchThreshold = defaultBatchThreshold
		}
	}
	err = client.resetTraces(true) // initialize maps
	if err != nil {
		return nil, err
	}
	if withPcap != nil {
		client.packetCapturer = newPacketCapturer(client, client.log, *withPcap)
	}
	var rt http.RoundTripper
	if withHTTP != nil {
		rt = newTracedRoundTripper(client, *withHTTP)
	} else {
		rt = client.httpTransp
	}
	client.Client = &http.Client{
		Transport: rt,
		Timeout:   config.ReqTimeout,
	}
	if client.packetCapturer != nil {
		err := client.packetCapturer.startPcap(client.tracingCtx, &client.tracingWG)
		if err != nil {
			return nil, err
		}
	}
	client.tracingWG.Add(1)
	go client.runTracing()
	client.log.Tracef("nettrace: created new HTTPClient id=%s", client.id)
	return client, nil
}

func (c *HTTPClient) getTracerID() TraceID {
	return c.id
}

// Get timestamp for the current time relative to when racing started.
func (c *HTTPClient) getRelTimestamp() Timestamp {
	c.Lock()
	defer c.Unlock()
	return c.getRelTimestampNolock()
}

// Get timestamp for the current time relative to when racing started.
func (c *HTTPClient) getRelTimestampNolock() Timestamp {
	return c.tracingStartedAt.Elapsed()
}

// Publish newly recorded networkTrace into the queue for processing.
func (c *HTTPClient) publishTrace(t networkTrace) {
	c.pendingTraces.Enqueue(t)
}

// resetTraces : recreates all maps holding recorded network traces and pcaps.
func (c *HTTPClient) resetTraces(delOpenConns bool) error {
	c.Lock()
	defer c.Unlock()

	prevStart := c.tracingStartedAt
	c.tracingStartedAt = Timestamp{Abs: time.Now()}

	// Capacity for evicting maps:
	// If no callback configured, default to unlimited size
	capacity := c.batchThreshold

	// We never want evictingMap to flush by itself in this design.
	// - In storage offload mode, we flush via flushIfThresholdLocked.
	// - In pure in-memory mode, we don't flush at all.
	var mapFlushFn func([]finalizedTrace) // == nil

	mapFlushThreshold := c.batchThreshold
	if c.batchCb == nil {
		mapFlushThreshold = maxMapFlushThreshold // effectively never (but moot since flushFn is nil)
	}

	c.noConnSockets = []*inetSocket{}

	// (Re)create bounded, ordered maps.
	c.dials = newEvictingMap(capacity, "dials", mapFlushThreshold, mapFlushFn)
	c.tlsTuns = newEvictingMap(capacity, "tlsTuns", mapFlushThreshold, mapFlushFn)
	c.dnsQueries = newEvictingMap(capacity, "dnsQueries", mapFlushThreshold, mapFlushFn)
	c.httpReqs = newEvictingMap(capacity, "httpReqs", mapFlushThreshold, mapFlushFn)

	if delOpenConns {
		c.connections = newEvictingMap(capacity, "connections", mapFlushThreshold, mapFlushFn)
	} else if c.connections != nil {
		// Keep open connections, just turn relative timestamps into absolute ones
		// (otherwise they would turn negative).
		// IMPORTANT: iterate over a snapshot; Delete mutates the live slice.
		ids := append([]TraceID(nil), c.connections.order...)
		for _, id := range ids {
			val, ok := c.connections.Get(id)
			if !ok {
				continue
			}
			conn, _ := val.(*connection)
			if conn == nil {
				continue
			}
			if !conn.Closed {
				conn.Reused = true
				if !conn.SockCreatedAt.Undefined() && conn.SockCreatedAt.IsRel {
					conn.SockCreatedAt = prevStart.Add(conn.SockCreatedAt)
				}
				if !conn.ConnectedAt.Undefined() && conn.ConnectedAt.IsRel {
					conn.ConnectedAt = prevStart.Add(conn.ConnectedAt)
				}
				if !conn.ClosedAt.Undefined() && conn.ClosedAt.IsRel {
					conn.ClosedAt = prevStart.Add(conn.ClosedAt)
				}
				if !conn.Conntrack.capturedAt.Undefined() && conn.Conntrack.capturedAt.IsRel {
					conn.Conntrack.capturedAt = prevStart.Add(conn.Conntrack.capturedAt)
				}
				conn.Conntrack.queriedAt = Timestamp{} // Reset to undefined timestamp.
			} else {
				// Just use the map's Delete; do not delete from store directly.
				c.connections.Delete(id)
			}
		}
	} else {
		// If connections was nil (first init), create it.
		c.connections = newEvictingMap(capacity, "connections", mapFlushThreshold, mapFlushFn)
	}

	c.processPendingTraces(delOpenConns)

	if c.packetCapturer != nil {
		c.packetCapturer.clearPcap()
	}
	c.batchSeq = 0
	return nil
}

// ExportHTTPTraceToJSON writes the provided in-memory HTTPTrace to a single JSON file.
func (c *HTTPClient) ExportHTTPTraceToJSON(filePath string, ht HTTPTrace) error {
	// Ensure destination directory exists.
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}

	// Ensure slices encode as [] (not null).
	if ht.Dials == nil {
		ht.Dials = []DialTrace{}
	}
	if ht.TCPConns == nil {
		ht.TCPConns = []TCPConnTrace{}
	}
	if ht.UDPConns == nil {
		ht.UDPConns = []UDPConnTrace{}
	}
	if ht.DNSQueries == nil {
		ht.DNSQueries = []DNSQueryTrace{}
	}
	if ht.HTTPRequests == nil {
		ht.HTTPRequests = []HTTPReqTrace{}
	}
	if ht.TLSTunnels == nil {
		ht.TLSTunnels = []TLSTunnelTrace{}
	}

	out := struct {
		Description  string           `json:"description"`
		TraceBeginAt Timestamp        `json:"traceBeginAt"`
		TraceEndAt   Timestamp        `json:"traceEndAt"`
		Dials        []DialTrace      `json:"dials"`
		TCPConns     []TCPConnTrace   `json:"tcpConns"`
		UDPConns     []UDPConnTrace   `json:"udpConns"`
		DNSQueries   []DNSQueryTrace  `json:"dnsQueries"`
		HTTPRequests []HTTPReqTrace   `json:"httpRequests"`
		TLSTunnels   []TLSTunnelTrace `json:"tlsTunnels"`
	}{
		Description:  ht.NetTrace.Description,
		TraceBeginAt: ht.NetTrace.TraceBeginAt,
		TraceEndAt:   ht.NetTrace.TraceEndAt,
		Dials:        ht.Dials,
		TCPConns:     ht.TCPConns,
		UDPConns:     ht.UDPConns,
		DNSQueries:   ht.DNSQueries,
		HTTPRequests: ht.HTTPRequests,
		TLSTunnels:   ht.TLSTunnels,
	}

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return enc.Encode(out) // valid JSON, newline-terminated
}

func tcpTraceFrom(v interface{}, withSockTrace bool) TCPConnTrace {
	switch x := v.(type) {
	case *inetSocket: // no-conn
		return TCPConnTrace{
			TraceID:          IDGenerator(),
			FromDial:         x.fromDial,
			FromResolver:     !x.fromResolvDial.Undefined(),
			HandshakeBeginAt: x.createdAt,
			HandshakeEndAt:   x.origClosedAt,
			Connected:        false,
			AddrTuple:        x.addrTuple.toExportedAddrTuple(),
			Conntract:        conntrackToExportedEntry(x.conntrack.flow, x.conntrack.capturedAt),
		}
	case *connection: // established
		var st *SocketTrace
		if withSockTrace {
			st = &SocketTrace{SocketOps: x.SocketOps}
		}
		return TCPConnTrace{
			TraceID:          x.ID,
			FromDial:         x.DialID,
			FromResolver:     x.FromResolver,
			HandshakeBeginAt: x.SockCreatedAt,
			HandshakeEndAt:   x.ConnectedAt,
			Connected:        true,
			ConnCloseAt:      x.ClosedAt,
			AddrTuple:        x.addrTuple.toExportedAddrTuple(),
			Reused:           x.Reused,
			TotalSentBytes:   x.TotalSentBytes,
			TotalRecvBytes:   x.TotalRecvBytes,
			Conntract:        conntrackToExportedEntry(x.Conntrack.flow, x.Conntrack.capturedAt),
			SocketTrace:      st,
		}
	default:
		return TCPConnTrace{} // or panic("tcpTraceFrom: unsupported type")
	}
}

func udpTraceFrom(v interface{}, withSockTrace bool) UDPConnTrace {
	switch x := v.(type) {
	case *inetSocket: // no-conn
		return UDPConnTrace{
			TraceID:        IDGenerator(),
			FromDial:       x.fromDial,
			FromResolver:   !x.fromResolvDial.Undefined(),
			SocketCreateAt: x.createdAt,
			AddrTuple:      x.addrTuple.toExportedAddrTuple(),
			Conntract:      conntrackToExportedEntry(x.conntrack.flow, x.conntrack.capturedAt),
		}
	case *connection: // established
		var st *SocketTrace
		if withSockTrace {
			st = &SocketTrace{SocketOps: x.SocketOps}
		}
		return UDPConnTrace{
			TraceID:        x.ID,
			FromDial:       x.DialID,
			FromResolver:   x.FromResolver,
			SocketCreateAt: x.SockCreatedAt,
			ConnCloseAt:    x.ClosedAt,
			AddrTuple:      x.addrTuple.toExportedAddrTuple(),
			TotalSentBytes: x.TotalSentBytes,
			TotalRecvBytes: x.TotalRecvBytes,
			Conntract:      conntrackToExportedEntry(x.Conntrack.flow, x.Conntrack.capturedAt),
			SocketTrace:    st,
		}
	default:
		return UDPConnTrace{} // or panic("udpTraceFrom: unsupported type")
	}
}

// GetTrace returns a summary of all network and HTTP trace records (aka HTTPTrace),
// collected since the tracing last (re)started (either when the client was created
// or when the last ClearTrace() was called).
// This will include packet capture for every selected interface if it was enabled.
// The method allows to insert some description into the returned HTTPTrace
// (e.g. “download image XYZ”).
// Note that .TraceEndAt of the returned HTTPTrace is set to the current time.
// Also note that this does not stop tracing or clears the collected traces - use Close()
// or ClearTrace() for that.
func (c *HTTPClient) GetTrace(description string) (HTTPTrace, []PacketCapture, error) {
	c.Lock()
	defer c.Unlock()

	// Finish processing what we have.
	c.processPendingTraces(false)
	c.periodicSockUpdate(true)
	c.periodicConnUpdate(true)

	// Collect captured packets.
	var pcaps []PacketCapture
	if c.packetCapturer != nil {
		pcaps = c.packetCapturer.getPcap()
	}

	// Always fill meta (used by both modes).
	httpTrace := HTTPTrace{NetTrace: NetTrace{
		Description:  description,
		TraceBeginAt: c.tracingStartedAt,
		TraceEndAt:   c.getRelTimestampNolock(),
		SessionUUID:  c.sessionUUID,
	}}

	// If we are in batch-offload mode, do NOT aggregate in-memory maps.
	// The consumer should export JSON from the Bolt sink with this meta.
	if c.batchCb != nil {
		return httpTrace, pcaps, nil
	}

	// -------- In-memory mode: build full HTTPTrace from evicting maps --------

	// DNS queries/replies
	if len(c.dnsQueries.order) > 0 {
		ids := append([]TraceID(nil), c.dnsQueries.order...) // safe copy
		for _, id := range ids {
			v, ok := c.dnsQueries.Get(id)
			if !ok {
				c.dnsQueries.Delete(id)
				continue
			}
			q, ok := v.(*DNSQueryTrace)
			if !ok {
				c.dnsQueries.Delete(id)
				continue
			}

			// Best-effort backfill FromDial from the associated connection if missing.
			if q.FromDial.Undefined() {
				if cv, okConn := c.connections.Get(q.Connection); okConn {
					if cn, okType := cv.(*connection); okType {
						q.FromDial = cn.DialID
					}
				}
			}

			httpTrace.DNSQueries = append(httpTrace.DNSQueries, *q)
			c.dnsQueries.Delete(id)
		}
	}

	for _, sock := range c.noConnSockets {
		switch sock.proto {
		case syscall.IPPROTO_TCP:
			httpTrace.TCPConns = append(httpTrace.TCPConns, tcpTraceFrom(sock, c.withSockTrace))
		case syscall.IPPROTO_UDP:
			httpTrace.UDPConns = append(httpTrace.UDPConns, udpTraceFrom(sock, c.withSockTrace))
		}
	}

	ids := append([]TraceID(nil), c.connections.order...)
	for _, id := range ids {
		if v, ok := c.connections.Get(id); ok {
			if cn, ok := v.(*connection); ok {
				switch cn.proto {
				case syscall.IPPROTO_TCP:
					httpTrace.TCPConns = append(httpTrace.TCPConns, tcpTraceFrom(cn, c.withSockTrace))
				case syscall.IPPROTO_UDP:
					httpTrace.UDPConns = append(httpTrace.UDPConns, udpTraceFrom(cn, c.withSockTrace))
				}
			}
		}
	}

	// TLS tunnels
	if len(c.tlsTuns.order) > 0 {
		ids := append([]TraceID(nil), c.tlsTuns.order...)
		for _, id := range ids {
			if v, ok := c.tlsTuns.Get(id); ok {
				if t, ok := v.(*tlsTun); ok {
					// If TCPConn is unset, try to backfill from HTTP request.
					if t.TCPConn.Undefined() {
						if rv, ok2 := c.httpReqs.Get(t.httpReqID); ok2 {
							if r, ok2 := rv.(*HTTPReqTrace); ok2 {
								t.TCPConn = r.TCPConn
							}
						}
					}
					httpTrace.TLSTunnels = append(httpTrace.TLSTunnels, t.TLSTunnelTrace)
				}
			}
			c.tlsTuns.Delete(id)
		}
	}

	// HTTP requests
	if len(c.httpReqs.order) > 0 {
		ids := append([]TraceID(nil), c.httpReqs.order...)
		for _, id := range ids {
			if v, ok := c.httpReqs.Get(id); ok {
				if r, ok := v.(*HTTPReqTrace); ok {
					// If TCPConn is unset, try to correlate via dials (same as old behavior).
					if r.TCPConn.Undefined() {
						for _, did := range c.dials.order {
							if dv, ok := c.dials.Get(did); ok {
								if d, ok := dv.(*dial); ok {
									if !d.httpReqID.Undefined() && d.httpReqID == r.TraceID {
										r.TCPConn = d.EstablishedConn
										break
									}
								}
							}
						}
					}
					httpTrace.HTTPRequests = append(httpTrace.HTTPRequests, *r)
				}
			}
			//c.httpReqs.Delete(id)
		}
	}

	// Dials
	if len(c.dials.order) > 0 {
		ids := append([]TraceID(nil), c.dials.order...) // copy to avoid mutation issues
		for _, id := range ids {
			if v, ok := c.dials.Get(id); ok {
				if d, ok := v.(*dial); ok {
					httpTrace.Dials = append(httpTrace.Dials, d.DialTrace)
				}
			}
			c.dials.Delete(id)
		}
	}

	return httpTrace, pcaps, nil
}

// ClearTrace effectively restarts tracing by removing all traces collected up to
// this point. If packet capture is enabled (WithPacketCapture), packets captured
// so far are deleted.
// However, note that if TCP connection is reused from a previous run, it will reappear
// in the HTTPTrace (returned by GetTrace()) with some attributes restored to their previously
// recorded values (like .HandshakeBeginAt) and some updated (for example .Reused will be set
// to true).
func (c *HTTPClient) ClearTrace() error {
	return c.resetTraces(false)
}

// Close stops tracing of the embedded HTTP client, including packet capture if it
// was enabled.
// After this, it would be invalid to call GetTrace(), ClearTrace() or even to keep using
// the embedded HTTP Client.
func (c *HTTPClient) Close() error {
	c.cancelTracing()
	c.tracingWG.Wait()

	// Optionally flush leftovers to callback on close.
	c.Lock()
	if c.finalFlushOnClose && c.batchCb != nil {
		c.flushAllLocked()
	}
	c.Unlock()

	return c.resetTraces(true)
}

// runTracing is a separate Go routine that:
//   - processes collected network traces
//   - runs filtering of captured packets
//   - tries to obtain source IP + port for every traced socket
//   - tries to update conntrack entry for every traced connection
func (c *HTTPClient) runTracing() {
	defer c.tracingWG.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.tracingCtx.Done():
			c.log.Tracef("nettrace: networkTracer id=%s: network tracing stopped\n", c.id)
			return
		case <-ticker.C:
			c.Lock()
			c.processPendingTraces(false)
			c.periodicSockUpdate(false)
			c.periodicConnUpdate(false)
			if c.packetCapturer != nil && c.packetCapturer.readyToFilterPcap() {
				c.packetCapturer.filterPcap()
			}
			// Only count-based flush; no timers.
			// We already called processPendingTraces(), so check thresholds now.
			c.flushIfThresholdLocked()
			c.Unlock()
		}
	}
}

// periodicSockUpdate periodically retries to get source IP+port for non-yet-connected
// AF_INET sockets (if still not available) and updates obtained conntrack entries.
// The function should be called with HTTPClient locked.
func (c *HTTPClient) periodicSockUpdate(gettingTrace bool) {
	now := c.getRelTimestampNolock()
	// How frequently to retry to get source IP and source port for an AF_INET socket.
	const addrRetryPeriod = 3 * time.Second
	// How frequently to update conntrack entry for not-yet-established connection.
	const conntrackUpdatePeriod = 5 * time.Second
	for _, sock := range c.noConnSockets {
		if sock.dupClosed {
			// This socket is no longer actively traced.
			continue
		}
		// Check if the original FD is still open.
		if !sock.origClosed {
			ret, err := unix.FcntlInt(uintptr(sock.origFD), unix.F_GETFD, 0)
			if errno, ok := err.(syscall.Errno); ret == -1 && ok {
				if errno == syscall.EBADF {
					sock.origClosed = true
					sock.origClosedAt = now
				}
			}
		}
		// Try to get source IP + port if we still do not have it for this socket.
		if !sock.withSrcAddr() {
			if gettingTrace || sock.origClosed || sock.addrUpdateAt.Undefined() ||
				now.Sub(sock.addrUpdateAt) >= addrRetryPeriod {
				c.getSockSrcAddr(sock)
			}
		}
		// Update conntrack entry if it is too old.
		if c.nfConn != nil && sock.withSrcAddr() {
			if gettingTrace || sock.origClosed || sock.conntrack.queriedAt.Undefined() ||
				now.Sub(sock.conntrack.queriedAt) >= conntrackUpdatePeriod {
				c.getConntrack(sock.addrTuple, &sock.conntrack, now)
			}
		}
		if sock.origClosed {
			c.closeSockDupFD(sock)
		}
	}
}

func (c *HTTPClient) getConntrack(addr addrTuple, entry *conntrackEntry, now Timestamp) {
	srcAddr, _ := netip.AddrFromSlice(addr.srcIP)
	dstAddr, _ := netip.AddrFromSlice(addr.dstIP)
	flow, err := c.nfConn.Get(conntrack.Flow{
		TupleOrig: conntrack.Tuple{
			IP: conntrack.IPTuple{
				SourceAddress:      srcAddr,
				DestinationAddress: dstAddr,
			},
			Proto: conntrack.ProtoTuple{
				Protocol:        addr.proto,
				SourcePort:      addr.srcPort,
				DestinationPort: addr.dstPort,
			},
		},
	})
	entry.queriedAt = now
	if err != nil {
		c.log.Warningf("nettrace: networkTracer id=%s: "+
			"failed to get conntrack entry for connection %v: %v",
			c.id, addr, err)
		return
	}
	entry.capturedAt = now
	entry.flow = &flow
}

func (c *HTTPClient) getSockSrcAddr(sock *inetSocket) {
	sa, err := syscall.Getsockname(sock.dupFD)
	if err != nil {
		c.log.Warningf("nettrace: networkTracer id=%s: "+
			"failed to get src IP+port for duplicated FD %d: %v",
			c.id, sock.dupFD, err)
	} else if sa != nil {
		if laddr4, ok := sa.(*syscall.SockaddrInet4); ok {
			sock.srcPort = uint16(laddr4.Port)
			sock.srcIP = laddr4.Addr[:]
		} else if laddr6, ok := sa.(*syscall.SockaddrInet6); ok {
			sock.srcPort = uint16(laddr6.Port)
			sock.srcIP = laddr6.Addr[:]
		}
	}
}

func (c *HTTPClient) closeSockDupFD(sock *inetSocket) {
	err := syscall.Close(sock.dupFD)
	if err != nil {
		c.log.Warningf("nettrace: networkTracer id=%s: "+
			"failed to close duplicated FD %d: %v", c.id, sock.dupFD, err)
	}
	sock.dupClosed = true
}

// periodicConnUpdate periodically updates obtained conntrack entries
// for established connections.
// The function should be called with HTTPClient locked.
func (c *HTTPClient) periodicConnUpdate(gettingTrace bool) {
	now := c.getRelTimestampNolock()
	const conntrackUpdatePeriod = 20 * time.Second

	for _, id := range c.connections.order {
		connIface := c.connections.store[id]
		conn, ok := connIface.(*connection)
		if !ok || conn.Closed {
			continue
		}
		if c.nfConn != nil {
			if gettingTrace || conn.Conntrack.queriedAt.Undefined() ||
				now.Sub(conn.Conntrack.queriedAt) >= conntrackUpdatePeriod {
				c.getConntrack(conn.addrTuple, &conn.Conntrack, now)
			}
		}
	}
}

// === Threshold-only batch flushing ===
func (c *HTTPClient) flushIfThresholdLocked() {
	if c.batchCb == nil || c.batchThreshold <= 0 {
		return
	}
	snap := BatchSnapshot{}
	added := false

	popOldest := func(m *evictingMap, n int, fn func(id TraceID, v interface{})) {
		if n <= 0 || len(m.order) == 0 {
			return
		}
		if n > len(m.order) {
			n = len(m.order)
		}
		for i := 0; i < n; i++ {
			id := m.order[i]
			if v, ok := m.store[id]; ok {
				fn(id, v)
			}
		}
		// delete first n
		for i := 0; i < n; i++ {
			id := m.order[0]
			delete(m.store, id)
			m.order = m.order[1:]
		}
	}

	// Dials
	if len(c.dials.order) >= c.batchThreshold {
		popOldest(c.dials, c.batchThreshold, func(_ TraceID, v interface{}) {
			if d, ok := v.(*dial); ok {
				snap.Dials = append(snap.Dials, d.DialTrace)
				added = true
			}
		})
	}

	// HTTP requests
	if len(c.httpReqs.order) >= c.batchThreshold {
		popOldest(c.httpReqs, c.batchThreshold, func(_ TraceID, v interface{}) {
			if r, ok := v.(*HTTPReqTrace); ok {
				snap.HTTPReqs = append(snap.HTTPReqs, *r)
				added = true
			}
		})
	}

	// DNS queries
	if len(c.dnsQueries.order) >= c.batchThreshold {
		popOldest(c.dnsQueries, c.batchThreshold, func(_ TraceID, v interface{}) {
			if q, ok := v.(*DNSQueryTrace); ok {
				snap.DNSQueries = append(snap.DNSQueries, *q)
				added = true
			}
		})
	}

	// TLS tunnels
	if len(c.tlsTuns.order) >= c.batchThreshold {
		popOldest(c.tlsTuns, c.batchThreshold, func(_ TraceID, v interface{}) {
			if t, ok := v.(*tlsTun); ok {
				snap.TLSTunnels = append(snap.TLSTunnels, t.TLSTunnelTrace)
				added = true
			}
		})
	}

	// Connections (split TCP/UDP)
	if len(c.connections.order) >= c.batchThreshold {
		popOldest(c.connections, c.batchThreshold, func(_ TraceID, v interface{}) {
			if cn, ok := v.(*connection); ok {
				switch cn.proto {
				case syscall.IPPROTO_TCP:
					snap.TCPConns = append(snap.TCPConns, tcpTraceFrom(cn, c.withSockTrace))
					added = true
				case syscall.IPPROTO_UDP:
					snap.UDPConns = append(snap.UDPConns, udpTraceFrom(cn, c.withSockTrace))
					added = true
				}
			}
		})
	}

	// no-conn TCP
	if len(c.pendingNoConnTCP) >= c.batchThreshold {
		snap.TCPConns = append(snap.TCPConns, c.pendingNoConnTCP[:c.batchThreshold]...)
		c.pendingNoConnTCP = c.pendingNoConnTCP[c.batchThreshold:]
		added = true
	}

	// no-conn UDP
	if len(c.pendingNoConnUDP) >= c.batchThreshold {
		snap.UDPConns = append(snap.UDPConns, c.pendingNoConnUDP[:c.batchThreshold]...)
		c.pendingNoConnUDP = c.pendingNoConnUDP[c.batchThreshold:]
		added = true
	}

	if !added {
		return
	}
	cb := c.batchCb
	go cb(snap)
}

// flushAllLocked emits all remaining items (used on Close when enabled).
func (c *HTTPClient) flushAllLocked() {
	if c.batchCb == nil {
		return
	}
	snap := BatchSnapshot{}
	added := false

	emitAll := func(m *evictingMap, fn func(id TraceID, v interface{})) {
		for _, id := range append([]TraceID(nil), m.order...) {
			if v := m.store[id]; v != nil {
				fn(id, v)
			}
			delete(m.store, id)
		}
		m.order = m.order[:0]
	}

	emitAll(c.dials, func(_ TraceID, v interface{}) {
		if d, ok := v.(*dial); ok {
			snap.Dials = append(snap.Dials, d.DialTrace)
			added = true
		}
	})
	emitAll(c.httpReqs, func(_ TraceID, v interface{}) {
		if r, ok := v.(*HTTPReqTrace); ok {
			snap.HTTPReqs = append(snap.HTTPReqs, *r)
			added = true
		}
	})
	emitAll(c.dnsQueries, func(_ TraceID, v interface{}) {
		if q, ok := v.(*DNSQueryTrace); ok {
			snap.DNSQueries = append(snap.DNSQueries, *q)
			added = true
		}
	})
	emitAll(c.tlsTuns, func(_ TraceID, v interface{}) {
		if t, ok := v.(*tlsTun); ok {
			snap.TLSTunnels = append(snap.TLSTunnels, t.TLSTunnelTrace)
			added = true
		}
	})
	emitAll(c.connections, func(_ TraceID, v interface{}) {
		if cn, ok := v.(*connection); ok {
			switch cn.proto {
			case syscall.IPPROTO_TCP:
				snap.TCPConns = append(snap.TCPConns, tcpTraceFrom(cn, c.withSockTrace))
			case syscall.IPPROTO_UDP:
				snap.UDPConns = append(snap.UDPConns, udpTraceFrom(cn, c.withSockTrace))
			}
			added = true
		}
	})

	// NEW: also flush any pending "not-yet-connected" sockets as TCP/UDP entries.
	if len(c.pendingNoConnTCP) > 0 {
		snap.TCPConns = append(snap.TCPConns, c.pendingNoConnTCP...)
		c.pendingNoConnTCP = nil
		added = true
	}
	if len(c.pendingNoConnUDP) > 0 {
		snap.UDPConns = append(snap.UDPConns, c.pendingNoConnUDP...)
		c.pendingNoConnUDP = nil
		added = true
	}

	if !added {
		return
	}
	cb := c.batchCb
	go cb(snap)
}

// processPendingTraces : processes all currently pending network traces.
// The function should be called with HTTPClient locked.
// At the end of the procedure it calls the Callback to transfer data.
func (c *HTTPClient) processPendingTraces(dropAll bool) {
	var i uint64
	traceCount := c.pendingTraces.Length()

	for i = 0; i < traceCount; i++ {
		item := c.pendingTraces.Dequeue()
		now := c.getRelTimestampNolock()
		if dropAll {
			continue
		}
		switch t := item.(networkTrace).(type) {
		case DialTraceEnv:
			dial := c.getOrAddDialTrace(t.TraceID)
			if t.CTXClosed {
				dial.CtxCloseAt = t.CtxCloseAt
				continue
			} else if t.JustBegan {
				dial.httpReqID = t.HTTPReqID
				dial.DialBeginAt = t.DialBeginAt
				dial.SourceIP = t.SourceIP
				dial.DstAddress = t.DstAddress
				continue
			} else {
				dial.httpReqID = t.HTTPReqID
				dial.DialErr = t.DialErr
				dial.DialBeginAt = t.DialBeginAt
				dial.DialEndAt = t.DialEndAt
				dial.EstablishedConn = t.EstablishedConn
				dial.SourceIP = t.SourceIP
				dial.DstAddress = t.DstAddress
			}
			connAddrTuple := addrTupleFromConn(t.Conn)
			connSockIdx := -1
			for idx, sock := range c.noConnSockets {
				if sock.fromDial == dial.TraceID {
					c.finalizeNoConnSocket(sock, t.Conn != nil, now)
					if !connAddrTuple.undefined() && sock.addrTuple.equal(connAddrTuple) {
						connSockIdx = idx
					}
				}
			}
			if t.Conn != nil {
				connection := &connection{
					ID:          t.EstablishedConn,
					addrTuple:   connAddrTuple,
					ConnectedAt: t.DialEndAt,
					DialID:      dial.TraceID,
				}
				if connSockIdx != -1 {
					connection.SockCreatedAt = c.noConnSockets[connSockIdx].createdAt
					connection.Conntrack = c.noConnSockets[connSockIdx].conntrack
				}
				if c.nfConn != nil {
					c.getConntrack(connAddrTuple, &connection.Conntrack, now)
				}
				c.connections.Set(t.EstablishedConn, connection)
			}
			if connSockIdx != -1 {
				c.delNoConnSocket(connSockIdx)
			}

		case ResolverDialTr:
			dial := c.getOrAddDialTrace(t.ParentDial)
			dial.ResolverDials = append(dial.ResolverDials, ResolverDialTrace{
				DialBeginAt:     t.DialBeginAt,
				DialEndAt:       t.DialEndAt,
				DialErr:         errToString(t.DialErr),
				Nameserver:      t.Nameserver,
				EstablishedConn: t.ConnID,
			})
			// Stop monitoring sockets opened by this call to resolver's Dial.
			connAddrTuple := addrTupleFromConn(t.Conn) // undefined if dial failed
			connSockIdx := -1
			for idx, sock := range c.noConnSockets {
				if sock.fromDial == t.ParentDial && sock.fromResolvDial == t.ResolvDial {
					c.finalizeNoConnSocket(sock, t.Conn != nil, now)
					if !connAddrTuple.undefined() && sock.addrTuple.equal(connAddrTuple) {
						connSockIdx = idx
					}
				}
			}
			if t.Conn != nil {
				// Add entry for newly created connection.
				connection := &connection{
					ID:           t.ConnID,
					addrTuple:    connAddrTuple,
					ConnectedAt:  t.DialEndAt,
					DialID:       t.ParentDial,
					FromResolver: true,
				}
				if connSockIdx != -1 {
					connection.SockCreatedAt = c.noConnSockets[connSockIdx].createdAt
					connection.Conntrack = c.noConnSockets[connSockIdx].conntrack
				}
				if c.nfConn != nil {
					c.getConntrack(connAddrTuple, &connection.Conntrack, now)
				}
				c.connections.Set(t.ConnID, connection)
			}
			if connSockIdx != -1 {
				// Socket is connected - remove it from the noConnSockets slice.
				c.delNoConnSocket(connSockIdx)
			}

		case ResolverCloseTraceEnv:
			dial := c.getOrAddDialTrace(t.ParentDial)
			dial.SkippedNameservers = t.SkippedServers

		case SocketOpTrace:
			connIface, ok := c.connections.Get(t.ConnID)
			if !ok {
				break
			}
			connection := connIface.(*connection)
			if t.Closed {
				connection.Closed = true
				connection.ClosedAt = t.ReturnAt
				if c.nfConn != nil {
					c.getConntrack(connection.addrTuple, &connection.Conntrack, now)
				}
			} else {
				switch t.SocketOp.Type {
				case SocketOpTypeRead, SocketOpTypeReadFrom:
					connection.TotalRecvBytes += uint64(t.SocketOp.DataLen)
				case SocketOpTypeWrite, SocketOpTypeWriteTo:
					connection.TotalSentBytes += uint64(t.SocketOp.DataLen)
				}
				if c.withSockTrace {
					connection.SocketOps = append(connection.SocketOps, t.SocketOp)
				}
			}

		case TLSTrace:
			tlsTunTrace := c.getOrAddTLSTunTrace(t.TraceID)
			tlsTunTrace.TLSTunnelTrace = t.TLSTunnelTrace
			tlsTunTrace.httpReqID = t.HTTPReqID
			httpReqTrace := c.getOrAddHTTPReqTrace(t.HTTPReqID)
			if t.ForProxy {
				httpReqTrace.ProxyTLSTunnel = t.TraceID
			} else {
				httpReqTrace.TLSTunnel = t.TraceID
			}

		case DNSQueryTraceEnv:
			dnsTrace := c.getOrAddDNSTrace(t.ConnID)
			dnsTrace.DNSQueryMsgs = append(dnsTrace.DNSQueryMsgs, t.DNSQueryMsg)

		case DNSReplyTrace:
			dnsTrace := c.getOrAddDNSTrace(t.connID)
			dnsTrace.DNSReplyMsgs = append(dnsTrace.DNSReplyMsgs, t.DNSReplyMsg)

		case HTTPBodyTrace:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.HTTPReqID)
			if t.ISRequest {
				httpReqTrace.ReqContentLen = t.ReadBodyLen
			} else {
				httpReqTrace.RespContentLen = t.ReadBodyLen
			}

		case HTTPConnTrace:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.HTTPReqID)
			if connTrace := c.lookupConnTrace(t.Conn); connTrace != nil {
				httpReqTrace.TCPConn = connTrace.ID
			}

		case HTTPReqTraceEnv:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.HTTPReqID)
			// Prefer proto versions from the response if already provided.
			if httpReqTrace.RespRecvAt.Undefined() {
				httpReqTrace.ProtoMajor = t.ProtoMajor
				httpReqTrace.ProtoMinor = t.ProtoMinor
			}
			httpReqTrace.ReqSentAt = t.SentAt
			httpReqTrace.ReqMethod = t.ReqMethod
			httpReqTrace.ReqURL = t.ReqURL
			httpReqTrace.ReqHeader = t.Header
			httpReqTrace.NetworkProxy = t.NetProxy

		case HTTPRespTrace:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.HTTPReqID)
			if t.RtErr != nil {
				httpReqTrace.ReqError = errToString(t.RtErr)
				continue
			}
			httpReqTrace.ProtoMajor = t.ProtoMajor
			httpReqTrace.ProtoMinor = t.ProtoMinor
			httpReqTrace.ReqError = ""
			httpReqTrace.RespRecvAt = t.RecvAt
			httpReqTrace.RespStatusCode = t.StatusCode
			httpReqTrace.RespHeader = t.Header
		}
	}

	// After integrating this batch of traces, check thresholds and emit if needed.
	c.flushIfThresholdLocked()

}

func (c *HTTPClient) getOrAddDialTrace(id TraceID) *dial {
	if val, ok := c.dials.Get(id); ok {
		if d, ok := val.(*dial); ok {
			return d
		}
	}
	d := &dial{DialTrace: DialTrace{TraceID: id}}
	c.dials.Set(id, d)
	return d
}

func (c *HTTPClient) getOrAddDNSTrace(connID TraceID) *DNSQueryTrace {
	for _, id := range c.dnsQueries.order {
		entry, ok := c.dnsQueries.Get(id)
		if !ok {
			continue
		}
		if dnsQuery, ok := entry.(*DNSQueryTrace); ok && dnsQuery.Connection == connID {
			return dnsQuery
		}
	}
	trace := &DNSQueryTrace{
		TraceID:    IDGenerator(),
		Connection: connID,
	}
	c.dnsQueries.Set(trace.TraceID, trace)
	return trace
}

func (c *HTTPClient) getOrAddTLSTunTrace(id TraceID) *tlsTun {
	if val, ok := c.tlsTuns.Get(id); ok {
		if t, ok := val.(*tlsTun); ok {
			return t
		}
	}
	t := &tlsTun{TLSTunnelTrace: TLSTunnelTrace{TraceID: id}}
	c.tlsTuns.Set(id, t)
	return t
}

func (c *HTTPClient) getOrAddHTTPReqTrace(id TraceID) *HTTPReqTrace {
	if val, ok := c.httpReqs.Get(id); ok {
		if r, ok := val.(*HTTPReqTrace); ok {
			return r
		}
	}
	r := &HTTPReqTrace{TraceID: id}
	c.httpReqs.Set(id, r)
	return r
}

func (c *HTTPClient) finalizeNoConnSocket(sock *inetSocket, connected bool, now Timestamp) {
	if sock.dupClosed {
		return
	}
	if !sock.withSrcAddr() {
		c.getSockSrcAddr(sock)
	}
	if c.nfConn != nil && sock.withSrcAddr() {
		c.getConntrack(sock.addrTuple, &sock.conntrack, now)
	}
	if !connected && sock.origClosedAt.Undefined() {
		sock.origClosedAt = now
	}

	// enqueue into pending TCP/UDP lists when not connected
	if !connected {
		switch sock.proto {
		case syscall.IPPROTO_TCP:
			c.pendingNoConnTCP = append(c.pendingNoConnTCP, tcpTraceFrom(sock, c.withSockTrace))
		case syscall.IPPROTO_UDP:
			c.pendingNoConnUDP = append(c.pendingNoConnUDP, udpTraceFrom(sock, c.withSockTrace))
		}
	}

	c.closeSockDupFD(sock)
}

func (c *HTTPClient) delNoConnSocket(idx int) {
	sockCount := len(c.noConnSockets)
	c.noConnSockets[idx] = c.noConnSockets[sockCount-1]
	c.noConnSockets[sockCount-1] = nil
	c.noConnSockets = c.noConnSockets[:sockCount-1]
}

func (c *HTTPClient) lookupConnTrace(conn net.Conn) *connection {
	addr := addrTupleFromConn(conn)
	for _, id := range c.connections.order {
		val, ok := c.connections.Get(id)
		if !ok {
			continue
		}
		connTrace, ok := val.(*connection)
		if !ok {
			continue
		}
		if connTrace.addrTuple.equal(addr) {
			return connTrace
		}
	}
	return nil
}

func (c *HTTPClient) getHTTPTransport() http.RoundTripper {
	return c.httpTransp
}

func (c *HTTPClient) iterNoConnSockets(iterCb connIterCallback) {
	for _, socket := range c.noConnSockets {
		stop := iterCb(socket.addrTuple, socket.conntrack.flow)
		if stop {
			return
		}
	}
}

func (c *HTTPClient) iterConnections(iterCb connIterCallback) {
	for _, id := range c.connections.order {
		val, ok := c.connections.Get(id)
		if !ok {
			continue
		}
		conn, ok := val.(*connection)
		if !ok {
			continue
		}
		stop := iterCb(conn.addrTuple, conn.Conntrack.flow)
		if stop {
			return
		}
	}
}

func (c *HTTPClient) proxyForRequest(req *http.Request) (*url.URL, error) {
	if c.netProxy == nil {
		return nil, nil
	}
	return c.netProxy(req)
}

func (c *HTTPClient) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := newTracedDialer(c, c.log, c.sourceIP, c.tcpHandshakeTimeout,
		c.tcpKeepAliveInterval, c.withDNSTrace, c.skipNameserver)
	return dialer.dial(ctx, network, addr)
}

// Start tracing a newly created AF_INET socket.
// This is done synchronously with HTTPClient locked (i.e. not using queue) to ensure
// that HTTPClient will not accidentally filter out first packets produced by this socket
// due to a race condition between trace processing and packet filtering.
func (c *HTTPClient) traceNewSocket(sock *inetSocket) {
	c.Lock()
	defer c.Unlock()
	now := c.getRelTimestampNolock()
	for _, oldSock := range c.noConnSockets {
		if !oldSock.origClosed && oldSock.origFD == sock.origFD {
			// oldSock.origFD was closed and got reused.
			oldSock.origClosed = true
			oldSock.origClosedAt = now
			break
		}
	}
	c.noConnSockets = append(c.noConnSockets, sock)
}
