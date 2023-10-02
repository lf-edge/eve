// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	connections      map[TraceID]*connection
	dials            map[TraceID]*dial
	tlsTuns          map[TraceID]*tlsTun
	dnsQueries       map[TraceID]*DNSQueryTrace // Note: .FromDial is not always set here
	httpReqs         map[TraceID]*HTTPReqTrace

	// Packet capture
	packetCapturer *packetCapturer // nil if disabled
}

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
	id             TraceID
	sockCreatedAt  Timestamp
	connectedAt    Timestamp // for TCP this is just after handshake
	closedAt       Timestamp
	reused         bool
	closed         bool
	dialID         TraceID
	fromResolver   bool
	conntrack      conntrackEntry
	totalRecvBytes uint64
	totalSentBytes uint64
	socketOps      []SocketOp
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
func NewHTTPClient(config HTTPClientCfg, traceOpts ...TraceOpt) (*HTTPClient, error) {
	client := &HTTPClient{
		id:             IDGenerator(),
		log:            &nilLogger{},
		sourceIP:       config.SourceIP,
		skipNameserver: config.SkipNameserver,
		netProxy:       config.Proxy,
		pendingTraces:  lockfree.NewQueue(),
	}
	err := client.resetTraces(true) // initialize maps
	if err != nil {
		return nil, err
	}
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
		}
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
	// Make sure that all pending traces for open connections are processed.
	c.processPendingTraces(delOpenConns)
	prevStart := c.tracingStartedAt
	c.tracingStartedAt = Timestamp{Abs: time.Now()}
	c.noConnSockets = []*inetSocket{}
	c.dials = make(map[TraceID]*dial)
	c.tlsTuns = make(map[TraceID]*tlsTun)
	c.dnsQueries = make(map[TraceID]*DNSQueryTrace)
	c.httpReqs = make(map[TraceID]*HTTPReqTrace)
	if delOpenConns {
		c.connections = make(map[TraceID]*connection)
	} else {
		// Keep open connections, just turn relative timestamps into absolute ones.
		// (otherwise they would turn negative)
		for id, conn := range c.connections {
			if !conn.closed {
				conn.reused = true
				if !conn.sockCreatedAt.Undefined() && conn.sockCreatedAt.IsRel {
					conn.sockCreatedAt = prevStart.Add(conn.sockCreatedAt)
				}
				if !conn.connectedAt.Undefined() && conn.connectedAt.IsRel {
					conn.connectedAt = prevStart.Add(conn.connectedAt)
				}
				if !conn.closedAt.Undefined() && conn.closedAt.IsRel {
					conn.closedAt = prevStart.Add(conn.closedAt)
				}
				if !conn.conntrack.capturedAt.Undefined() && conn.conntrack.capturedAt.IsRel {
					conn.conntrack.capturedAt = prevStart.Add(conn.conntrack.capturedAt)
				}
				conn.conntrack.queriedAt = Timestamp{} // Reset to undefined timestamp.
			} else {
				delete(c.connections, id)
			}
		}
	}
	if c.packetCapturer != nil {
		c.packetCapturer.clearPcap()
	}
	return nil
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
	// Last-minute processing of collected traces...
	c.processPendingTraces(false)
	c.periodicSockUpdate(true)
	c.periodicConnUpdate(true)
	// Collect captured packets.
	var pcaps []PacketCapture
	if c.packetCapturer != nil {
		pcaps = c.packetCapturer.getPcap()
	}
	// Combine all network traces into one HTTPTrace.
	httpTrace := HTTPTrace{NetTrace: NetTrace{
		Description:  description,
		TraceBeginAt: c.tracingStartedAt,
		TraceEndAt:   c.getRelTimestampNolock(),
	}}
	for _, dial := range c.dials {
		httpTrace.Dials = append(httpTrace.Dials, dial.DialTrace)
	}
	for _, sock := range c.noConnSockets {
		conntrack := conntrackToExportedEntry(sock.conntrack.flow, sock.conntrack.capturedAt)
		switch sock.proto {
		case syscall.IPPROTO_TCP:
			httpTrace.TCPConns = append(httpTrace.TCPConns, TCPConnTrace{
				TraceID:          IDGenerator(),
				FromDial:         sock.fromDial,
				FromResolver:     !sock.fromResolvDial.Undefined(),
				HandshakeBeginAt: sock.createdAt,
				HandshakeEndAt:   sock.origClosedAt,
				Connected:        false,
				AddrTuple:        sock.addrTuple.toExportedAddrTuple(),
				Reused:           false,
				Conntract:        conntrack,
			})
		case syscall.IPPROTO_UDP:
			httpTrace.UDPConns = append(httpTrace.UDPConns, UDPConnTrace{
				TraceID:        IDGenerator(),
				FromDial:       sock.fromDial,
				FromResolver:   !sock.fromResolvDial.Undefined(),
				SocketCreateAt: sock.createdAt,
				AddrTuple:      sock.addrTuple.toExportedAddrTuple(),
				Conntract:      conntrack,
			})
		}
	}
	for _, conn := range c.connections {
		conntrack := conntrackToExportedEntry(conn.conntrack.flow, conn.conntrack.capturedAt)
		var socketTrace *SocketTrace
		if c.withSockTrace {
			socketTrace = &SocketTrace{SocketOps: conn.socketOps}
		}
		switch conn.proto {
		case syscall.IPPROTO_TCP:
			httpTrace.TCPConns = append(httpTrace.TCPConns, TCPConnTrace{
				TraceID:          conn.id,
				FromDial:         conn.dialID,
				FromResolver:     conn.fromResolver,
				HandshakeBeginAt: conn.sockCreatedAt,
				HandshakeEndAt:   conn.connectedAt,
				Connected:        true,
				ConnCloseAt:      conn.closedAt,
				AddrTuple:        conn.addrTuple.toExportedAddrTuple(),
				Reused:           conn.reused,
				TotalSentBytes:   conn.totalSentBytes,
				TotalRecvBytes:   conn.totalRecvBytes,
				Conntract:        conntrack,
				SocketTrace:      socketTrace,
			})
		case syscall.IPPROTO_UDP:
			httpTrace.UDPConns = append(httpTrace.UDPConns, UDPConnTrace{
				TraceID:        conn.id,
				FromDial:       conn.dialID,
				FromResolver:   conn.fromResolver,
				SocketCreateAt: conn.sockCreatedAt,
				ConnCloseAt:    conn.closedAt,
				AddrTuple:      conn.addrTuple.toExportedAddrTuple(),
				TotalSentBytes: conn.totalSentBytes,
				TotalRecvBytes: conn.totalRecvBytes,
				Conntract:      conntrack,
				SocketTrace:    socketTrace,
			})
		}
	}
	for _, dnsQuery := range c.dnsQueries {
		if dnsQuery.FromDial.Undefined() {
			if connTrace, ok := c.connections[dnsQuery.Connection]; ok {
				dnsQuery.FromDial = connTrace.dialID
			}
		}
		httpTrace.DNSQueries = append(httpTrace.DNSQueries, *dnsQuery)
	}
	for _, httpReq := range c.httpReqs {
		if httpReq.TCPConn.Undefined() {
			// Certainly not reused connection.
			// Try to find the corresponding Dial.
			for _, dial := range c.dials {
				if !dial.httpReqID.Undefined() && dial.httpReqID == httpReq.TraceID {
					httpReq.TCPConn = dial.EstablishedConn
				}
			}
		}
		httpTrace.HTTPRequests = append(httpTrace.HTTPRequests, *httpReq)
	}
	for _, tlsTun := range c.tlsTuns {
		if tlsTun.TCPConn.Undefined() {
			if httpReq, ok := c.httpReqs[tlsTun.httpReqID]; ok {
				tlsTun.TCPConn = httpReq.TCPConn
			}
		}
		httpTrace.TLSTunnels = append(httpTrace.TLSTunnels, tlsTun.TLSTunnelTrace)
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
			if c.packetCapturer != nil {
				if c.packetCapturer.readyToFilterPcap() {
					c.packetCapturer.filterPcap()
				}
			}
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
	flow, err := c.nfConn.Get(conntrack.Flow{
		TupleOrig: conntrack.Tuple{
			IP: conntrack.IPTuple{
				SourceAddress:      addr.srcIP,
				DestinationAddress: addr.dstIP,
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
	// How frequently to update conntrack entry for established connection.
	const conntrackUpdatePeriod = 20 * time.Second
	for _, conn := range c.connections {
		if conn.closed {
			// No longer actively traced.
			continue
		}
		if c.nfConn != nil {
			if gettingTrace || conn.conntrack.queriedAt.Undefined() ||
				now.Sub(conn.conntrack.queriedAt) >= conntrackUpdatePeriod {
				c.getConntrack(conn.addrTuple, &conn.conntrack, now)
			}
		}
	}
}

// processPendingTraces : processes all currently pending network traces.
// The function should be called with HTTPClient locked.
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
		case dialTrace:
			dial := c.getOrAddDialTrace(t.TraceID)
			if t.ctxClosed {
				dial.CtxCloseAt = t.CtxCloseAt
				continue
			} else if t.justBegan {
				dial.httpReqID = t.httpReqID
				dial.DialBeginAt = t.DialBeginAt
				dial.SourceIP = t.SourceIP
				dial.DstAddress = t.DstAddress
				continue
			} else {
				dial.httpReqID = t.httpReqID
				dial.DialErr = t.DialErr
				dial.DialBeginAt = t.DialBeginAt
				dial.DialEndAt = t.DialEndAt
				dial.EstablishedConn = t.EstablishedConn
				dial.SourceIP = t.SourceIP
				dial.DstAddress = t.DstAddress
			}
			// Stop monitoring sockets created by this Dial.
			connAddrTuple := addrTupleFromConn(t.conn) // undefined if dial failed
			connSockIdx := -1
			for idx, sock := range c.noConnSockets {
				if sock.fromDial == dial.TraceID {
					c.finalizeNoConnSocket(sock, t.conn != nil, now)
					if !connAddrTuple.undefined() && sock.addrTuple.equal(connAddrTuple) {
						connSockIdx = idx
					}
				}
			}
			if t.conn != nil {
				// Add entry for newly created connection.
				connection := &connection{
					id:          t.EstablishedConn,
					addrTuple:   connAddrTuple,
					connectedAt: t.DialEndAt,
					dialID:      dial.TraceID,
				}
				if connSockIdx != -1 {
					connection.sockCreatedAt = c.noConnSockets[connSockIdx].createdAt
					connection.conntrack = c.noConnSockets[connSockIdx].conntrack
				}
				if c.nfConn != nil {
					c.getConntrack(connAddrTuple, &connection.conntrack, now)
				}
				c.connections[t.EstablishedConn] = connection
			}
			if connSockIdx != -1 {
				// Socket is connected - remove it from the noConnSockets slice.
				c.delNoConnSocket(connSockIdx)
			}

		case resolverDialTrace:
			dial := c.getOrAddDialTrace(t.parentDial)
			dial.ResolverDials = append(dial.ResolverDials, ResolverDialTrace{
				DialBeginAt:     t.dialBeginAt,
				DialEndAt:       t.dialEndAt,
				DialErr:         errToString(t.dialErr),
				Nameserver:      t.nameserver,
				EstablishedConn: t.connID,
			})
			// Stop monitoring sockets opened by this call to resolver's Dial.
			connAddrTuple := addrTupleFromConn(t.conn) // undefined if dial failed
			connSockIdx := -1
			for idx, sock := range c.noConnSockets {
				if sock.fromDial == t.parentDial && sock.fromResolvDial == t.resolvDial {
					c.finalizeNoConnSocket(sock, t.conn != nil, now)
					if !connAddrTuple.undefined() && sock.addrTuple.equal(connAddrTuple) {
						connSockIdx = idx
					}
				}
			}
			if t.conn != nil {
				// Add entry for newly created connection.
				connection := &connection{
					id:           t.connID,
					addrTuple:    connAddrTuple,
					connectedAt:  t.dialEndAt,
					dialID:       t.parentDial,
					fromResolver: true,
				}
				if connSockIdx != -1 {
					connection.sockCreatedAt = c.noConnSockets[connSockIdx].createdAt
					connection.conntrack = c.noConnSockets[connSockIdx].conntrack
				}
				if c.nfConn != nil {
					c.getConntrack(connAddrTuple, &connection.conntrack, now)
				}
				c.connections[t.connID] = connection
			}
			if connSockIdx != -1 {
				// Socket is connected - remove it from the noConnSockets slice.
				c.delNoConnSocket(connSockIdx)
			}

		case resolverCloseTrace:
			dial := c.getOrAddDialTrace(t.parentDial)
			dial.SkippedNameservers = t.skippedServers

		case socketOpTrace:
			if connection := c.connections[t.connID]; connection != nil {
				if t.closed {
					connection.closed = true
					connection.closedAt = t.ReturnAt
					if c.nfConn != nil {
						c.getConntrack(connection.addrTuple, &connection.conntrack, now)
					}
				} else {
					switch t.SocketOp.Type {
					case SocketOpTypeRead, SocketOpTypeReadFrom:
						connection.totalRecvBytes += uint64(t.SocketOp.DataLen)
					case SocketOpTypeWrite, SocketOpTypeWriteTo:
						connection.totalSentBytes += uint64(t.SocketOp.DataLen)
					}
					if c.withSockTrace {
						connection.socketOps = append(connection.socketOps, t.SocketOp)
					}
				}
			}

		case tlsTrace:
			tlsTunTrace := c.getOrAddTLSTunTrace(t.TraceID)
			tlsTunTrace.TLSTunnelTrace = t.TLSTunnelTrace
			tlsTunTrace.httpReqID = t.httpReqID
			httpReqTrace := c.getOrAddHTTPReqTrace(t.httpReqID)
			if t.forProxy {
				httpReqTrace.ProxyTLSTunnel = t.TraceID
			} else {
				httpReqTrace.TLSTunnel = t.TraceID
			}

		case dnsQueryTrace:
			dnsTrace := c.getOrAddDNSTrace(t.connID)
			dnsTrace.DNSQueryMsgs = append(dnsTrace.DNSQueryMsgs, t.DNSQueryMsg)

		case dnsReplyTrace:
			dnsTrace := c.getOrAddDNSTrace(t.connID)
			dnsTrace.DNSReplyMsgs = append(dnsTrace.DNSReplyMsgs, t.DNSReplyMsg)

		case httpBodyTrace:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.httpReqID)
			if t.isRequest {
				httpReqTrace.ReqContentLen = t.readBodyLen
			} else {
				httpReqTrace.RespContentLen = t.readBodyLen
			}

		case httpConnTrace:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.httpReqID)
			if connTrace := c.lookupConnTrace(t.conn); connTrace != nil {
				httpReqTrace.TCPConn = connTrace.id
			}

		case httpReqTrace:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.httpReqID)
			// Prefer proto versions from the response if already provided.
			if httpReqTrace.RespRecvAt.Undefined() {
				httpReqTrace.ProtoMajor = t.protoMajor
				httpReqTrace.ProtoMinor = t.protoMinor
			}
			httpReqTrace.ReqSentAt = t.sentAt
			httpReqTrace.ReqMethod = t.reqMethod
			httpReqTrace.ReqURL = t.reqURL
			httpReqTrace.ReqHeader = t.header
			httpReqTrace.NetworkProxy = t.netProxy

		case httpRespTrace:
			httpReqTrace := c.getOrAddHTTPReqTrace(t.httpReqID)
			if t.rtErr != nil {
				httpReqTrace.ReqError = errToString(t.rtErr)
				continue
			}
			httpReqTrace.ProtoMajor = t.protoMajor
			httpReqTrace.ProtoMinor = t.protoMinor
			httpReqTrace.ReqError = ""
			httpReqTrace.RespRecvAt = t.recvAt
			httpReqTrace.RespStatusCode = t.statusCode
			httpReqTrace.RespHeader = t.header

		default:
			c.log.Warningf("nettrace: networkTracer id=%s: unrecognized trace (%T): %v\n",
				c.id, t, t)
		}
	}
}

func (c *HTTPClient) getOrAddDialTrace(id TraceID) *dial {
	if _, haveEntry := c.dials[id]; !haveEntry {
		c.dials[id] = &dial{DialTrace: DialTrace{TraceID: id}}
	}
	return c.dials[id]
}

func (c *HTTPClient) getOrAddDNSTrace(connID TraceID) *DNSQueryTrace {
	for _, dnsQuery := range c.dnsQueries {
		if dnsQuery.Connection == connID {
			return dnsQuery
		}
	}
	trace := &DNSQueryTrace{
		TraceID:    IDGenerator(),
		Connection: connID,
	}
	c.dnsQueries[trace.TraceID] = trace
	return trace
}

func (c *HTTPClient) getOrAddTLSTunTrace(id TraceID) *tlsTun {
	if _, haveEntry := c.tlsTuns[id]; !haveEntry {
		c.tlsTuns[id] = &tlsTun{TLSTunnelTrace: TLSTunnelTrace{TraceID: id}}
	}
	return c.tlsTuns[id]
}

func (c *HTTPClient) getOrAddHTTPReqTrace(id TraceID) *HTTPReqTrace {
	if _, haveEntry := c.httpReqs[id]; !haveEntry {
		c.httpReqs[id] = &HTTPReqTrace{TraceID: id}
	}
	return c.httpReqs[id]
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
	for _, connTrace := range c.connections {
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
	for _, conn := range c.connections {
		stop := iterCb(conn.addrTuple, conn.conntrack.flow)
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
