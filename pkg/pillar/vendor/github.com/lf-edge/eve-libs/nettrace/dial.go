// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// tracedDialer publishes traces from TCP/UDP dialing.
// Should be used only for one dial call (i.e. create new instance for every call).
type tracedDialer struct {
	dialID            TraceID
	log               Logger
	tracer            tracerWithDial
	tfd               *tracedFD
	sourceIP          net.IP
	handshakeTimeout  time.Duration
	keepAliveInterval time.Duration
	withDNSTrace      bool
	skipNameserver    NameserverSelector
}

// tracedResolver publishes traces from nameserver dialing.
type tracedResolver struct {
	caller         *tracedDialer
	skippedServers []string
	triedServers   []string
	sync.Mutex
}

// tracedFD records trace for every AF_INET socket created during dialing.
type tracedFD struct {
	tracer       tracerWithDial
	dialID       TraceID
	resolvDialID TraceID // undefined if FD is not created by resolver
}

// tracerWithDial : interface that a tracer must implement to be compatible
// with tracedDialer.
type tracerWithDial interface {
	networkTracer
	traceNewSocket(sock *inetSocket)
}

// DialTraceEnv is published after each Dial (except those targeted at nameservers,
// for those resolverDialTrace is published instead).
// Does not contain DialTrace.ResolverDials - those are published as resolverDialTrace.
type DialTraceEnv struct {
	DialTrace
	Conn      net.Conn
	JustBegan bool
	CTXClosed bool
	HTTPReqID TraceID
}

func (DialTraceEnv) isInternalNetTrace() {}

// ResolverDialTr trace published after every attempt to dial a nameserver.
type ResolverDialTr struct {
	ResolvDial  TraceID
	ParentDial  TraceID
	Nameserver  string
	DialBeginAt Timestamp
	DialEndAt   Timestamp
	DialErr     error
	Conn        net.Conn
	ConnID      TraceID
}

func (ResolverDialTr) isInternalNetTrace() {}

// ResolverCloseTraceEnv trace sent by the resolver at the end of its use.
type ResolverCloseTraceEnv struct {
	ParentDial     TraceID
	SkippedServers []string
	TriedServers   []string
}

func (ResolverCloseTraceEnv) isInternalNetTrace() {}

func newTracedDialer(tracer tracerWithDial, log Logger, sourceIP net.IP,
	handshakeTimeout, keepAliveInterval time.Duration, withDNSTrace bool,
	skipNameserver NameserverSelector) *tracedDialer {
	dialID := IDGenerator()
	return &tracedDialer{
		dialID: dialID,
		log:    log,
		tracer: tracer,
		tfd: &tracedFD{
			tracer: tracer,
			dialID: dialID,
		},
		sourceIP:          sourceIP,
		handshakeTimeout:  handshakeTimeout,
		keepAliveInterval: keepAliveInterval,
		withDNSTrace:      withDNSTrace,
		skipNameserver:    skipNameserver,
	}
}

// dial implement DialContext method of the net.Dialer interface.
func (td *tracedDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	// Note that if the overall timeout to the http.Client is reached, this dial() method
	// may simply be abandoned. You cannot expect any goroutine or defer to be reached.
	// This matters in that this routine expects to set the following parameters:
	// - dialTrace.DialTrace.CtxCloseAt
	// - dialTrace.DialEndAt
	// - dialTrace.ctxClosed
	//
	// Anything that expects those to be set, should *not* expect them to be set
	// if http.Client times out.
	// Prepare the original Dialer from the net package.
	var sourceAddr net.Addr
	if td.sourceIP != nil {
		if strings.HasPrefix(network, "tcp") {
			sourceAddr = &net.TCPAddr{IP: td.sourceIP}
		} else {
			sourceAddr = &net.UDPAddr{IP: td.sourceIP}
		}
	}
	resolver := &tracedResolver{caller: td}
	netDialer := net.Dialer{Resolver: resolver.netResolver(), Control: td.tfd.controlFD,
		LocalAddr: sourceAddr, Timeout: td.handshakeTimeout, KeepAlive: td.keepAliveInterval}

	if ctx == nil || ctx.Done() == nil {
		td.log.Errorf("nettrace dial: nil or non-cancelable context passed. Dumping the stack to trace the context\n%s",
			debug.Stack())
	} else {
		// Monitor context for closure.
		go func(ctx context.Context) {
			<-ctx.Done()
			td.tracer.publishTrace(DialTraceEnv{
				DialTrace: DialTrace{
					TraceID:    td.dialID,
					CtxCloseAt: td.tracer.getRelTimestamp(),
				},
				CTXClosed: true,
			})
		}(ctx)
	}

	// Run DialContext method of the original Dialer.
	dial := DialTraceEnv{
		DialTrace: DialTrace{
			TraceID:     td.dialID,
			DialBeginAt: td.tracer.getRelTimestamp(),
			DstAddress:  address,
		},
		JustBegan: true,
		HTTPReqID: getHTTPReqID(ctx),
	}
	if td.sourceIP != nil {
		dial.SourceIP = td.sourceIP.String()
	}
	td.tracer.publishTrace(dial)
	// if the http.Client.Timeout is reached, this will *not* return an error.
	// It simply will be abandoned. Listening for a ctx.Done() or setting a defer()
	// will not help either.
	conn, err := netDialer.DialContext(ctx, network, address)
	resolver.close()
	dial.JustBegan = false
	dial.DialEndAt = td.tracer.getRelTimestamp()
	if err != nil {
		dial.DialErr = err.Error()
		td.tracer.publishTrace(dial)
		return conn, err
	}
	dial.Conn = conn
	dial.EstablishedConn = IDGenerator()
	td.tracer.publishTrace(dial)

	// Trace established connection.
	tracedConn := newTracedConn(
		td.tracer, dial.EstablishedConn, conn, td.log, false, td.withDNSTrace)
	if packetConn, isPacketConn := conn.(net.PacketConn); isPacketConn {
		return &tracedPacketConn{
			tracedConn: tracedConn,
			packetConn: packetConn,
		}, nil
	}
	return tracedConn, err

}

func (tr *tracedResolver) netResolver() *net.Resolver {
	return &net.Resolver{Dial: tr.dial, PreferGo: true, StrictErrors: false}
}

func (tr *tracedResolver) dial(ctx context.Context, network, address string) (net.Conn, error) {
	ip, port, err := parseHostAddr(address)
	if err != nil {
		return nil, fmt.Errorf("nettrace: networkTracer id=%s: %w",
			tr.caller.tracer.getTracerID(), err)
	}
	// Check if this nameserver is allowed by the user config.
	if tr.caller.skipNameserver != nil {
		skip, reason := tr.caller.skipNameserver(ip, port)
		if skip {
			tr.ensureSkippedServersContains(address)
			return nil, fmt.Errorf("skipped nameserver %s: %s", address, reason)
		}
	}

	// Prepare the original Dialer from the net package.
	var sourceAddr net.Addr
	if tr.caller.sourceIP != nil && !ip.IsLoopback() {
		if strings.HasPrefix(network, "tcp") {
			sourceAddr = &net.TCPAddr{IP: tr.caller.sourceIP}
		} else {
			sourceAddr = &net.UDPAddr{IP: tr.caller.sourceIP}
		}
	}
	resolvDialID := IDGenerator()
	tfd := &tracedFD{
		tracer:       tr.caller.tracer,
		dialID:       tr.caller.dialID,
		resolvDialID: resolvDialID,
	}
	netDialer := net.Dialer{Control: tfd.controlFD, LocalAddr: sourceAddr}

	// Run DialContext method of the original Dialer.
	trace := ResolverDialTr{
		ResolvDial:  resolvDialID,
		ParentDial:  tr.caller.dialID,
		Nameserver:  address,
		DialBeginAt: tr.caller.tracer.getRelTimestamp(),
	}
	conn, err := netDialer.DialContext(ctx, network, address)
	trace.DialEndAt = tr.caller.tracer.getRelTimestamp()
	tr.ensureTriedServersContains(address)
	if err != nil {
		trace.DialErr = err
		tr.caller.tracer.publishTrace(trace)
		return conn, err
	}
	trace.Conn = conn
	trace.ConnID = IDGenerator()
	tr.caller.tracer.publishTrace(trace)

	// Trace established connection.
	tracedConn := newTracedConn(
		tr.caller.tracer, trace.ConnID, conn, tr.caller.log, true, tr.caller.withDNSTrace)
	if packetConn, isPacketConn := conn.(net.PacketConn); isPacketConn {
		return &tracedPacketConn{
			tracedConn: tracedConn,
			packetConn: packetConn,
		}, nil
	}
	return tracedConn, err
}

// Run by tracedDialer when resolution is completed.
func (tr *tracedResolver) close() {
	tr.caller.tracer.publishTrace(ResolverCloseTraceEnv{
		ParentDial:     tr.caller.dialID,
		SkippedServers: tr.skippedServers,
		TriedServers:   tr.triedServers,
	})
}

// ensureTriedServersContains ensure the list of tried servers contains the given server,
// by adding it only if it does not already exist
func (tr *tracedResolver) ensureTriedServersContains(server string) {
	tr.Lock()
	defer tr.Unlock()
	if !stringListContains(tr.triedServers, server) {
		tr.triedServers = append(tr.triedServers, server)
	}
}

// ensureSkippedServersContains ensure the list of skipped servers contains the given server,
// by adding it only if it does not already exist
func (tr *tracedResolver) ensureSkippedServersContains(server string) {
	tr.Lock()
	defer tr.Unlock()
	if !stringListContains(tr.skippedServers, server) {
		tr.skippedServers = append(tr.skippedServers, server)
	}
}

// controlFD is called for every newly created AF_INET socket.
// The function duplicates the socket so that the source address can be read even
// after the original was closed.
// The function adds the socket into HTTPClient.noConnSockets synchronously,
// i.e. not using a queue but instead locking HTTPClient and adding the new entry
// directly. This is to ensure that HTTPClient will not accidentally filter out first
// packets produced by this socket.
func (tfd *tracedFD) controlFD(network, address string, conn syscall.RawConn) error {
	ip, port, err := parseHostAddr(address)
	if err != nil {
		return fmt.Errorf("nettrace: networkTracer id=%s: %w",
			tfd.tracer.getTracerID(), err)
	}
	var proto uint8
	if strings.HasPrefix(network, "tcp") {
		proto = syscall.IPPROTO_TCP
	} else if strings.HasPrefix(network, "udp") {
		proto = syscall.IPPROTO_UDP
	}
	var (
		origFd int
		dupFd  int
		dupErr error
	)
	duplicateFd := func(fd uintptr) {
		origFd = int(fd)
		dupFd, dupErr = syscall.Dup(origFd)
	}
	err = conn.Control(duplicateFd)
	if err != nil {
		return err
	}
	if dupErr != nil {
		return fmt.Errorf("nettrace: networkTracer id=%s: failed to duplicate fd %d: %w",
			tfd.tracer.getTracerID(), origFd, dupErr)
	}
	tfd.tracer.traceNewSocket(&inetSocket{
		addrTuple: addrTuple{
			proto:   proto,
			dstIP:   ip,
			dstPort: port,
		},
		origFD:         origFd,
		dupFD:          dupFd,
		fromDial:       tfd.dialID,
		fromResolvDial: tfd.resolvDialID,
		createdAt:      tfd.tracer.getRelTimestamp(),
	})
	return nil
}

func parseHostAddr(address string) (ip net.IP, port uint16, err error) {
	ipStr, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to split host and port from %s: %w", address, err)
	}
	ip = net.ParseIP(ipStr)
	if ip == nil {
		return nil, 0, fmt.Errorf("failed to parse IP address %s", ipStr)
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse port %s: %w", portStr, err)
	}
	return ip, uint16(portInt), nil
}

func stringListContains(list []string, item string) bool {
	for _, listItem := range list {
		if listItem == item {
			return true
		}
	}
	return false
}
