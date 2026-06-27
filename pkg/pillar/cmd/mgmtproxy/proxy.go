// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package mgmtproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"golang.org/x/sys/unix"
)

// newProxyHandler returns the http.Handler installed on the loopback listener.
// CONNECT requests are tunneled cost-aware. GET /healthz returns a JSON
// snapshot of proxy state for live debugging. Anything else is rejected.
//
// Plain-HTTP forwarding is intentionally not implemented: the relevant egress
// paths (containerd image pulls, `curl https://get.k3s.io`) all use HTTPS, and
// CONNECT-only keeps the implementation small and side-effect-free (no header
// rewriting, no auth header handling, no risk of leaking credentials in logs).
func newProxyHandler(ctx *mgmtProxyContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Path == "/healthz" {
			handleHealthz(ctx, w)
			return
		}
		if req.Method != http.MethodConnect {
			http.Error(w, "mgmtproxy: only CONNECT and GET /healthz are supported", http.StatusMethodNotAllowed)
			return
		}
		handleConnect(ctx, w, req)
	})
}

// handleHealthz returns 200 + JSON describing proxy state. Operators can curl
// http://127.0.0.1:5443/healthz to see whether the proxy is up, what the
// effective max-cost is, which mgmt ports are visible (with their costs and
// LastError flags from NIM), traffic counters, and the last success/error.
func handleHealthz(ctx *mgmtProxyContext, w http.ResponseWriter) {
	dns, maxCost, ready := ctx.snapshot()
	_ = dns

	// cni0Listening: probe whether the cni0 link-local listener is up by
	// attempting a non-binding dial. Avoids tracking state across goroutines.
	cni0Listening := false
	if c, err := net.DialTimeout("tcp", CNI0ListenAddr, 200*time.Millisecond); err == nil {
		c.Close()
		cni0Listening = true
	}

	r := types.MgmtProxyHealthz{
		Listening:        ListenAddr,
		CNI0Listening:    cni0Listening,
		Ready:            ready,
		MaxPortCost:      maxCost,
		Ports:            ctx.portSummaries(),
		Requests:         ctx.stats.requests.Load(),
		DialFailures:     ctx.stats.dialFailures.Load(),
		NotReady:         ctx.stats.notReady.Load(),
		TunnelIdleClosed: ctx.stats.tunnelIdleClosed.Load(),
		BytesUp:          ctx.stats.bytesUp.Load(),
		BytesDown:        ctx.stats.bytesDown.Load(),
		SuccessByPort:    mapToCounts(&ctx.stats.successByPort),
		FailureByPort:    mapToCounts(&ctx.stats.failureByPort),
	}
	if t := ctx.stats.lastSuccessTime.Load(); t != 0 {
		r.LastSuccessTime = time.Unix(0, t).UTC().Format(time.RFC3339)
		ctx.stats.lastSuccessMu.RLock()
		r.LastSuccessTarget = ctx.stats.lastSuccessTarget
		r.LastSuccessPort = ctx.stats.lastSuccessPort
		r.LastSuccessCost = ctx.stats.lastSuccessCost
		ctx.stats.lastSuccessMu.RUnlock()
	}
	if t := ctx.stats.lastErrorTime.Load(); t != 0 {
		r.LastErrorTime = time.Unix(0, t).UTC().Format(time.RFC3339)
		ctx.stats.lastErrorMu.RLock()
		r.LastError = ctx.stats.lastError
		ctx.stats.lastErrorMu.RUnlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&r)
}

func handleConnect(ctx *mgmtProxyContext, w http.ResponseWriter, req *http.Request) {
	ctx.stats.requests.Add(1)
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		http.Error(w, "mgmtproxy: bad CONNECT target", http.StatusBadRequest)
		return
	}

	// clientAddr is the source of the incoming CONNECT connection.
	// 127.0.0.1:PORT  → host process (containerd, kubectl)
	// 10.42.x.x:PORT  → CDI importer pod (via cni0 link-local listener)
	clientAddr := req.RemoteAddr

	start := time.Now()
	res, err := ctx.dialUpstreamCtx(req.Context(), target)
	if err != nil {
		// Always logged at Warn so operators see CONNECT failures without
		// raising the global log level. Includes per-port attempts so the
		// log line tells you exactly which interfaces failed and why.
		log.Warnf("mgmtproxy: CONNECT %s from %s FAILED after %v: %v",
			target, clientAddr, time.Since(start).Round(time.Millisecond), err)
		var de *dialError
		if errors.As(err, &de) {
			ctx.stats.recordFailure(target, de.Attempts(), err.Error())
			// Record one RecordFailure per attempted interface so the
			// per-port FailureCount in `edgeview url` reflects which
			// uplinks the dialer actually tried.
			for _, a := range de.Attempts() {
				ctx.agentMetrics.RecordFailure(log, a.IfName, target, 0, 0, false)
			}
		} else {
			ctx.stats.recordFailure(target, nil, err.Error())
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	dialDur := time.Since(start).Round(time.Millisecond)
	ctx.stats.recordSuccess(target, res.IfName, res.Cost)
	// Record dial-time failures for any ports we tried before the winner.
	// These are real attempts NIM should know failed for this target.
	for _, a := range res.Attempts {
		ctx.agentMetrics.RecordFailure(log, a.IfName, target, 0, 0, false)
	}
	// Notice level: every CONNECT outcome is visible at the default log
	// level. clientAddr identifies the caller: 127.0.0.1 = host process
	// (containerd/kubectl), 10.42.x.x = CDI importer pod via cni0 listener.
	log.Noticef("mgmtproxy: CONNECT %s from %s via %s src %v cost %d (dial %v, %d fallback(s))",
		target, clientAddr, res.IfName, res.SrcIP, res.Cost, dialDur, len(res.Attempts))

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = res.Conn.Close()
		http.Error(w, "mgmtproxy: server does not support hijacking", http.StatusInternalServerError)
		return
	}

	// Hijack BEFORE writing the response. Calling w.WriteHeader first lets
	// the http.ResponseWriter buffer/flush extra headers (Date, Connection,
	// Content-Type) onto the wire — fine for forgiving clients but not for
	// the strict TLS clients common in container-registry stacks. Take over
	// the conn first, then write a clean "HTTP/1.1 200 OK\r\n\r\n" by hand.
	client, clientBuf, err := hijacker.Hijack()
	if err != nil {
		_ = res.Conn.Close()
		log.Errorf("mgmtproxy: hijack: %v", err)
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = res.Conn.Close()
		log.Tracef("mgmtproxy: write CONNECT response: %v", err)
		return
	}

	// Some clients pipeline the first TLS bytes immediately after the
	// CONNECT request; flush any buffered bytes upstream before tunneling.
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		if _, err := io.CopyN(res.Conn, clientBuf, int64(clientBuf.Reader.Buffered())); err != nil {
			_ = client.Close()
			_ = res.Conn.Close()
			log.Tracef("mgmtproxy: drain client buffer to upstream: %v", err)
			return
		}
	}

	tunnel(ctx, target, res.IfName, client, res.Conn, start)
}

// tunnel performs a bidirectional copy with an idle timeout and accounts
// bytes per direction. On close it logs a single Functionf line with the
// totals — visible if operators bump the level to debug a specific pull.
//
// The copy is io.Copy in each direction: between two *net.TCPConn it takes the
// kernel splice() zero-copy path, so payload never round-trips through a
// userspace buffer. splice keeps draining the receive socket promptly, which
// is what keeps TCP receive-window autotuning growing the window toward the
// kernel ceiling (tcp_rmem[2], ~6 MiB by default) — the lever for image-pull
// throughput on high-RTT internet paths (see README.md).
func tunnel(ctx *mgmtProxyContext, target, ifName string, a, b net.Conn, dialStart time.Time) {
	idleCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idleClosed := atomic.Bool{}
	go idleWatchdog(idleCtx, &idleClosed, idleTimeout, a, b)

	var wg sync.WaitGroup
	var bytesA2B, bytesB2A int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		bytesA2B = copyTunnel(b, a)
		_ = a.Close()
	}()
	go func() {
		defer wg.Done()
		bytesB2A = copyTunnel(a, b)
		_ = b.Close()
	}()
	wg.Wait()
	ctx.stats.bytesUp.Add(uint64(bytesA2B))
	ctx.stats.bytesDown.Add(uint64(bytesB2A))
	if idleClosed.Load() {
		ctx.stats.tunnelIdleClosed.Add(1)
	}
	durationMs := time.Since(dialStart).Milliseconds()
	// Record one RecordSuccess per CONNECT at tunnel close so the per-target
	// byte counts and total time in `edgeview url` reflect actual transfer,
	// not just the dial. SessionResume is always false (we don't terminate
	// TLS so we can't observe it). For the half-broken-firewall case (idle
	// kill with bytes=0) we still record success — the dial succeeded; the
	// /healthz tunnelIdleClosed counter and the bytes=0 in edgeview tell
	// the rest of the story without double-counting.
	ctx.agentMetrics.RecordSuccess(log, ifName, target,
		bytesA2B, bytesB2A, durationMs, false)
	log.Functionf("mgmtproxy: tunnel %s via %s closed: up=%d down=%d duration=%v idle=%v",
		target, ifName, bytesA2B, bytesB2A,
		time.Duration(durationMs)*time.Millisecond, idleClosed.Load())
}

// copyTunnel copies src→dst for one direction of the tunnel and returns the
// number of bytes copied. Between two *net.TCPConn io.Copy takes the kernel
// splice() zero-copy path. EOF and the errors that fire when the peer half is
// closed during teardown (net.ErrClosed) are the normal way a tunnel ends; any
// other error is logged at Trace as a debugging signal (matching the prior
// manual copy loop) without failing the relay.
func copyTunnel(dst io.Writer, src io.Reader) int64 {
	n, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		log.Tracef("mgmtproxy: tunnel copy: %v", err)
	}
	return n
}

// idleWatchdog closes the tunnel connections if no payload bytes are received
// on either socket for timeout. The splice() path in tunnel never surfaces
// per-chunk progress to userspace, so instead of a per-write activity signal we
// poll each socket's TCP_INFO.tcpi_bytes_received and close once the combined
// count has not advanced for a full timeout. The poll runs every timeout/4, so
// the actual close fires between timeout and timeout+timeout/4 after the last
// observed progress.
//
// If neither connection exposes TCP_INFO (e.g. a non-TCP conn in tests), idle
// enforcement is skipped rather than risking a false close of an active tunnel.
func idleWatchdog(ctx context.Context, idleClosed *atomic.Bool,
	timeout time.Duration, conns ...net.Conn) {

	interval := timeout / 4
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastBytes uint64
	lastChange := time.Now()
	seenBytes := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var total uint64
			readable := 0
			for _, c := range conns {
				if n, ok := tcpBytesReceived(c); ok {
					total += n
					readable++
				}
			}
			if readable == 0 {
				// Can't observe progress on these conns; don't risk
				// closing a tunnel that may well be active.
				lastChange = time.Now()
				continue
			}
			if !seenBytes || total != lastBytes {
				seenBytes = true
				lastBytes = total
				lastChange = time.Now()
				continue
			}
			if time.Since(lastChange) >= timeout {
				log.Warnf("mgmtproxy: tunnel idle for %v, closing", timeout)
				idleClosed.Store(true)
				for _, c := range conns {
					_ = c.Close()
				}
				return
			}
		}
	}
}

// tcpBytesReceived returns the cumulative payload bytes the kernel has received
// on conn's socket (TCP_INFO.tcpi_bytes_received). ok is false if conn is not a
// TCP socket or the counter can't be read — callers treat that as "unknown",
// never as "idle".
func tcpBytesReceived(conn net.Conn) (uint64, bool) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var bytes uint64
	var got bool
	if cerr := raw.Control(func(fd uintptr) {
		info, gerr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if gerr == nil {
			bytes = info.Bytes_received
			got = true
		}
	}); cerr != nil {
		return 0, false
	}
	return bytes, got
}
