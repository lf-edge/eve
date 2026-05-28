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
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
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
func tunnel(ctx *mgmtProxyContext, target, ifName string, a, b net.Conn, dialStart time.Time) {
	idleCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	activity := make(chan struct{}, 4)
	idleClosed := atomic.Bool{}
	go idleWatchdog(idleCtx, &idleClosed, activity, a, b)

	var wg sync.WaitGroup
	var bytesA2B, bytesB2A uint64
	wg.Add(2)
	go func() {
		defer wg.Done()
		bytesA2B = copyAndSignal(b, a, activity)
		_ = a.Close()
	}()
	go func() {
		defer wg.Done()
		bytesB2A = copyAndSignal(a, b, activity)
		_ = b.Close()
	}()
	wg.Wait()
	ctx.stats.bytesUp.Add(bytesA2B)
	ctx.stats.bytesDown.Add(bytesB2A)
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
		int64(bytesA2B), int64(bytesB2A), durationMs, false)
	log.Functionf("mgmtproxy: tunnel %s via %s closed: up=%d down=%d duration=%v idle=%v",
		target, ifName, bytesA2B, bytesB2A,
		time.Duration(durationMs)*time.Millisecond, idleClosed.Load())
}

// copyAndSignal copies src→dst and pokes the activity channel periodically so
// the idle watchdog can tell the tunnel from a stalled one. Returns total
// bytes copied (best-effort — partial writes on error still counted).
func copyAndSignal(dst io.Writer, src io.Reader, activity chan<- struct{}) uint64 {
	buf := make([]byte, 32*1024)
	var total uint64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += uint64(w)
			if werr != nil {
				return total
			}
			select {
			case activity <- struct{}{}:
			default:
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Tracef("mgmtproxy: tunnel read: %v", err)
			}
			return total
		}
	}
}

func idleWatchdog(ctx context.Context, idleClosed *atomic.Bool,
	activity <-chan struct{}, conns ...net.Conn) {

	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idleTimeout)
		case <-timer.C:
			log.Warnf("mgmtproxy: tunnel idle for %v, closing", idleTimeout)
			idleClosed.Store(true)
			for _, c := range conns {
				_ = c.Close()
			}
			return
		}
	}
}
