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
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// TestMain initializes the package-level logger that the proxy code logs
// through, so handlers and the dialer don't panic on a nil *base.LogObject.
func TestMain(m *testing.M) {
	logger = logrus.StandardLogger()
	logger.SetLevel(logrus.FatalLevel) // keep test output quiet
	log = base.NewSourceLogObject(logger, "mgmtproxy-test", 0)
	m.Run()
}

// newTestContext returns a context wired with the metrics publisher the proxy
// handler and dialer expect, and with the given DeviceNetworkStatus already
// applied (initialized = true so dialUpstreamCtx does not short-circuit).
func newTestContext(dns types.DeviceNetworkStatus, maxCost uint8) *mgmtProxyContext {
	ctx := &mgmtProxyContext{
		agentMetrics:        controllerconn.NewAgentMetrics(),
		deviceNetworkStatus: dns,
		maxPortCost:         maxCost,
		gcInitialized:       true,
		dnsInitialized:      true,
	}
	ctx.dialTimeout.Store(int64(2 * time.Second))
	return ctx
}

// mkPort builds a mgmt, L3 NetworkPortStatus with the given cost and source
// addresses. Passing no addresses yields a port with an empty AddrInfoList.
func mkPort(ifname string, cost uint8, addrs ...net.IP) types.NetworkPortStatus {
	var ail []types.AddrInfo
	for _, a := range addrs {
		ail = append(ail, types.AddrInfo{Addr: a})
	}
	return types.NetworkPortStatus{
		IfName:       ifname,
		IsMgmt:       true,
		IsL3Port:     true,
		Cost:         cost,
		AddrInfoList: ail,
	}
}

func mkDNS(ports ...types.NetworkPortStatus) types.DeviceNetworkStatus {
	return types.DeviceNetworkStatus{
		Version: types.DPCIsMgmt,
		Ports:   ports,
	}
}

// --- dialError -------------------------------------------------------------

func TestDialErrorMessageNoAttempts(t *testing.T) {
	e := &dialError{msg: "boom"}
	if got := e.Error(); got != "boom" {
		t.Fatalf("Error() = %q, want %q", got, "boom")
	}
	if e.Attempts() != nil {
		t.Fatalf("Attempts() = %v, want nil", e.Attempts())
	}
}

func TestDialErrorMessageWithAttempts(t *testing.T) {
	e := &dialError{
		msg: "all attempts failed",
		attempts: []attemptResult{
			{IfName: "eth0", SrcIP: net.ParseIP("192.0.2.1"), Cost: 0, Err: errors.New("refused")},
			{IfName: "wwan0", SrcIP: net.ParseIP("192.0.2.2"), Cost: 10, Err: errors.New("timeout")},
		},
	}
	got := e.Error()
	for _, want := range []string{"all attempts failed", "eth0", "wwan0", "cost=0", "cost=10", "refused", "timeout"} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, missing %q", got, want)
		}
	}
	if len(e.Attempts()) != 2 {
		t.Fatalf("Attempts() len = %d, want 2", len(e.Attempts()))
	}
}

// --- proxyStats ------------------------------------------------------------

func TestProxyStatsRecordSuccess(t *testing.T) {
	var s proxyStats
	s.recordSuccess("registry:443", "eth0", 3)
	s.recordSuccess("registry:443", "eth0", 3)

	counts := mapToCounts(&s.successByPort)
	if counts["eth0"] != 2 {
		t.Errorf("successByPort[eth0] = %d, want 2", counts["eth0"])
	}
	if s.lastSuccessTime.Load() == 0 {
		t.Error("lastSuccessTime not set")
	}
	s.lastSuccessMu.RLock()
	defer s.lastSuccessMu.RUnlock()
	if s.lastSuccessTarget != "registry:443" || s.lastSuccessPort != "eth0" || s.lastSuccessCost != 3 {
		t.Errorf("last success = (%q,%q,%d), want (registry:443,eth0,3)",
			s.lastSuccessTarget, s.lastSuccessPort, s.lastSuccessCost)
	}
}

func TestProxyStatsRecordFailure(t *testing.T) {
	var s proxyStats
	attempts := []attemptResult{
		{IfName: "eth0"},
		{IfName: "wwan0"},
		{IfName: "eth0"},
	}
	s.recordFailure("registry:443", attempts, "all attempts failed")

	if s.dialFailures.Load() != 1 {
		t.Errorf("dialFailures = %d, want 1", s.dialFailures.Load())
	}
	counts := mapToCounts(&s.failureByPort)
	if counts["eth0"] != 2 || counts["wwan0"] != 1 {
		t.Errorf("failureByPort = %v, want eth0=2 wwan0=1", counts)
	}
	if s.lastErrorTime.Load() == 0 {
		t.Error("lastErrorTime not set")
	}
	s.lastErrorMu.RLock()
	defer s.lastErrorMu.RUnlock()
	if !strings.Contains(s.lastError, "registry:443") || !strings.Contains(s.lastError, "all attempts failed") {
		t.Errorf("lastError = %q, want target + summary", s.lastError)
	}
}

func TestMapToCountsEmpty(t *testing.T) {
	var s proxyStats
	if got := mapToCounts(&s.successByPort); len(got) != 0 {
		t.Errorf("mapToCounts(empty) = %v, want empty", got)
	}
}

// --- context: snapshot / dialUpstreamCtx -----------------------------------

func TestSnapshotReady(t *testing.T) {
	dns := mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10")))
	ctx := newTestContext(dns, 7)
	gotDNS, maxCost, ready := ctx.snapshot()
	if !ready {
		t.Error("ready = false, want true")
	}
	if maxCost != 7 {
		t.Errorf("maxCost = %d, want 7", maxCost)
	}
	if len(gotDNS.Ports) != 1 || gotDNS.Ports[0].IfName != "eth0" {
		t.Errorf("snapshot DNS = %+v, want one eth0 port", gotDNS.Ports)
	}
}

func TestDialUpstreamCtxNotReady(t *testing.T) {
	ctx := newTestContext(types.DeviceNetworkStatus{}, 0)
	ctx.gcInitialized = false
	ctx.dnsInitialized = false

	res, err := ctx.dialUpstreamCtx(context.Background(), "registry:443")
	if res != nil {
		t.Errorf("res = %v, want nil", res)
	}
	if err == nil {
		t.Fatal("err = nil, want not-initialized error")
	}
	if ctx.stats.notReady.Load() != 1 {
		t.Errorf("notReady = %d, want 1", ctx.stats.notReady.Load())
	}
}

// --- portSummaries ---------------------------------------------------------

func TestPortSummaries(t *testing.T) {
	mgmt := mkPort("eth0", 0, net.ParseIP("fe80::1"), net.ParseIP("192.0.2.10"))
	highCost := mkPort("wwan0", 10, net.ParseIP("192.0.2.20"))
	// A non-mgmt port must be excluded from the summary.
	appPort := mkPort("eth1", 0, net.ParseIP("192.0.2.30"))
	appPort.IsMgmt = false
	// A port flagged failed by NIM: HasError() true.
	failed := mkPort("wlan0", 5, net.ParseIP("192.0.2.40"))
	failed.LastFailed = time.Now()
	failed.LastError = "link down"

	ctx := newTestContext(mkDNS(mgmt, highCost, appPort, failed), 255)
	sums := ctx.portSummaries()

	byName := map[string]types.MgmtProxyPortSummary{}
	for _, s := range sums {
		byName[s.IfName] = s
	}
	if _, ok := byName["eth1"]; ok {
		t.Error("non-mgmt eth1 should not appear in summary")
	}
	if len(byName) != 3 {
		t.Fatalf("got %d mgmt summaries, want 3: %+v", len(byName), sums)
	}
	// Link-local address must be skipped; the routable v4 addr is reported.
	if byName["eth0"].UsableAddr != "192.0.2.10" {
		t.Errorf("eth0 UsableAddr = %q, want 192.0.2.10", byName["eth0"].UsableAddr)
	}
	if byName["eth0"].NumAddrs != 2 {
		t.Errorf("eth0 NumAddrs = %d, want 2", byName["eth0"].NumAddrs)
	}
	if !byName["wlan0"].HasError || byName["wlan0"].LastError != "link down" {
		t.Errorf("wlan0 error not surfaced: %+v", byName["wlan0"])
	}
	if byName["wwan0"].Cost != 10 {
		t.Errorf("wwan0 Cost = %d, want 10", byName["wwan0"].Cost)
	}
}

// --- newProxyHandler routing -----------------------------------------------

func TestProxyHandlerRejectsPlainGET(t *testing.T) {
	ctx := newTestContext(mkDNS(), 0)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://registry/v2/", nil)
	newProxyHandler(ctx).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET / status = %d, want 405", rec.Code)
	}
}

func TestProxyHandlerBadConnectTarget(t *testing.T) {
	ctx := newTestContext(mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10"))), 0)
	rec := httptest.NewRecorder()
	// No port in the authority → net.SplitHostPort fails → 400.
	req := httptest.NewRequest(http.MethodConnect, "//registry-no-port", nil)
	req.URL.Host = "registry-no-port"
	req.Host = "registry-no-port"
	newProxyHandler(ctx).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad CONNECT target status = %d, want 400", rec.Code)
	}
	if ctx.stats.requests.Load() != 1 {
		t.Errorf("requests = %d, want 1", ctx.stats.requests.Load())
	}
}

func TestProxyHandlerConnectNotReady(t *testing.T) {
	ctx := newTestContext(types.DeviceNetworkStatus{}, 0)
	ctx.gcInitialized = false
	ctx.dnsInitialized = false
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "//registry.example:443", nil)
	req.URL.Host = "registry.example:443"
	req.Host = "registry.example:443"
	newProxyHandler(ctx).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("not-ready CONNECT status = %d, want 502", rec.Code)
	}
}

func TestProxyHandlerHealthz(t *testing.T) {
	dns := mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10")))
	ctx := newTestContext(dns, 4)
	ctx.stats.requests.Store(5)
	ctx.stats.recordSuccess("registry:443", "eth0", 0)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5443/healthz", nil)
	newProxyHandler(ctx).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Listening       string `json:"listening"`
		Ready           bool   `json:"ready"`
		MaxPortCost     uint8  `json:"maxPortCost"`
		Requests        uint64 `json:"requests"`
		LastSuccessPort string `json:"lastSuccessPort"`
		Ports           []struct {
			IfName string `json:"ifname"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal /healthz body: %v (body=%s)", err, rec.Body.String())
	}
	if body.Listening != ListenAddr {
		t.Errorf("listening = %q, want %q", body.Listening, ListenAddr)
	}
	if !body.Ready {
		t.Error("ready = false, want true")
	}
	if body.MaxPortCost != 4 {
		t.Errorf("maxPortCost = %d, want 4", body.MaxPortCost)
	}
	if body.Requests != 5 {
		t.Errorf("requests = %d, want 5", body.Requests)
	}
	if body.LastSuccessPort != "eth0" {
		t.Errorf("lastSuccessPort = %q, want eth0", body.LastSuccessPort)
	}
	if len(body.Ports) != 1 || body.Ports[0].IfName != "eth0" {
		t.Errorf("ports = %+v, want one eth0", body.Ports)
	}
}

// --- dialCostAware (network-free paths) ------------------------------------

func TestDialCostAwareNoMgmtInterfaces(t *testing.T) {
	res, err := dialCostAware(context.Background(), log,
		types.DeviceNetworkStatus{}, 255, "registry:443", time.Second, 0)
	if res != nil {
		t.Errorf("res = %v, want nil", res)
	}
	var de *dialError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *dialError", err)
	}
	if !strings.Contains(de.Error(), "no management interfaces") {
		t.Errorf("err = %q, want 'no management interfaces'", de.Error())
	}
	if len(de.Attempts()) != 0 {
		t.Errorf("attempts = %v, want none", de.Attempts())
	}
}

func TestDialCostAwareAllAboveMaxCost(t *testing.T) {
	// Both ports usable, but maxCost filters them all out → no dial attempts.
	dns := mkDNS(
		mkPort("wwan0", 10, net.ParseIP("192.0.2.10")),
		mkPort("wlan0", 20, net.ParseIP("192.0.2.20")),
	)
	res, err := dialCostAware(context.Background(), log, dns, 5, "registry:443", time.Second, 0)
	if res != nil {
		t.Errorf("res = %v, want nil", res)
	}
	var de *dialError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *dialError", err)
	}
	if len(de.Attempts()) != 0 {
		t.Errorf("attempts = %v, want none (all cost-filtered)", de.Attempts())
	}
}

func TestDialCostAwareLinkLocalOnly(t *testing.T) {
	// Port within budget but its only address is link-local → skipped, no dial.
	dns := mkDNS(mkPort("eth0", 0, net.ParseIP("fe80::1")))
	res, err := dialCostAware(context.Background(), log, dns, 255, "registry:443", time.Second, 0)
	if res != nil {
		t.Errorf("res = %v, want nil", res)
	}
	var de *dialError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *dialError", err)
	}
	if len(de.Attempts()) != 0 {
		t.Errorf("attempts = %v, want none (link-local skipped)", de.Attempts())
	}
}

// TestDialCostAwareOrdersByCost asserts the dialer tries ports in ascending
// cost order. Binding the outbound socket to a source IP that is not assigned
// to any local interface fails immediately with EADDRNOTAVAIL on Linux, so no
// packets leave the host; we only observe the order of the recorded attempts.
func TestDialCostAwareOrdersByCost(t *testing.T) {
	dns := mkDNS(
		mkPort("wlan0", 20, net.ParseIP("198.51.100.20")),
		mkPort("eth0", 0, net.ParseIP("198.51.100.10")),
		mkPort("wwan0", 10, net.ParseIP("198.51.100.30")),
	)
	// Target is a literal IP (TEST-NET-2 discard port) so no DNS lookup runs.
	res, err := dialCostAware(context.Background(), log, dns, 255, "198.51.100.99:9", time.Second, 0)
	if res != nil {
		_ = res.Conn.Close()
		t.Skip("unexpected successful dial in this environment; skipping ordering assertion")
	}
	var de *dialError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *dialError", err)
	}
	attempts := de.Attempts()
	if len(attempts) != 3 {
		t.Fatalf("got %d attempts, want 3: %+v", len(attempts), attempts)
	}
	wantOrder := []string{"eth0", "wwan0", "wlan0"}
	for i, want := range wantOrder {
		if attempts[i].IfName != want {
			t.Errorf("attempt[%d] = %s, want %s (cost order)", i, attempts[i].IfName, want)
		}
	}
}

// --- idleWatchdog ----------------------------------------------------------

// tcpConnPair returns the two ends of a single loopback TCP connection. Real
// TCP sockets are required (not net.Pipe) so the watchdog's TCP_INFO read works.
func tcpConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return c1, r.c
}

// TestIdleWatchdogClosesStalledTunnel: with no bytes ever received on either
// socket, the watchdog must flip idleClosed and close the conns after timeout.
func TestIdleWatchdogClosesStalledTunnel(t *testing.T) {
	c1, c2 := tcpConnPair(t)
	defer c1.Close()
	defer c2.Close()

	var idleClosed atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		idleWatchdog(ctx, &idleClosed, 300*time.Millisecond, c1, c2)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("watchdog did not close a stalled tunnel within 3s")
	}
	if !idleClosed.Load() {
		t.Error("idleClosed = false, want true for a stalled tunnel")
	}
}

// TestIdleWatchdogKeepsActiveTunnelOpen: a tunnel that keeps receiving bytes
// must not be closed, even past several timeout windows.
func TestIdleWatchdogKeepsActiveTunnelOpen(t *testing.T) {
	c1, c2 := tcpConnPair(t)
	defer c1.Close()
	defer c2.Close()
	// Drain c2 so writes never block on a full window.
	go io.Copy(io.Discard, c2)

	var idleClosed atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		idleWatchdog(ctx, &idleClosed, 300*time.Millisecond, c1, c2)
		close(done)
	}()

	// Keep traffic flowing on the c1→c2 leg for ~3 timeout windows.
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, _ = c1.Write([]byte("x"))
			}
		}
	}()

	time.Sleep(900 * time.Millisecond)
	if idleClosed.Load() {
		t.Error("idleClosed = true, want false for an active tunnel")
	}
	close(stop)
	cancel()
	<-done
}

// --- tunnel ----------------------------------------------------------------

// TestTunnelCopiesBothDirections drives a full tunnel over two in-memory
// socket pairs and verifies bytes flow client→upstream and upstream→client,
// that the per-direction counters are updated, and that closing both peers
// lets tunnel return promptly (idle watchdog not triggered).
func TestTunnelCopiesBothDirections(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	upConn, upPeer := net.Pipe()

	ctx := newTestContext(mkDNS(), 0)

	done := make(chan struct{})
	go func() {
		tunnel(ctx, "registry:443", "eth0", clientConn, upConn, time.Now())
		close(done)
	}()

	upGot := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := upPeer.Read(buf)
		upGot <- string(buf[:n])
	}()
	clientGot := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := clientPeer.Read(buf)
		clientGot <- string(buf[:n])
	}()

	if _, err := clientPeer.Write([]byte("up-data")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := upPeer.Write([]byte("down-data")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}

	if got := <-upGot; got != "up-data" {
		t.Errorf("upstream received %q, want up-data", got)
	}
	if got := <-clientGot; got != "down-data" {
		t.Errorf("client received %q, want down-data", got)
	}

	// Closing both peers signals EOF on both copy goroutines so tunnel returns.
	_ = clientPeer.Close()
	_ = upPeer.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not return after peers closed")
	}

	if ctx.stats.bytesUp.Load() != uint64(len("up-data")) {
		t.Errorf("bytesUp = %d, want %d", ctx.stats.bytesUp.Load(), len("up-data"))
	}
	if ctx.stats.bytesDown.Load() != uint64(len("down-data")) {
		t.Errorf("bytesDown = %d, want %d", ctx.stats.bytesDown.Load(), len("down-data"))
	}
	if ctx.stats.tunnelIdleClosed.Load() != 0 {
		t.Errorf("tunnelIdleClosed = %d, want 0", ctx.stats.tunnelIdleClosed.Load())
	}
}
