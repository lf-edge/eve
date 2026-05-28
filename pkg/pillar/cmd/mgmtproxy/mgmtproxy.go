// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

// Package mgmtproxy implements a small HTTP CONNECT forward proxy on the
// loopback interface that performs cost-aware outbound dialing. It is intended
// to be used by EVE-K's standalone containerd (and the curl that fetches the
// k3s installer) so that container image pulls and the k3s download honor
// network.download.max.cost in the same way pillar's downloader already does.
package mgmtproxy

import (
	"context"
	"flag"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName   = "mgmtproxy"
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	// ListenAddr is the loopback address the proxy listens on. Containerd
	// and the k3s installer reach it via HTTPS_PROXY=http://127.0.0.1:5443.
	// The kube container runs in the host net namespace so it shares this
	// loopback with pillar.
	ListenAddr = "127.0.0.1:5443"

	// CNI0ListenAddr is an additional listener on the well-known link-local
	// anchor IP assigned to cni0 by cluster-init.sh:setup_cni0_proxy_ip().
	// CDI importer pods (created by Rancher/Helm VMIRS with source.http.url
	// DataVolumeTemplates) send HTTPS_PROXY connections here to reach the
	// local mgmtproxy. Link-local addresses are not routed by flannel across
	// nodes, so each pod reaches its own node's mgmtproxy exclusively.
	// Must match cluster-utils.sh:MGMTPROXY_CNI0_IP and MGMTPROXY_CNI0_URL.
	// Only active on kubevirt-enabled nodes (cluster-init.sh assigns the IP
	// to cni0 only when install_kubevirt=1). This goroutine retries silently
	// until the IP is assigned, which may be several minutes after pillar
	// starts. EVE-managed VM volumes (virtctl image-upload / source.upload)
	// are unaffected — they use the CDI upload-proxy service IP which is
	// already in NO_PROXY.
	CNI0ListenAddr = "169.254.100.1:5443"

	// idleTimeout caps how long an established CONNECT tunnel can sit
	// without bytes flowing in either direction. Bounds the worst case
	// when an upstream firewall accepts SYN but blackholes mid-stream.
	idleTimeout = 30 * time.Second

	// defaultDialTimeoutSecs is the per-attempt TCP connect timeout used
	// until global config arrives. Matches timer.dial.timeout's default.
	defaultDialTimeoutSecs = 10
)

var (
	logger *logrus.Logger
	log    *base.LogObject
)

type mgmtProxyContext struct {
	agentbase.AgentBase

	ps                     *pubsub.PubSub
	subGlobalConfig        pubsub.Subscription
	subDeviceNetworkStatus pubsub.Subscription

	mu                  sync.RWMutex
	deviceNetworkStatus types.DeviceNetworkStatus
	maxPortCost         uint8
	gcInitialized       bool
	dnsInitialized      bool

	// dialTimeout is the per-attempt TCP connect timeout for the upstream
	// dial, readable by the proxy handler without holding mu.
	dialTimeout atomic.Int64 // nanoseconds; set from timer.dial.timeout

	// dialRotation is incremented once per CONNECT and passed as the rotation
	// argument to the mgmt-port selectors, so requests round-robin across
	// same-cost ports (matching controllerconn's load-sharing).
	dialRotation atomic.Uint64

	stats proxyStats

	// agentMetrics is published as types.MetricsMap on
	// /run/mgmtproxy/MetricsMap/global.json so the per-target,
	// per-interface byte counts and success/failure history show up in
	// `edgeview url` and in the device ZedcloudMetric report (zedagent
	// subscribes to this MetricsMap and folds it in via AddInto), alongside
	// the other controllerconn-using agents (zedagent, downloader, nim, ...).
	agentMetrics *controllerconn.AgentMetrics
}

// proxyStats accumulates lightweight counters for /healthz. All counters use
// atomics so the proxy handler can update them from any goroutine without
// taking ctx.mu.
type proxyStats struct {
	requests          atomic.Uint64
	dialFailures      atomic.Uint64 // all upstream attempts failed → 502
	notReady          atomic.Uint64 // CONNECT before pubsub initialized
	tunnelIdleClosed  atomic.Uint64 // tunnel killed by idle watchdog
	successByPort     sync.Map      // ifName → *atomic.Uint64
	failureByPort     sync.Map      // ifName → *atomic.Uint64
	bytesUp           atomic.Uint64 // client → upstream
	bytesDown         atomic.Uint64 // upstream → client
	lastErrorTime     atomic.Int64  // unix nanos
	lastErrorMu       sync.RWMutex
	lastError         string
	lastSuccessTime   atomic.Int64 // unix nanos
	lastSuccessMu     sync.RWMutex
	lastSuccessTarget string
	lastSuccessPort   string
	lastSuccessCost   uint8
}

func (s *proxyStats) recordSuccess(target, ifName string, cost uint8) {
	c, _ := s.successByPort.LoadOrStore(ifName, &atomic.Uint64{})
	c.(*atomic.Uint64).Add(1)
	s.lastSuccessTime.Store(time.Now().UnixNano())
	s.lastSuccessMu.Lock()
	s.lastSuccessTarget = target
	s.lastSuccessPort = ifName
	s.lastSuccessCost = cost
	s.lastSuccessMu.Unlock()
}

func (s *proxyStats) recordFailure(target string, attempts []attemptResult, summary string) {
	for _, a := range attempts {
		c, _ := s.failureByPort.LoadOrStore(a.IfName, &atomic.Uint64{})
		c.(*atomic.Uint64).Add(1)
	}
	s.dialFailures.Add(1)
	s.lastErrorTime.Store(time.Now().UnixNano())
	s.lastErrorMu.Lock()
	s.lastError = target + ": " + summary
	s.lastErrorMu.Unlock()
}

func mapToCounts(m *sync.Map) map[string]uint64 {
	out := map[string]uint64{}
	m.Range(func(k, v interface{}) bool {
		out[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return out
}

// AddAgentSpecificCLIFlags satisfies agentbase.AgentBase.
func (ctx *mgmtProxyContext) AddAgentSpecificCLIFlags(_ *flag.FlagSet) {}

// snapshot returns a copy of the current DeviceNetworkStatus and the
// effective max-cost. Callers (the proxy handler) take this snapshot once per
// CONNECT so they don't race with pubsub updates while iterating ports.
func (ctx *mgmtProxyContext) snapshot() (types.DeviceNetworkStatus, uint8, bool) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.deviceNetworkStatus, ctx.maxPortCost, ctx.gcInitialized && ctx.dnsInitialized
}

// Run is the entry point for mgmtproxy from zedbox.
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject,
	arguments []string, baseDir string) int {

	logger = loggerArg
	log = logArg

	ctx := &mgmtProxyContext{
		ps:           ps,
		agentMetrics: controllerconn.NewAgentMetrics(),
	}
	// Default to timer.dial.timeout's default (10s) until global config arrives.
	ctx.dialTimeout.Store(int64(defaultDialTimeoutSecs * time.Second))
	agentbase.Init(ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	metricsPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.MetricsMap{},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Publish metrics every 10 seconds, with the same flextimer pattern
	// other agents use (downloader, zedagent, etc.). Edgeview's `url`
	// command reads /run/mgmtproxy/MetricsMap/global.json, and zedagent
	// subscribes to this publication to include it in the device metrics
	// reported to the controller.
	publishTimer := flextimer.NewRangeTicker(3*time.Second, 10*time.Second)

	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    false,
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleDNSCreate,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	server := &http.Server{
		Addr:        ListenAddr,
		Handler:     newProxyHandler(ctx),
		ReadTimeout: 30 * time.Second,
	}
	// Listen with retry rather than log.Fatal so a (rare) port-5443 conflict
	// doesn't crash pillar and trigger a watchdog reboot. The agent will keep
	// retrying every 30s; in the meantime containerd's pulls hit ECONNREFUSED
	// and kubelet retries them with ImagePullBackOff backoff. The off-switch
	// flag in cluster-init.sh is the operator escape valve for this case.
	go func() {
		for {
			listener, err := net.Listen("tcp", ListenAddr)
			if err != nil {
				log.Errorf("mgmtproxy: listen %s failed (will retry): %v",
					ListenAddr, err)
				time.Sleep(30 * time.Second)
				continue
			}
			log.Noticef("mgmtproxy: listening on %s", ListenAddr)
			if serveErr := server.Serve(listener); serveErr != nil &&
				serveErr != http.ErrServerClosed {
				log.Errorf("mgmtproxy: server.Serve: %v", serveErr)
			}
			// If Serve returned (e.g. listener closed externally), retry
			// listen rather than spin.
			time.Sleep(5 * time.Second)
		}
	}()

	// Second listener on the cni0 link-local anchor. Retries silently until
	// cluster-init.sh:setup_cni0_proxy_ip() assigns 169.254.100.1/32 to cni0
	// (only on kubevirt-enabled nodes). Shares the same handler as the
	// loopback listener — same cost-aware CONNECT logic, same metrics.
	go func() {
		server2 := &http.Server{
			Handler:     newProxyHandler(ctx),
			ReadTimeout: 30 * time.Second,
		}
		for {
			listener, err := net.Listen("tcp", CNI0ListenAddr)
			if err != nil {
				time.Sleep(30 * time.Second)
				continue
			}
			log.Noticef("mgmtproxy: cni0 listener on %s", CNI0ListenAddr)
			if serveErr := server2.Serve(listener); serveErr != nil &&
				serveErr != http.ErrServerClosed {
				log.Errorf("mgmtproxy: cni0 server.Serve: %v", serveErr)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
		case <-publishTimer.C:
			if err := ctx.agentMetrics.Publish(log, metricsPub, "global"); err != nil {
				log.Errorf("mgmtproxy: agentMetrics.Publish: %v", err)
			}
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleGlobalConfigCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string, _ interface{}) {
	ctx := ctxArg.(*mgmtProxyContext)
	if key != "global" {
		return
	}
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp == nil {
		return
	}
	ctx.mu.Lock()
	ctx.maxPortCost = uint8(gcp.GlobalValueInt(types.DownloadMaxPortCost))
	ctx.gcInitialized = true
	ctx.mu.Unlock()
	dialTimeoutSecs := gcp.GlobalValueInt(types.NetworkDialTimeout)
	ctx.dialTimeout.Store(int64(time.Duration(dialTimeoutSecs) * time.Second))
	log.Functionf("mgmtproxy: maxPortCost=%d dialTimeout=%ds", ctx.maxPortCost, dialTimeoutSecs)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string, _ interface{}) {
	ctx := ctxArg.(*mgmtProxyContext)
	if key != "global" {
		return
	}
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
}

func handleDNSCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSImpl(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*mgmtProxyContext)
	if key != "global" {
		return
	}
	dns := statusArg.(types.DeviceNetworkStatus)
	ctx.mu.Lock()
	ctx.deviceNetworkStatus = dns
	ctx.dnsInitialized = true
	ctx.mu.Unlock()
}

func handleDNSDelete(ctxArg interface{}, key string, _ interface{}) {
	ctx := ctxArg.(*mgmtProxyContext)
	if key != "global" {
		return
	}
	ctx.mu.Lock()
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	ctx.mu.Unlock()
}

// dialUpstreamCtx wraps the cost-aware dialer with the agent's snapshot logic.
// Exposed via this small adapter so proxy.go does not import pubsub or context
// internals.
func (ctx *mgmtProxyContext) dialUpstreamCtx(parent context.Context,
	target string) (*dialResult, error) {
	dns, maxCost, ready := ctx.snapshot()
	if !ready {
		ctx.stats.notReady.Add(1)
		return nil, &dialError{msg: "mgmtproxy: device network status or global config not yet initialized"}
	}
	rotation := int(ctx.dialRotation.Add(1))
	return dialCostAware(parent, log, dns, maxCost, target,
		time.Duration(ctx.dialTimeout.Load()), rotation)
}

// portSummaries returns the current mgmt-port view from DeviceNetworkStatus
// for /healthz, with the same filtering logic the dialer uses. The element
// type lives in pillar/types so consumers (e.g. edgeview) can unmarshal it.
func (ctx *mgmtProxyContext) portSummaries() []types.MgmtProxyPortSummary {
	dns, _, _ := ctx.snapshot()
	var out []types.MgmtProxyPortSummary
	for _, p := range dns.Ports {
		if !p.IsMgmt {
			continue
		}
		s := types.MgmtProxyPortSummary{
			IfName:   p.IfName,
			Cost:     p.Cost,
			IsMgmt:   p.IsMgmt,
			HasError: p.HasError(),
			NumAddrs: len(p.AddrInfoList),
		}
		if s.HasError {
			s.LastError = p.LastError
		}
		for _, a := range p.AddrInfoList {
			if a.Addr == nil || a.Addr.IsLinkLocalUnicast() {
				continue
			}
			s.UsableAddr = a.Addr.String()
			break
		}
		out = append(out, s)
	}
	return out
}
