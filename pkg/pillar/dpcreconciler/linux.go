// Copyright (c) 2022,2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcreconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	generic "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/vishvananda/netlink"
)

// Device connectivity configuration is modeled using dependency graph (see libs/depgraph).
// Config graph with all sub-graphs and config item types used for Linux network stack:
//
// +----------------------------------------------------------------------------------------+
// |                                    DeviceConnectivity                                  |
// |                                                                                        |
// |   +--------------------------------------+    +------------------------------------+   |
// |   |              NetworkIO               |    |                Global              |   |
// |   |                                      |    |                                    |   |
// |   | +-----------+    +------------+      |    | +-------------+   +-------------+  |   |
// |   | | NetIO     |    | NetIO      |      |    | | ResolvConf  |   |   IPRule    |  |   |
// |   | | (external)|    | (external) | ...  |    | | (singleton) |   | (Local RT)  |  |   |
// |   | +-----------+    +------------+      |    | +-------------+   +-------------+  |   |
// |   +--------------------------------------+    | +-------------------+              |   |
// |                                               | |      IPRule       | ...          |   |
// |                                               | | (for HV=kubevirt) |              |   |
// |                                               | +-------------------+              |   |
// |                                               +------------------------------------+   |
// |                                                                                        |
// |                                                                                        |
// |   +-----------------+  +------------------+   +-------------------------------------+  |
// |   |  PhysicalIfs    |  |  LogicalIO (L2)  |   |             Wireless                |  |
// |   |                 |  |                  |   |                                     |  |
// |   |  +--------+     |  |  +------+        |   |  +-------------+   +-------------+  |  |
// |   |  | PhysIf | ... |  |  | Vlan | ...    |   |  |    Wwan     |   |    Wlan     |  |  |
// |   |  +--------+     |  |  +------+        |   |  | (singleton) |   | (singleton) |  |  |
// |   +-----------------+  |  +------+        |   |  +-------------+   +-------------+  |  |
// |                        |  | Bond | ...    |   +-------------------------------------+  |
// |                        |  +------+        |                                            |
// |                        +------------------+                                            |
// |                                                                                        |
// |  +----------------------------------------------------------------------------------+  |
// |  |                                         L3                                       |  |
// |  |                                                                                  |  |
// |  |                                               +-------------------------------+  |  |
// |  |                                               |            IPRules            |  |  |
// |  |  +----------------------------------------+   |                               |  |  |
// |  |  |               Adapters                 |   | +-------+  +--------+         |  |  |
// |  |  |                                        |   | |IPRule |  | IPRule | ...     |  |  |
// |  |  | +---------+      +---------+           |   | +-------+  +--------+         |  |  |
// |  |  | | Adapter |      | Adapter | ...       |   +-------------------------------+  |  |
// |  |  | +---------+      +---------+           |                                      |  |
// |  |  | +------------+   +------------+        |   +-------------------------------+  |  |
// |  |  | | DhcpClient |   | DhcpClient | ...    |   |            Routes             |  |  |
// |  |  | +------------+   +------------+        |   |                               |  |  |
// |  |  | +------------------------------------+ |   | +-------+  +-------+          |  |  |
// |  |  | |            AdapterAddrs            | |   | | Route |  | Route | ...      |  |  |
// |  |  | |                                    | |   | +-------+  +-------+          |  |  |
// |  |  | |        +--------------+            | |   +-------------------------------+  |  |
// |  |  | |        | AdapterAddrs | ...        | |                                      |  |
// |  |  | |        |  (external)  |            | |   +-------------------------------+  |  |
// |  |  | |        +--------------+            | |   |             ARPs              |  |  |
// |  |  | +------------------------------------+ |   |                               |  |  |
// |  |  +----------------------------------------+   | +-----+  +-----+              |  |  |
// |  |                                               | | Arp |  | Arp | ...          |  |  |
// |  |                                               | +-----+  +-----+              |  |  |
// |  |                                               +-------------------------------+  |  |
// |  |                                                                                  |  |
// |  +----------------------------------------------------------------------------------+  |
// |                                                                                        |
// |  +----------------------------------------------------------------------------------+  |
// |  |                                       ACLs                                       |  |
// |  |                                                                                  |  |
// |  |                                +---------------+                                 |  |
// |  |                                |  SSHAuthKeys  |                                 |  |
// |  |                                |  (singleton)  |                                 |  |
// |  |                                +---------------+                                 |  |
// |  |     +--------------------------------+    +--------------------------------+     |  |
// |  |     |           IPv4Rules            |    |           IPv6Rules            |     |  |
// |  |     |                                |    |                                |     |  |
// |  |     |      +---------------+         |    |      +---------------+         |     |  |
// |  |     |      | IptablesChain | ...     |    |      | IptablesChain | ...     |     |  |
// |  |     |      +---------------+         |    |      +---------------+         |     |  |
// |  |     |      +---------------+         |    |      +---------------+         |     |  |
// |  |     |      | IptablesRule  | ...     |    |      | IptablesRule  | ...     |     |  |
// |  |     |      +---------------+         |    |      +---------------+         |     |  |
// |  |     +--------------------------------+    +--------------------------------+     |  |
// |  +----------------------------------------------------------------------------------+  |
// +----------------------------------------------------------------------------------------+
const (
	// GraphName : name of the graph with the managed state as a whole.
	GraphName = "DeviceConnectivity"
	// GlobalSG : name of the sub-graph with global configuration.
	GlobalSG = "Global"
	// NetworkIoSG : name of the sub-graph with network IO devices.
	NetworkIoSG = "NetworkIO"
	// PhysicalIfsSG : sub-graph with network interfaces corresponding to physical NICs.
	PhysicalIfsSG = "PhysicalInterfaces"
	// LogicalIoSG : name of the sub-graph with logical network interfaces.
	LogicalIoSG = "LogicalIO"
	// WirelessSG : sub-graph with everything related to wireless connectivity.
	WirelessSG = "Wireless"
	// L3SG : subgraph with configuration items related to Layer3 of the ISO/OSI model.
	L3SG = "L3"
	// AdaptersSG : sub-graph with everything related to adapters.
	AdaptersSG = "Adapters"
	// AdapterAddrsSG : sub-graph with external items representing addresses assigned to adapters.
	AdapterAddrsSG = "AdapterAddrs"
	// IPRulesSG : sub-graph with IP rules.
	IPRulesSG = "IPRules"
	// RoutesSG : sub-graph with IP routes.
	RoutesSG = "Routes"
	// ArpsSG : sub-graph with ARP entries.
	ArpsSG = "ARPs"
	// ACLsSG : sub-graph with device-wide ACLs.
	ACLsSG = "ACLs"
	// IPv4ACLsSG : sub-graph of ACLsSG with IPv4 rules.
	IPv4ACLsSG = "IPv4Rules"
	// IPv6ACLsSG : sub-graph of ACLsSG with IPv6 rules.
	IPv6ACLsSG = "IPv6Rules"
)

const (
	// File where the current state graph is exported (as DOT) after each reconcile.
	// Can be used for troubleshooting purposes.
	currentStateFile = "/run/nim-current-state.dot"
	// File where the intended state graph is exported (as DOT) after each reconcile.
	// Can be used for troubleshooting purposes.
	intendedStateFile = "/run/nim-intended-state.dot"
)

var (
	// CIDR used for IP allocation for K3s pods.
	_, kubePodCIDR, _ = net.ParseCIDR("10.42.0.0/16")
	// CIDR used for IP allocation for K3s services.
	_, kubeSvcCIDR, _ = net.ParseCIDR("10.43.0.0/16")
)

// LinuxDpcReconciler is a DPC-reconciler for Linux network stack,
// i.e. it configures and uses Linux networking to provide device connectivity.
type LinuxDpcReconciler struct {
	sync.Mutex

	// Enable to have the current state exported to /run/nim-current-state.dot
	// on every change.
	ExportCurrentState bool
	// Enable to have the intended state exported to /run/nim-intended-state.dot
	// on every change.
	ExportIntendedState bool

	// Note: the exported attributes below should be injected,
	// but most are optional.
	Log                  *base.LogObject // mandatory
	AgentName            string
	NetworkMonitor       netmonitor.NetworkMonitor // mandatory
	SubControllerCert    pubsub.Subscription
	SubEdgeNodeCert      pubsub.Subscription
	PubCipherBlockStatus pubsub.Publication
	CipherMetrics        *cipher.AgentMetrics
	PubWwanConfig        pubsub.Publication

	currentState  dg.Graph
	intendedState dg.Graph

	initialized bool
	registry    reconciler.ConfiguratorRegistry
	// Used to access WwanConfigurator.LastChecksum.
	wwanConfigurator *generic.WwanConfigurator

	// To manage asynchronous operations.
	watcherControl   chan watcherCtrl
	pendingReconcile pendingReconcile
	resumeReconcile  chan struct{}
	resumeAsync      <-chan string // nil if no async ops

	lastArgs     Args
	prevStatus   ReconcileStatus
	radioSilence types.RadioSilence
	HVTypeKube   bool
	intfMTU      map[string]uint16
}

type pendingReconcile struct {
	isPending   bool
	forSubGraph string
	reasons     []string
}

type encryptedPassword struct {
	cleartext  string
	ciphertext string
	used       bool
}

type watcherCtrl uint8

const (
	watcherCtrlUndefined watcherCtrl = iota
	watcherCtrlStart
	watcherCtrlPause
	watcherCtrlCont
)

// GetCurrentState : get the current state (read-only).
// Exported only for unit-testing purposes.
func (r *LinuxDpcReconciler) GetCurrentState() (graph dg.GraphR, release func()) {
	release = r.pauseWatcher()
	return r.currentState, release
}

// GetIntendedState : get the intended state (read-only).
// Exported only for unit-testing purposes.
func (r *LinuxDpcReconciler) GetIntendedState() (graph dg.GraphR, release func()) {
	release = r.pauseWatcher()
	return r.intendedState, release
}

func (r *LinuxDpcReconciler) init() (startWatcher func()) {
	r.Lock()
	if r.initialized {
		r.Log.Fatal("Already initialized")
	}
	registry := &reconciler.DefaultRegistry{}
	if err := generic.RegisterItems(r.Log, registry, r.PubWwanConfig); err != nil {
		r.Log.Fatal(err)
	}
	if err := linux.RegisterItems(r.Log, registry, r.NetworkMonitor); err != nil {
		r.Log.Fatal(err)
	}
	if err := iptables.RegisterItems(r.Log, registry); err != nil {
		r.Log.Fatal(err)
	}
	r.registry = registry
	configurator := registry.GetConfigurator(generic.Wwan{})
	r.wwanConfigurator = configurator.(*generic.WwanConfigurator)
	r.watcherControl = make(chan watcherCtrl, 10)
	netEvents := r.NetworkMonitor.WatchEvents(
		context.Background(), "linux-dpc-reconciler")
	go r.watcher(netEvents)
	r.initialized = true
	return func() {
		r.watcherControl <- watcherCtrlStart
		r.Unlock()
	}
}

func (r *LinuxDpcReconciler) pauseWatcher() (cont func()) {
	r.watcherControl <- watcherCtrlPause
	r.Lock()
	return func() {
		r.watcherControl <- watcherCtrlCont
		r.Unlock()
	}
}

func (r *LinuxDpcReconciler) watcher(netEvents <-chan netmonitor.Event) {
	var ctrl watcherCtrl
	for ctrl != watcherCtrlStart {
		ctrl = <-r.watcherControl
	}
	r.Lock()
	defer r.Unlock()
	for {
		select {
		case subgraph := <-r.resumeAsync:
			r.addPendingReconcile(subgraph, "async op finalized", true)

		case event := <-netEvents:
			switch ev := event.(type) {
			case netmonitor.RouteChange:
				if ev.Table == syscall.RT_TABLE_MAIN {
					r.addPendingReconcile(L3SG, "route change", true)
				}
			case netmonitor.IfChange:
				if ev.Added || ev.Deleted {
					changed := r.updateCurrentNetworkIO(r.lastArgs.DPC, r.lastArgs.AA)
					if changed {
						r.addPendingReconcile(
							NetworkIoSG, "interface added/deleted", true)
					}
				}
				if ev.Deleted {
					changed := r.updateCurrentRoutes(r.lastArgs.DPC,
						r.lastArgs.ClusterStatus)
					if changed {
						r.addPendingReconcile(
							L3SG, "interface delete triggered route change", true)
					}
				}
			case netmonitor.AddrChange:
				changed := r.updateCurrentAdapterAddrs(r.lastArgs.DPC)
				if changed {
					r.addPendingReconcile(L3SG, "address change", true)
				}
				changed = r.updateCurrentRoutes(r.lastArgs.DPC, r.lastArgs.ClusterStatus)
				if changed {
					r.addPendingReconcile(L3SG, "address change triggered route change", true)
				}

			case netmonitor.DNSInfoChange:
				newGlobalCfg := r.getIntendedGlobalCfg(r.lastArgs.DPC,
					r.lastArgs.ClusterStatus)
				prevGlobalCfg := r.intendedState.SubGraph(GlobalSG)
				if len(prevGlobalCfg.DiffItems(newGlobalCfg)) > 0 {
					r.addPendingReconcile(GlobalSG, "DNS info change", true)
				}
			}

		case ctrl = <-r.watcherControl:
			if ctrl == watcherCtrlPause {
				r.Unlock()
				pauseCnt := 1
				for pauseCnt != 0 {
					ctrl = <-r.watcherControl
					switch ctrl {
					case watcherCtrlPause:
						pauseCnt++
					case watcherCtrlCont:
						pauseCnt--
					}
				}
				r.Lock()
			}
		}
	}
}

func (r *LinuxDpcReconciler) addPendingReconcile(forSG, reason string, sendSignal bool) {
	var dulicateReason bool
	for _, prevReason := range r.pendingReconcile.reasons {
		if prevReason == reason {
			dulicateReason = true
			break
		}
	}
	if !dulicateReason {
		r.pendingReconcile.reasons = append(r.pendingReconcile.reasons, reason)
	}
	if r.pendingReconcile.isPending {
		if r.pendingReconcile.forSubGraph != forSG {
			r.pendingReconcile.forSubGraph = GraphName // reconcile all
		}
		return
	}
	r.pendingReconcile.isPending = true
	r.pendingReconcile.forSubGraph = forSG
	if !sendSignal {
		return
	}
	select {
	case r.resumeReconcile <- struct{}{}:
	default:
		r.Log.Warn("Failed to send signal to resume reconciliation")
	}
}

// Reconcile : call to apply the current DPC into the Linux network stack.
func (r *LinuxDpcReconciler) Reconcile(ctx context.Context, args Args) ReconcileStatus {
	var (
		rs           reconciler.Status
		reconcileAll bool
		reconcileSG  string
	)
	if !r.initialized {
		// This is the first state reconciliation.
		startWatcher := r.init()
		defer startWatcher()
		// r.currentState and r.intendedState are both nil, reconcile everything.
		r.addPendingReconcile(GraphName, "initial reconcile", false) // reconcile all

	} else {
		// Already run the first state reconciliation.
		contWatcher := r.pauseWatcher()
		defer contWatcher()
		// Determine what subset of the state to reconcile.
		if r.dpcChanged(args.DPC) {
			r.addPendingReconcile(GraphName, "DPC change", false) // reconcile all
		}
		if r.gcpChanged(args.GCP) {
			r.addPendingReconcile(ACLsSG, "GCP change", false)
		}
		if r.aaChanged(args.AA) {
			changed := r.updateCurrentNetworkIO(args.DPC, args.AA)
			if changed {
				r.addPendingReconcile(NetworkIoSG, "AA change", false)
			}
			r.addPendingReconcile(WirelessSG, "AA change", false)
		}
		if r.rsChanged(args.RS) {
			r.addPendingReconcile(WirelessSG, "RS change", false)
		}
		if r.flowlogStateChanged(args.FlowlogEnabled) {
			r.addPendingReconcile(ACLsSG, "Flowlog state change", false)
		}
		if r.clusterStatusChanged(args.ClusterStatus) {
			// Reconcile all items.
			r.addPendingReconcile(GraphName, "Cluster status change", false)
		}
		if !r.lastArgs.KubeUserServices.Equal(args.KubeUserServices) {
			// Services and ingresses affect ACLs
			r.addPendingReconcile(ACLsSG, "Kube services/ingresses change", false)
		}
	}
	if r.pendingReconcile.isPending {
		reconcileSG = r.pendingReconcile.forSubGraph
	} else {
		// Nothing to reconcile.
		newStatus := r.prevStatus
		newStatus.Error = nil
		newStatus.FailingItems = nil
		return newStatus
	}
	if reconcileSG == GraphName {
		reconcileAll = true
	}

	// Reconcile with clear network monitor cache to avoid working with stale data.
	r.NetworkMonitor.ClearCache()
	reconcileStartTime := time.Now()
	if reconcileAll {
		r.rebuildMTUMap(args.DPC)
		r.updateIntendedState(args)
		r.updateCurrentState(args)
		r.Log.Noticef("Running a full state reconciliation, reasons: %s",
			strings.Join(r.pendingReconcile.reasons, ", "))
		reconciler := reconciler.New(r.registry)
		rs = reconciler.Reconcile(ctx, r.currentState, r.intendedState)
		r.currentState = rs.NewCurrentState
	} else {
		// Re-build intended config only where needed.
		var intSG dg.Graph
		switch reconcileSG {
		case GlobalSG:
			intSG = r.getIntendedGlobalCfg(args.DPC, args.ClusterStatus)
		case NetworkIoSG:
			intSG = r.getIntendedNetworkIO(args.DPC)
		case PhysicalIfsSG:
			r.rebuildMTUMap(args.DPC)
			intSG = r.getIntendedPhysicalIfs(args.DPC)
		case LogicalIoSG:
			r.rebuildMTUMap(args.DPC)
			intSG = r.getIntendedLogicalIO(args.DPC)
		case L3SG:
			r.rebuildMTUMap(args.DPC)
			intSG = r.getIntendedL3Cfg(args.DPC, args.ClusterStatus)
		case WirelessSG:
			intSG = r.getIntendedWirelessCfg(args.DPC, args.AA, args.RS)
		case ACLsSG:
			intSG = r.getIntendedACLs(args.DPC, args.ClusterStatus, args.GCP,
				args.FlowlogEnabled, args.KubeUserServices)
		default:
			// Only these top-level subgraphs are used for selective-reconcile for now.
			r.Log.Fatalf("Unexpected SG select for reconcile: %s", reconcileSG)
		}
		r.intendedState.PutSubGraph(intSG)
		currSG := r.currentState.SubGraph(reconcileSG)
		r.Log.Noticef("Running state reconciliation for subgraph %s, reasons: %s",
			reconcileSG, strings.Join(r.pendingReconcile.reasons, ", "))
		reconciler := reconciler.New(r.registry)
		rs = reconciler.Reconcile(ctx, r.currentState.EditSubGraph(currSG), intSG)
	}

	// Log every executed operation.
	for _, log := range rs.OperationLog {
		var withErr string
		if log.Err != nil {
			withErr = fmt.Sprintf(" with error: %v", log.Err)
		}
		var verb string
		if log.InProgress {
			verb = "started async execution of"
		} else {
			if log.StartTime.Before(reconcileStartTime) {
				verb = "finalized async execution of"
			} else {
				// synchronous operation
				verb = "executed"
			}
		}
		r.Log.Noticef("DPC Reconciler %s %v for %v%s, content: %s",
			verb, log.Operation, dg.Reference(log.Item), withErr, log.Item.String())
	}

	// Log transitions from no-error to error and vice-versa.
	var failed, fixed []string
	var failingItems reconciler.OperationLog
	for _, log := range rs.OperationLog {
		if log.PrevErr == nil && log.Err != nil {
			failed = append(failed,
				fmt.Sprintf("%v (err: %v)", dg.Reference(log.Item), log.Err))
		}
		if log.PrevErr != nil && log.Err == nil {
			fixed = append(fixed, dg.Reference(log.Item).String())
		}
		if log.Err != nil {
			failingItems = append(failingItems, log)
		}
	}
	if len(failed) > 0 {
		r.Log.Errorf("Newly failed config items: %s",
			strings.Join(failed, ", "))
	}
	if len(fixed) > 0 {
		r.Log.Noticef("Fixed config items: %s",
			strings.Join(fixed, ", "))
	}

	// Check the state of the radio silence.
	r.radioSilence = args.RS
	_, state, _, found := r.currentState.Item(dg.Reference(linux.Wlan{}))
	if found && state.WithError() != nil {
		r.radioSilence.ConfigError = state.WithError().Error()
	}
	if r.radioSilence.Imposed {
		if !found {
			r.radioSilence.ConfigError = "missing WLAN configuration"
		}
		if !found || state.WithError() != nil {
			r.radioSilence.Imposed = false
		}
	}
	_, state, _, found = r.currentState.Item(dg.Reference(generic.Wwan{}))
	if found && state.WithError() != nil {
		r.radioSilence.ConfigError = state.WithError().Error()
	}
	if r.radioSilence.Imposed {
		if !found {
			r.radioSilence.ConfigError = "missing WWAN configuration"
		}
		if !found || state.WithError() != nil {
			r.radioSilence.Imposed = false
		}
	}

	// Check the state of DNS
	var dnsError error
	var resolvConf generic.ResolvConf
	item, state, _, found := r.currentState.Item(dg.Reference(generic.ResolvConf{}))
	if found {
		dnsError = state.WithError()
		resolvConf = item.(generic.ResolvConf)
	}
	if !found && len(args.DPC.Ports) > 0 {
		dnsError = errors.New("resolv.conf is not installed")
	}

	r.resumeReconcile = make(chan struct{}, 10)
	newStatus := ReconcileStatus{
		Error:           rs.Err,
		AsyncInProgress: rs.AsyncOpsInProgress,
		ResumeReconcile: r.resumeReconcile,
		CancelAsyncOps:  func() { rs.CancelAsyncOps(nil) },
		WaitForAsyncOps: rs.WaitForAsyncOps,
		FailingItems:    failingItems,
		RS:              r.radioSilence,
		DNS: DNSStatus{
			Error:   dnsError,
			Servers: resolvConf.DNSServers,
		},
	}

	// Update the internal state.
	r.saveArgs(args)
	r.prevStatus = newStatus
	r.resumeAsync = rs.ReadyToResume
	r.pendingReconcile.isPending = false
	r.pendingReconcile.forSubGraph = ""
	r.pendingReconcile.reasons = []string{}

	// Output the current state into a file for troubleshooting purposes.
	if r.ExportCurrentState {
		dotExporter := &dg.DotExporter{CheckDeps: true}
		dot, err := dotExporter.Export(r.currentState)
		if err != nil {
			r.Log.Warnf("Failed to export the current state to DOT: %v", err)
		} else {
			err := fileutils.WriteRename(currentStateFile, []byte(dot))
			if err != nil {
				r.Log.Warnf("WriteRename failed for %s: %v",
					currentStateFile, err)
			}
		}
	}
	// Output the intended state into a file for troubleshooting purposes.
	if r.ExportIntendedState {
		dotExporter := &dg.DotExporter{CheckDeps: true}
		dot, err := dotExporter.Export(r.intendedState)
		if err != nil {
			r.Log.Warnf("Failed to export the intended state to DOT: %v", err)
		} else {
			err := fileutils.WriteRename(intendedStateFile, []byte(dot))
			if err != nil {
				r.Log.Warnf("WriteRename failed for %s: %v",
					intendedStateFile, err)
			}
		}
	}

	return newStatus
}

func (r *LinuxDpcReconciler) saveArgs(args Args) {
	r.lastArgs = args
	// Make sure the arguments are copied so that we avoid race conditions
	// between DpcReconciler and DPCManager.
	r.lastArgs.DPC.Ports = make([]types.NetworkPortConfig, len(args.DPC.Ports))
	for i := range args.DPC.Ports {
		r.lastArgs.DPC.Ports[i] = args.DPC.Ports[i]
	}
	r.lastArgs.AA.IoBundleList = make([]types.IoBundle, len(args.AA.IoBundleList))
	for i := range args.AA.IoBundleList {
		r.lastArgs.AA.IoBundleList[i] = args.AA.IoBundleList[i]
	}

	// Deep copy KubeUserServices
	r.lastArgs.KubeUserServices.UserService = make([]types.KubeServiceInfo, len(args.KubeUserServices.UserService))
	copy(r.lastArgs.KubeUserServices.UserService, args.KubeUserServices.UserService)

	r.lastArgs.KubeUserServices.UserIngress = make([]types.KubeIngressInfo, len(args.KubeUserServices.UserIngress))
	copy(r.lastArgs.KubeUserServices.UserIngress, args.KubeUserServices.UserIngress)
}

func (r *LinuxDpcReconciler) dpcChanged(newDPC types.DevicePortConfig) bool {
	return !r.lastArgs.DPC.MostlyEqual(&newDPC)
}

func (r *LinuxDpcReconciler) aaChanged(newAA types.AssignableAdapters) bool {
	if len(newAA.IoBundleList) != len(r.lastArgs.AA.IoBundleList) {
		return true
	}
	for i := range newAA.IoBundleList {
		newIo := newAA.IoBundleList[i]
		prevIo := r.lastArgs.AA.IoBundleList[i]
		// Compare only attributes used by DpcReconciler.
		if prevIo.Logicallabel != newIo.Logicallabel ||
			prevIo.Ifname != newIo.Ifname ||
			prevIo.UsbAddr != newIo.UsbAddr ||
			prevIo.UsbProduct != newIo.UsbProduct ||
			prevIo.PciLong != newIo.PciLong ||
			prevIo.IsPCIBack != newIo.IsPCIBack {
			return true
		}
	}
	return false
}

func (r *LinuxDpcReconciler) rsChanged(newRS types.RadioSilence) bool {
	return r.lastArgs.RS.Imposed != newRS.Imposed
}

func (r *LinuxDpcReconciler) gcpChanged(newGCP types.ConfigItemValueMap) bool {
	prevAuthKeys := r.lastArgs.GCP.GlobalValueString(types.SSHAuthorizedKeys)
	newAuthKeys := newGCP.GlobalValueString(types.SSHAuthorizedKeys)
	if prevAuthKeys != newAuthKeys {
		return true
	}
	prevAllowVNC := r.lastArgs.GCP.GlobalValueBool(types.AllowAppVnc)
	newAllowVNC := newGCP.GlobalValueBool(types.AllowAppVnc)
	if prevAllowVNC != newAllowVNC {
		return true
	}
	return false
}

func (r *LinuxDpcReconciler) flowlogStateChanged(flowlogEnabled bool) bool {
	return r.lastArgs.FlowlogEnabled != flowlogEnabled
}

func (r *LinuxDpcReconciler) clusterStatusChanged(
	newStatus types.EdgeNodeClusterStatus) bool {
	// DPCReconciler cares only about the networking-related fields of the ClusterStatus.
	return r.lastArgs.ClusterStatus.ClusterInterface != newStatus.ClusterInterface ||
		!netutils.EqualIPNets(r.lastArgs.ClusterStatus.ClusterIPPrefix,
			newStatus.ClusterIPPrefix)
}

func (r *LinuxDpcReconciler) updateCurrentState(args Args) (changed bool) {
	if r.currentState == nil {
		// Initialize only subgraphs with external items.
		addrsSG := dg.InitArgs{Name: AdapterAddrsSG}
		adaptersSG := dg.InitArgs{Name: AdaptersSG, Subgraphs: []dg.InitArgs{addrsSG}}
		routesSG := dg.InitArgs{Name: RoutesSG}
		l3SG := dg.InitArgs{Name: L3SG, Subgraphs: []dg.InitArgs{adaptersSG, routesSG}}
		netIoSG := dg.InitArgs{Name: NetworkIoSG}
		graph := dg.InitArgs{Name: GraphName, Subgraphs: []dg.InitArgs{netIoSG, l3SG}}
		r.currentState = dg.New(graph)
		changed = true
	}
	if ioChanged := r.updateCurrentNetworkIO(args.DPC, args.AA); ioChanged {
		changed = true
	}
	if addrsChanged := r.updateCurrentAdapterAddrs(args.DPC); addrsChanged {
		changed = true
	}
	if routesChanged := r.updateCurrentRoutes(args.DPC, args.ClusterStatus); routesChanged {
		changed = true
	}
	return changed
}

func (r *LinuxDpcReconciler) updateCurrentNetworkIO(
	dpc types.DevicePortConfig, aa types.AssignableAdapters) (changed bool) {
	currentIO := dg.New(dg.InitArgs{Name: NetworkIoSG})
	for _, port := range dpc.Ports {
		if port.L2Type != types.L2LinkTypeNone || port.IfName == "" {
			continue
		}
		ioBundle := aa.LookupIoBundleIfName(port.IfName)
		if ioBundle != nil && ioBundle.IsPCIBack {
			// Until confirmed by domainmgr that the interface is out of PCIBack
			// and ready, pretend that it doesn't exist. This is because domainmgr
			// might perform interface renaming and it could mess up the config
			// applied by DPC reconciler.
			// But note that until there is a config from controller,
			// we do not have any IO Bundles, therefore interfaces without
			// entries in AssignableAdapters should not be ignored.
			continue
		}
		_, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("updateCurrentNetworkIO: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		currentIO.PutItem(generic.NetIO{
			LogicalLabel: port.Logicallabel,
			IfName:       port.IfName,
		}, &reconciler.ItemStateData{
			State:         reconciler.ItemStateCreated,
			LastOperation: reconciler.OperationCreate,
		})
	}
	prevSG := r.currentState.SubGraph(NetworkIoSG)
	if len(prevSG.DiffItems(currentIO)) > 0 {
		r.currentState.PutSubGraph(currentIO)
		return true
	}
	return false
}

func (r *LinuxDpcReconciler) updateCurrentAdapterAddrs(
	dpc types.DevicePortConfig) (changed bool) {
	sgPath := dg.NewSubGraphPath(L3SG, AdaptersSG, AdapterAddrsSG)
	currentAddrs := dg.New(dg.InitArgs{Name: AdapterAddrsSG})
	for _, port := range dpc.Ports {
		if !port.IsL3Port || port.IfName == "" || port.InvalidConfig {
			continue
		}
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("updateCurrentAdapterAddrs: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		ipAddrs, _, err := r.NetworkMonitor.GetInterfaceAddrs(ifIndex)
		if err != nil {
			r.Log.Errorf("updateCurrentAdapterAddrs: failed to get IP addrs for %s: %v",
				port.IfName, err)
			continue
		}
		currentAddrs.PutItem(generic.AdapterAddrs{
			AdapterIfName: port.IfName,
			AdapterLL:     port.Logicallabel,
			IPAddrs:       ipAddrs,
		}, &reconciler.ItemStateData{
			State:         reconciler.ItemStateCreated,
			LastOperation: reconciler.OperationCreate,
		})
	}
	prevSG := dg.GetSubGraph(r.currentState, sgPath)
	if len(prevSG.DiffItems(currentAddrs)) > 0 {
		prevSG.EditParentGraph().PutSubGraph(currentAddrs)
		return true
	}
	return false
}

func (r *LinuxDpcReconciler) updateCurrentRoutes(dpc types.DevicePortConfig,
	clusterStatus types.EdgeNodeClusterStatus) (changed bool) {
	sgPath := dg.NewSubGraphPath(L3SG, RoutesSG)
	currentRoutes := dg.New(dg.InitArgs{Name: RoutesSG})
	for _, port := range dpc.Ports {
		if port.IfName == "" || port.InvalidConfig {
			continue
		}
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("updateCurrentRoutes: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		table := types.DPCBaseRTIndex + ifIndex
		routes, err := r.NetworkMonitor.ListRoutes(netmonitor.RouteFilters{
			FilterByTable: true,
			Table:         table,
			FilterByIf:    true,
			IfIndex:       ifIndex,
		})
		if err != nil {
			r.Log.Errorf("updateCurrentRoutes: ListRoutes failed for ifIndex %d: %v",
				ifIndex, err)
		}
		if r.HVTypeKube && clusterStatus.ClusterInterface == port.Logicallabel {
			k3sSvcRoutes, err := r.NetworkMonitor.ListRoutes(netmonitor.RouteFilters{
				FilterByTable: true,
				Table:         types.KubeSvcRT,
				FilterByIf:    true,
				IfIndex:       ifIndex,
			})
			if err == nil {
				routes = append(routes, k3sSvcRoutes...)
			} else {
				r.Log.Errorf("updateCurrentRoutes: ListRoutes failed for ifIndex %d "+
					"and the KubeSvc table: %v", ifIndex, err)
			}
		}
		for _, rt := range routes {
			currentRoutes.PutItem(linux.Route{
				Route:         rt.Data.(netlink.Route),
				AdapterIfName: port.IfName,
				AdapterLL:     port.Logicallabel,
			}, &reconciler.ItemStateData{
				State:         reconciler.ItemStateCreated,
				LastOperation: reconciler.OperationCreate,
			})
		}
	}
	prevSG := dg.GetSubGraph(r.currentState, sgPath)
	if len(prevSG.DiffItems(currentRoutes)) > 0 {
		prevSG.EditParentGraph().PutSubGraph(currentRoutes)
		return true
	}
	return false
}

func (r *LinuxDpcReconciler) updateIntendedState(args Args) {
	graphArgs := dg.InitArgs{
		Name:        GraphName,
		Description: "Device Connectivity provided using Linux network stack",
	}
	r.intendedState = dg.New(graphArgs)
	r.intendedState.PutSubGraph(r.getIntendedGlobalCfg(args.DPC, args.ClusterStatus))
	r.intendedState.PutSubGraph(r.getIntendedNetworkIO(args.DPC))
	r.intendedState.PutSubGraph(r.getIntendedPhysicalIfs(args.DPC))
	r.intendedState.PutSubGraph(r.getIntendedLogicalIO(args.DPC))
	r.intendedState.PutSubGraph(r.getIntendedL3Cfg(args.DPC, args.ClusterStatus))
	r.intendedState.PutSubGraph(r.getIntendedWirelessCfg(args.DPC, args.AA, args.RS))
	r.intendedState.PutSubGraph(r.getIntendedACLs(args.DPC, args.ClusterStatus, args.GCP,
		args.FlowlogEnabled, args.KubeUserServices))
}

func (r *LinuxDpcReconciler) getIntendedGlobalCfg(dpc types.DevicePortConfig,
	clusterStatus types.EdgeNodeClusterStatus) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        GlobalSG,
		Description: "Global configuration",
	}
	intendedCfg := dg.New(graphArgs)
	// Move IP rule that matches local destined packets below network instance rules.
	intendedCfg.PutItem(linux.IPRule{
		Priority: types.PbrLocalDestPrio,
		Table:    unix.RT_TABLE_LOCAL,
	}, nil)
	if r.HVTypeKube {
		intendedCfg.PutItem(linux.IPRule{
			Dst:      kubePodCIDR,
			Priority: types.PbrKubeNetworkPrio,
			Table:    unix.RT_TABLE_MAIN,
		}, nil)
		tableForKubeSvc := unix.RT_TABLE_MAIN
		if clusterStatus.ClusterInterface != "" {
			tableForKubeSvc = types.KubeSvcRT
		}
		intendedCfg.PutItem(linux.IPRule{
			Dst:      kubeSvcCIDR,
			Priority: types.PbrKubeNetworkPrio,
			Table:    tableForKubeSvc,
		}, nil)
	}
	if len(dpc.Ports) == 0 {
		return intendedCfg
	}
	// Intended content of /etc/resolv.conf
	dnsServers := make(map[string][]net.IP)
	for _, port := range dpc.Ports {
		if !port.IsMgmt || port.IfName == "" || port.InvalidConfig {
			continue
		}
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("getIntendedGlobalCfg: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		dnsInfo, err := r.NetworkMonitor.GetInterfaceDNSInfo(ifIndex)
		if err != nil {
			r.Log.Errorf("getIntendedGlobalCfg: failed to get DNS info for %s: %v",
				port.IfName, err)
			continue
		}
		dnsServers[port.IfName] = dnsInfo.DNSServers
	}
	intendedCfg.PutItem(generic.ResolvConf{DNSServers: dnsServers}, nil)
	return intendedCfg
}

func (r *LinuxDpcReconciler) getIntendedNetworkIO(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        NetworkIoSG,
		Description: "Network IO devices",
	}
	intendedIO := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		if port.IfName == "" {
			continue
		}
		if port.L2Type == types.L2LinkTypeNone {
			intendedIO.PutItem(generic.NetIO{
				LogicalLabel: port.Logicallabel,
				IfName:       port.IfName,
			}, nil)
		}
	}
	return intendedIO
}

func (r *LinuxDpcReconciler) rebuildMTUMap(dpc types.DevicePortConfig) {
	r.intfMTU = make(map[string]uint16) // logical label -> MTU
	for _, port := range dpc.Ports {
		if port.InvalidConfig {
			continue
		}
		portMTU := port.MTU
		if portMTU == 0 {
			portMTU = types.DefaultMTU
		}
		if portMTU > r.intfMTU[port.Logicallabel] {
			r.intfMTU[port.Logicallabel] = portMTU
		}
		// Lower-layer ports should have the max MTU of all associated higher-layer ports.
		switch port.L2Type {
		case types.L2LinkTypeVLAN:
			if portMTU > r.intfMTU[port.VLAN.ParentPort] {
				r.intfMTU[port.VLAN.ParentPort] = portMTU
			}
		case types.L2LinkTypeBond:
			for _, aggrPort := range port.Bond.AggregatedPorts {
				if portMTU > r.intfMTU[aggrPort] {
					r.intfMTU[aggrPort] = portMTU
				}
			}
		}
	}
}

func (r *LinuxDpcReconciler) getIntendedPhysicalIfs(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        PhysicalIfsSG,
		Description: "Physical network interfaces",
	}
	intendedIfs := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		if port.IfName == "" || port.InvalidConfig {
			continue
		}
		switch port.L2Type {
		case types.L2LinkTypeNone:
			if port.IsL3Port && !dpc.IsPortUsedAsVlanParent(port.Logicallabel) {
				intendedIfs.PutItem(linux.PhysIf{
					PhysIfLL:     port.Logicallabel,
					PhysIfName:   port.IfName,
					Usage:        generic.IOUsageL3Adapter,
					WirelessType: port.WirelessCfg.WType,
					MTU:          r.intfMTU[port.Logicallabel],
				}, nil)
			}
		case types.L2LinkTypeVLAN:
			parent := dpc.LookupPortByLogicallabel(port.VLAN.ParentPort)
			usage := generic.IOUsageVlanParent
			if parent.IsL3Port {
				usage = generic.IOUsageVlanParentAndL3Adapter
			}
			if parent != nil && parent.L2Type == types.L2LinkTypeNone {
				intendedIfs.PutItem(linux.PhysIf{
					PhysIfLL:     parent.Logicallabel,
					PhysIfName:   parent.IfName,
					Usage:        usage,
					WirelessType: port.WirelessCfg.WType,
					MTU:          r.intfMTU[port.Logicallabel],
				}, nil)
			}
		case types.L2LinkTypeBond:
			for _, aggrPort := range port.Bond.AggregatedPorts {
				if nps := dpc.LookupPortByLogicallabel(aggrPort); nps != nil {
					intendedIfs.PutItem(linux.PhysIf{
						PhysIfLL:     nps.Logicallabel,
						PhysIfName:   nps.IfName,
						Usage:        generic.IOUsageBondAggrIf,
						MasterIfName: port.IfName,
						WirelessType: port.WirelessCfg.WType,
						MTU:          r.intfMTU[port.Logicallabel],
					}, nil)
				}
			}
		}
	}
	return intendedIfs
}

func (r *LinuxDpcReconciler) getIntendedLogicalIO(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        LogicalIoSG,
		Description: "Logical (L2) network interfaces",
	}
	intendedIO := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		if port.IfName == "" || port.InvalidConfig {
			continue
		}
		switch port.L2Type {
		case types.L2LinkTypeVLAN:
			parent := dpc.LookupPortByLogicallabel(port.VLAN.ParentPort)
			if parent != nil {
				vlan := linux.Vlan{
					LogicalLabel:   port.Logicallabel,
					IfName:         port.IfName,
					ParentLL:       port.VLAN.ParentPort,
					ParentIfName:   parent.IfName,
					ParentL2Type:   parent.L2Type,
					ParentIsL3Port: parent.IsL3Port,
					ID:             port.VLAN.ID,
					MTU:            r.intfMTU[port.Logicallabel],
				}
				intendedIO.PutItem(vlan, nil)
			}

		case types.L2LinkTypeBond:
			var aggrIfNames []string
			for _, aggrPort := range port.Bond.AggregatedPorts {
				if nps := dpc.LookupPortByLogicallabel(aggrPort); nps != nil {
					aggrIfNames = append(aggrIfNames, nps.IfName)
				}
			}
			var usage generic.IOUsage
			if dpc.IsPortUsedAsVlanParent(port.Logicallabel) {
				if port.IsL3Port {
					usage = generic.IOUsageVlanParentAndL3Adapter
				} else {
					usage = generic.IOUsageVlanParent
				}
			} else if port.IsL3Port {
				usage = generic.IOUsageL3Adapter
			}
			intendedIO.PutItem(linux.Bond{
				BondConfig:        port.Bond,
				LogicalLabel:      port.Logicallabel,
				IfName:            port.IfName,
				AggregatedIfNames: aggrIfNames,
				Usage:             usage,
				MTU:               r.intfMTU[port.Logicallabel],
			}, nil)
		}
	}
	return intendedIO
}

func (r *LinuxDpcReconciler) getIntendedL3Cfg(dpc types.DevicePortConfig,
	clusterStatus types.EdgeNodeClusterStatus) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        L3SG,
		Description: "Network Layer3 configuration",
	}
	intendedL3 := dg.New(graphArgs)
	intendedL3.PutSubGraph(r.getIntendedAdapters(dpc, clusterStatus))
	intendedL3.PutSubGraph(r.getIntendedSrcIPRules(dpc))
	intendedL3.PutSubGraph(r.getIntendedRoutes(dpc, clusterStatus))
	intendedL3.PutSubGraph(r.getIntendedArps(dpc))
	return intendedL3
}

func (r *LinuxDpcReconciler) getIntendedAdapters(dpc types.DevicePortConfig,
	clusterStatus types.EdgeNodeClusterStatus) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        AdaptersSG,
		Description: "L3 configuration assigned to network interfaces",
		Subgraphs: []dg.InitArgs{
			{
				Name:        AdapterAddrsSG,
				Description: "IP addresses assigned to adapters",
			},
		},
	}
	intendedAdapters := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		if !port.IsL3Port || port.IfName == "" || port.InvalidConfig {
			continue
		}
		var staticIPs []*net.IPNet
		if r.HVTypeKube {
			if port.Logicallabel == clusterStatus.ClusterInterface &&
				clusterStatus.ClusterIPPrefix != nil {
				staticIPs = append(staticIPs, clusterStatus.ClusterIPPrefix)
			}
		}
		adapter := linux.Adapter{
			LogicalLabel:     port.Logicallabel,
			IfName:           port.IfName,
			L2Type:           port.L2Type,
			WirelessType:     port.WirelessCfg.WType,
			UsedAsVlanParent: dpc.IsPortUsedAsVlanParent(port.Logicallabel),
			DhcpType:         port.Dhcp,
			MTU:              r.intfMTU[port.Logicallabel],
			StaticIPs:        staticIPs,
		}
		intendedAdapters.PutItem(adapter, nil)
		if port.Dhcp != types.DhcpTypeNone &&
			port.WirelessCfg.WType != types.WirelessTypeCellular {
			intendedAdapters.PutItem(generic.Dhcpcd{
				AdapterLL:     port.Logicallabel,
				AdapterIfName: port.IfName,
				DhcpConfig:    port.DhcpConfig,
			}, nil)
		}
		// Inside the intended state the external items (like AdapterAddrs)
		// are only informatory, hence ignore any errors below.
		if ifIndex, found, _ := r.NetworkMonitor.GetInterfaceIndex(port.IfName); found {
			if ipAddrs, _, err := r.NetworkMonitor.GetInterfaceAddrs(ifIndex); err == nil {
				dg.PutItemInto(intendedAdapters,
					generic.AdapterAddrs{
						AdapterIfName: port.IfName,
						AdapterLL:     port.Logicallabel,
						IPAddrs:       ipAddrs,
					}, nil, dg.NewSubGraphPath(AdapterAddrsSG))
			}
		}
	}
	return intendedAdapters
}

func (r *LinuxDpcReconciler) getIntendedSrcIPRules(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        IPRulesSG,
		Description: "Source-based IP rules",
	}
	intendedRules := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		if port.IfName == "" || port.InvalidConfig {
			continue
		}
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("getIntendedSrcIPRules: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		ipAddrs, _, err := r.NetworkMonitor.GetInterfaceAddrs(ifIndex)
		if err != nil {
			r.Log.Errorf("getIntendedSrcIPRules: failed to get IP addresses for %s: %v",
				port.IfName, err)
			continue
		}
		for _, ipAddr := range ipAddrs {
			intendedRules.PutItem(linux.IPRule{
				Src:      netutils.HostSubnet(ipAddr.IP),
				Priority: types.PbrLocalOrigPrio,
				Table:    types.DPCBaseRTIndex + ifIndex,
			}, nil)
		}
	}
	return intendedRules
}

func (r *LinuxDpcReconciler) getIntendedRoutes(dpc types.DevicePortConfig,
	clusterStatus types.EdgeNodeClusterStatus) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        RoutesSG,
		Description: "IP routes",
	}
	intendedRoutes := dg.New(graphArgs)
	// Routes are copied from the main table.
	srcTable := syscall.RT_TABLE_MAIN
	for _, port := range dpc.Ports {
		if port.IfName == "" || port.InvalidConfig {
			continue
		}
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("getIntendedRoutes: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		dstTable := types.DPCBaseRTIndex + ifIndex
		routes, err := r.NetworkMonitor.ListRoutes(netmonitor.RouteFilters{
			FilterByTable: true,
			Table:         srcTable,
			FilterByIf:    true,
			IfIndex:       ifIndex,
		})
		if err != nil {
			r.Log.Errorf("getIntendedRoutes: ListRoutes failed for ifIndex %d: %v",
				ifIndex, err)
		}
		for _, rt := range routes {
			rtCopy := rt.Data.(netlink.Route)
			rtCopy.Table = dstTable
			r.prepareRouteForCopy(&rtCopy)
			intendedRoutes.PutItem(linux.Route{
				Route:         rtCopy,
				AdapterIfName: port.IfName,
				AdapterLL:     port.Logicallabel,
			}, nil)
		}
		if r.HVTypeKube && clusterStatus.ClusterInterface == port.Logicallabel &&
			clusterStatus.ClusterIPPrefix != nil {
			// Ensure that packets destined for K3s services do not use the default route,
			// but are instead routed through the cluster port. This guarantees that traffic
			// handled by kube-proxy is properly SNATed to the cluster IP. That's the theory
			// at least. We're not entirely certain. Without this route, however,
			// some Longhorn pods fail to access K3s services when the cluster IP is configured
			// on a non-default port.
			intendedRoutes.PutItem(linux.Route{
				Route: netlink.Route{
					LinkIndex: ifIndex,
					Family:    netlink.FAMILY_V4,
					Scope:     netlink.SCOPE_UNIVERSE,
					Protocol:  unix.RTPROT_STATIC,
					Type:      unix.RTN_UNICAST,
					Dst:       kubeSvcCIDR,
					Gw:        clusterStatus.ClusterIPPrefix.IP,
					Table:     types.KubeSvcRT,
				},
				AdapterIfName: port.IfName,
				AdapterLL:     port.Logicallabel,
			}, nil)
		}
	}
	return intendedRoutes
}

func (r *LinuxDpcReconciler) prepareRouteForCopy(route *netlink.Route) {
	// Multiple IPv6 link-locals can't be added to the same
	// table unless the Priority differs.
	// Different LinkIndex, Src, Scope doesn't matter.
	if route.Dst != nil && route.Dst.IP.IsLinkLocalUnicast() {
		if r.Log != nil {
			r.Log.Tracef("Forcing IPv6 priority to %v", route.LinkIndex)
		}
		// Hack to make the kernel routes not appear identical.
		route.Priority = route.LinkIndex
	}
}

type portAddr struct {
	logicalLabel string
	ifName       string
	macAddr      net.HardwareAddr
	ipAddr       net.IP
}

// Group port addresses by subnet.
func (r *LinuxDpcReconciler) groupPortAddrs(dpc types.DevicePortConfig) map[string][]portAddr {
	arpGroups := map[string][]portAddr{}
	for _, port := range dpc.Ports {
		if port.IfName == "" || port.InvalidConfig {
			continue
		}
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("groupPortAddrs: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		ipAddrs, macAddr, err := r.NetworkMonitor.GetInterfaceAddrs(ifIndex)
		if err != nil {
			r.Log.Errorf("groupPortAddrs: failed to get IP addresses for %s: %v",
				port.IfName, err)
			continue
		}
		if len(macAddr) == 0 {
			continue
		}
		for _, ipAddr := range ipAddrs {
			if netutils.HostFamily(ipAddr.IP) != syscall.AF_INET {
				continue
			}
			subnet := &net.IPNet{Mask: ipAddr.Mask, IP: ipAddr.IP.Mask(ipAddr.Mask)}
			addr := portAddr{
				logicalLabel: port.Logicallabel,
				ifName:       port.IfName,
				macAddr:      macAddr,
				ipAddr:       ipAddr.IP,
			}
			if group, ok := arpGroups[subnet.String()]; ok {
				arpGroups[subnet.String()] = append(group, addr)
			} else {
				arpGroups[subnet.String()] = []portAddr{addr}
			}
			break
		}
	}
	return arpGroups
}

func (r *LinuxDpcReconciler) getIntendedArps(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        ArpsSG,
		Description: "ARP entries",
	}
	intendedArps := dg.New(graphArgs)
	for _, group := range r.groupPortAddrs(dpc) {
		if len(group) <= 1 {
			// No ARP entries to be programmed.
			continue
		}
		for i := 0; i < len(group); i++ {
			from := group[i]
			for j := i + 1; j < len(group); j++ {
				to := group[j]
				intendedArps.PutItem(linux.Arp{
					AdapterLL:     from.logicalLabel,
					AdapterIfName: from.ifName,
					IPAddr:        to.ipAddr,
					HwAddr:        to.macAddr,
				}, nil)
				// Create reverse entry at the same time
				intendedArps.PutItem(linux.Arp{
					AdapterLL:     to.logicalLabel,
					AdapterIfName: to.ifName,
					IPAddr:        from.ipAddr,
					HwAddr:        from.macAddr,
				}, nil)
			}
		}
	}
	return intendedArps
}

func (r *LinuxDpcReconciler) getIntendedWirelessCfg(dpc types.DevicePortConfig,
	aa types.AssignableAdapters, radioSilence types.RadioSilence) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        WirelessSG,
		Description: "Configuration for wireless connectivity",
	}
	intendedWirelessCfg := dg.New(graphArgs)
	intendedWirelessCfg.PutItem(
		r.getIntendedWlanConfig(dpc, radioSilence), nil)
	if dpc.Key != "" {
		// Do not send config to wwan microservice until we receive DPC.
		// The default behaviour of wwan microservice (i.e. without config) is to disable
		// radios of all cellular modems, which is the same effect we would get with empty
		// config anyway. However, without config the wwan microservice does just that
		// and does not waste time collecting e.g. modem state data. This is important
		// because when the DPC arrives, wwan microservice won't be blocked on retrieving
		// some state data but will be ready to apply the config immediately.
		intendedWirelessCfg.PutItem(
			r.getIntendedWwanConfig(dpc, aa, radioSilence), nil)
	}
	return intendedWirelessCfg
}

func (r *LinuxDpcReconciler) getIntendedWlanConfig(
	dpc types.DevicePortConfig, radioSilence types.RadioSilence) dg.Item {
	var wifiPort *types.NetworkPortConfig
	for _, portCfg := range dpc.Ports {
		if portCfg.WirelessCfg.WType == types.WirelessTypeWifi &&
			!portCfg.WirelessCfg.IsEmpty() {
			wifiPort = &portCfg
			break
		}
	}
	var wifiConfig []linux.WifiConfig
	if wifiPort != nil {
		for _, wifi := range wifiPort.WirelessCfg.Wifi {
			credentials, err := r.getWifiCredentials(wifi)
			if err != nil {
				continue
			}
			wifiConfig = append(wifiConfig, linux.WifiConfig{
				WifiConfig:  wifi,
				Credentials: credentials,
			})
		}
	}
	return linux.Wlan{
		Config:   wifiConfig,
		EnableRF: wifiPort != nil && !radioSilence.Imposed,
	}
}

func (r *LinuxDpcReconciler) getWifiCredentials(wifi types.WifiConfig) (types.EncryptionBlock, error) {
	decryptAvailable := r.SubControllerCert != nil && r.SubEdgeNodeCert != nil
	if !wifi.CipherBlockStatus.IsCipher || !decryptAvailable {
		if !wifi.CipherBlockStatus.IsCipher {
			r.Log.Functionf("%s, wifi config cipherblock is not present\n", wifi.SSID)
		} else {
			r.Log.Warnf("%s, context for decryption of wifi credentials is not available\n",
				wifi.SSID)
		}
		decBlock := types.EncryptionBlock{}
		decBlock.WifiUserName = wifi.Identity
		decBlock.WifiPassword = wifi.Password
		if r.CipherMetrics != nil {
			if decBlock.WifiUserName != "" || decBlock.WifiPassword != "" {
				r.CipherMetrics.RecordFailure(r.Log, types.NoCipher)
			} else {
				r.CipherMetrics.RecordFailure(r.Log, types.NoData)
			}
		}
		return decBlock, nil
	}
	status, decBlock, err := cipher.GetCipherCredentials(
		&cipher.DecryptCipherContext{
			Log:                  r.Log,
			AgentName:            r.AgentName,
			AgentMetrics:         r.CipherMetrics,
			PubSubControllerCert: r.SubControllerCert,
			PubSubEdgeNodeCert:   r.SubEdgeNodeCert,
		},
		wifi.CipherBlockStatus)
	if r.PubCipherBlockStatus != nil {
		r.PubCipherBlockStatus.Publish(status.Key(), status)
	}
	if err != nil {
		r.Log.Errorf("%s, wifi config cipherblock decryption was unsuccessful, "+
			"falling back to cleartext: %v\n", wifi.SSID, err)
		decBlock.WifiUserName = wifi.Identity
		decBlock.WifiPassword = wifi.Password
		// We assume IsCipher is only set when there was some
		// data. Hence this is a fallback if there is
		// some cleartext.
		if r.CipherMetrics != nil {
			if decBlock.WifiUserName != "" || decBlock.WifiPassword != "" {
				r.CipherMetrics.RecordFailure(r.Log, types.CleartextFallback)
			} else {
				r.CipherMetrics.RecordFailure(r.Log, types.MissingFallback)
			}
		}
		return decBlock, nil
	}
	r.Log.Functionf("%s, wifi config cipherblock decryption was successful\n",
		wifi.SSID)
	return decBlock, nil
}

func (r *LinuxDpcReconciler) getIntendedWwanConfig(dpc types.DevicePortConfig,
	aa types.AssignableAdapters, radioSilence types.RadioSilence) dg.Item {
	config := types.WwanConfig{
		DPCKey:            dpc.Key,
		DPCTimestamp:      dpc.TimePriority,
		RSConfigTimestamp: radioSilence.ChangeRequestedAt,
		RadioSilence:      radioSilence.Imposed,
		Networks:          []types.WwanNetworkConfig{},
	}
	for _, port := range dpc.Ports {
		if port.InvalidConfig {
			continue
		}
		if port.WirelessCfg.WType != types.WirelessTypeCellular ||
			port.WirelessCfg.IsEmpty() {
			continue
		}
		if !aa.Initialized {
			r.Log.Warnf("getIntendedWwanConfig: AA is not yet initialized, "+
				"skipping IsPCIBack check for port %s", port.Logicallabel)
		} else {
			ioBundle := aa.LookupIoBundleLogicallabel(port.Logicallabel)
			if ioBundle == nil {
				r.Log.Warnf("Failed to find adapter with logical label '%s'",
					port.Logicallabel)
				continue
			}
			if ioBundle.IsPCIBack {
				r.Log.Warnf("getIntendedWwanConfig: wwan adapter with the logical label "+
					"'%s' is assigned to pciback, skipping", port.Logicallabel)
				continue
			}
		}
		var (
			accessPoint      *types.CellularAccessPoint
			probeCfg         types.WwanProbe
			locationTracking bool
		)
		for _, ap := range port.WirelessCfg.CellularV2.AccessPoints {
			if ap.Activated {
				accessPoint = &ap
				break
			}
		}
		if accessPoint != nil {
			// CellularV2 is being used.
			probeCfg = port.WirelessCfg.CellularV2.Probe
			locationTracking = port.WirelessCfg.CellularV2.LocationTracking
		} else {
			if len(port.WirelessCfg.Cellular) > 0 {
				// Old and now deprecated Cellular config is being used.
				cellCfg := port.WirelessCfg.Cellular[0]
				accessPoint = &types.CellularAccessPoint{
					Activated: true,
					APN:       cellCfg.APN,
				}
				probeCfg.Disable = cellCfg.DisableProbe
				if cellCfg.ProbeAddr != "" {
					probeCfg.UserDefinedProbe.Method = types.ConnectivityProbeMethodICMP
					probeCfg.UserDefinedProbe.ProbeHost = cellCfg.ProbeAddr
				}
				locationTracking = cellCfg.LocationTracking
				r.Log.Warnf("getIntendedWwanConfig: using deprecated WirelessCfg.Cellular")
			} else {
				r.Log.Warnf("getIntendedWwanConfig: no activated access point "+
					"for port %s, skipping", port.Logicallabel)
				continue
			}
		}
		// Prefer USB and PCI addresses over interface name.
		var physAddress types.WwanPhysAddrs
		if port.USBAddr != "" || port.PCIAddr != "" {
			physAddress.USB = port.USBAddr
			physAddress.PCI = port.PCIAddr
		} else {
			physAddress.Interface = port.IfName
		}
		network := types.WwanNetworkConfig{
			LogicalLabel:     port.Logicallabel,
			PhysAddrs:        physAddress,
			AccessPoint:      *accessPoint,
			Proxies:          port.Proxies,
			Probe:            probeCfg,
			MTU:              port.MTU,
			LocationTracking: locationTracking,
		}
		config.Networks = append(config.Networks, network)
	}
	return generic.Wwan{Config: config}
}

func (r *LinuxDpcReconciler) getIntendedACLs(dpc types.DevicePortConfig,
	clusterStatus types.EdgeNodeClusterStatus, gcp types.ConfigItemValueMap,
	withFlowlog bool, kubeUserServices types.KubeUserServices) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        ACLsSG,
		Description: "Device-wide ACLs",
	}
	intendedACLs := dg.New(graphArgs)
	graphArgs = dg.InitArgs{
		Name:        IPv4ACLsSG,
		Description: "IPv4 Device-Wide ACL rules",
	}
	intendedIPv4ACLs := dg.New(graphArgs)
	intendedACLs.PutSubGraph(intendedIPv4ACLs)
	graphArgs = dg.InitArgs{
		Name:        IPv6ACLsSG,
		Description: "IPv6 Device-Wide ACL rules",
	}
	intendedIPv6ACLs := dg.New(graphArgs)
	intendedACLs.PutSubGraph(intendedIPv6ACLs)

	gcpSSHAuthKeys := gcp.GlobalValueString(types.SSHAuthorizedKeys)
	intendedACLs.PutItem(generic.SSHAuthKeys{Keys: gcpSSHAuthKeys}, nil)

	// Create chains for both device-wide ACLs as well as for application ACLs.
	// Link them from top-level chains, with app ACLs always preceding device ACLs.
	// Do this only for chains which are actually used.
	usedChains := map[iptables.Chain]struct{ devACLs, appACLs bool }{
		{Table: "raw", ChainName: "PREROUTING"}:     {devACLs: false, appACLs: true},
		{Table: "filter", ChainName: "INPUT"}:       {devACLs: true, appACLs: true},
		{Table: "filter", ChainName: "FORWARD"}:     {devACLs: true, appACLs: true},
		{Table: "mangle", ChainName: "PREROUTING"}:  {devACLs: true, appACLs: true},
		{Table: "mangle", ChainName: "FORWARD"}:     {devACLs: true, appACLs: false},
		{Table: "mangle", ChainName: "POSTROUTING"}: {devACLs: false, appACLs: true},
		{Table: "mangle", ChainName: "OUTPUT"}:      {devACLs: true, appACLs: false},
		{Table: "nat", ChainName: "PREROUTING"}:     {devACLs: false, appACLs: true},
		{Table: "nat", ChainName: "POSTROUTING"}:    {devACLs: false, appACLs: true},
	}

	const (
		appTraverseRuleLabel = "Traverse application ACLs"
		devTraverseRuleLabel = "Traverse device-wide ACLs"
	)
	for chain, usedFor := range usedChains {
		for _, forIPv6 := range []bool{true, false} {
			subgraph := intendedIPv4ACLs
			if forIPv6 {
				subgraph = intendedIPv6ACLs
			}
			if usedFor.appACLs {
				subgraph.PutItem(iptables.Chain{
					ChainName: chain.ChainName + iptables.AppChainSuffix,
					Table:     chain.Table,
					ForIPv6:   forIPv6,
				}, nil)
				var appliedBefore []string
				if usedFor.devACLs {
					appliedBefore = append(appliedBefore, devTraverseRuleLabel)
				}
				subgraph.PutItem(iptables.Rule{
					RuleLabel:     appTraverseRuleLabel,
					Table:         chain.Table,
					ChainName:     chain.ChainName,
					ForIPv6:       forIPv6,
					AppliedBefore: appliedBefore,
					Target:        chain.ChainName + iptables.AppChainSuffix,
				}, nil)
			}
			if usedFor.devACLs {
				subgraph.PutItem(iptables.Chain{
					ChainName: chain.ChainName + iptables.DeviceChainSuffix,
					Table:     chain.Table,
					ForIPv6:   forIPv6,
				}, nil)
				subgraph.PutItem(iptables.Rule{
					RuleLabel: devTraverseRuleLabel,
					Table:     chain.Table,
					ChainName: chain.ChainName,
					ForIPv6:   forIPv6,
					Target:    chain.ChainName + iptables.DeviceChainSuffix,
				}, nil)
			}
		}
	}

	r.getIntendedFilterRules(gcp, dpc, clusterStatus, kubeUserServices, intendedIPv4ACLs, intendedIPv6ACLs)
	if withFlowlog || r.HVTypeKube {
		r.getIntendedMarkingRules(dpc, intendedIPv4ACLs, intendedIPv6ACLs, kubeUserServices)
	}
	return intendedACLs
}

// KubeACEEnabled checks if any Kubernetes user service has ACE (Authorized Cluster Endpoint) enabled
func (r *LinuxDpcReconciler) KubeACEEnabled(services types.KubeUserServices) bool {
	for _, service := range services.UserService {
		if service.ACEenabled {
			return true
		}
	}
	return false
}

// GetIntendedFilterRules is an exported version of getIntendedFilterRules for testing
func (r *LinuxDpcReconciler) GetIntendedFilterRules(gcp types.ConfigItemValueMap,
	dpc types.DevicePortConfig, clusterStatus types.EdgeNodeClusterStatus,
	services types.KubeUserServices, intendedIPv4ACLs, intendedIPv6ACLs dg.Graph) {
	r.getIntendedFilterRules(gcp, dpc, clusterStatus, services, intendedIPv4ACLs, intendedIPv6ACLs)
}

func (r *LinuxDpcReconciler) getIntendedFilterRules(gcp types.ConfigItemValueMap,
	dpc types.DevicePortConfig, clusterStatus types.EdgeNodeClusterStatus,
	services types.KubeUserServices, intendedIPv4ACLs, intendedIPv6ACLs dg.Graph) {
	// Prepare filter/INPUT rules.
	var inputV4Rules, inputV6Rules []iptables.Rule

	// Ports which are always blocked.
	block8080 := iptables.Rule{
		RuleLabel:   "Port 8080",
		MatchOpts:   []string{"-p", "tcp", "--dport", "8080"},
		Target:      "REJECT",
		TargetOpts:  []string{"--reject-with", "tcp-reset"},
		Description: "Port 8080 is always blocked",
	}
	inputV4Rules = append(inputV4Rules, block8080)
	inputV6Rules = append(inputV6Rules, block8080)

	// Allow Guacamole.
	const (
		localGuacamoleRuleLabel  = "Local Guacamole"
		remoteGuacamoleRuleLabel = "Remote Guacamole"
	)
	allowGuacamoleDescr := "Local Guacamole traffic is always allowed " +
		"(provides console and VDI services to running VMs and containers)"
	allowLocalGuacamoleV4 := iptables.Rule{
		RuleLabel:     localGuacamoleRuleLabel,
		MatchOpts:     []string{"-p", "tcp", "-s", "127.0.0.1", "-d", "127.0.0.1", "--dport", "4822"},
		Target:        "ACCEPT",
		AppliedBefore: []string{remoteGuacamoleRuleLabel},
		Description:   allowGuacamoleDescr,
	}
	allowLocalGuacamoleV6 := iptables.Rule{
		RuleLabel:     localGuacamoleRuleLabel,
		MatchOpts:     []string{"-p", "tcp", "-s", "::1", "-d", "::1", "--dport", "4822"},
		Target:        "ACCEPT",
		AppliedBefore: []string{remoteGuacamoleRuleLabel},
		Description:   allowGuacamoleDescr,
	}
	blockNonLocalGuacamole := iptables.Rule{
		RuleLabel:   remoteGuacamoleRuleLabel,
		MatchOpts:   []string{"-p", "tcp", "--dport", "4822"},
		Target:      "REJECT",
		TargetOpts:  []string{"--reject-with", "tcp-reset"},
		Description: "Block attempts to connect to Guacamole server from outside",
	}
	inputV4Rules = append(inputV4Rules, allowLocalGuacamoleV4, blockNonLocalGuacamole)
	inputV6Rules = append(inputV6Rules, allowLocalGuacamoleV6, blockNonLocalGuacamole)

	// Allow local access to node exporter metrics (port 9100)
	const (
		localMetricsRuleLabel  = "Local Node Exporter Metrics"
		remoteMetricsRuleLabel = "Remote Node Exporter Metrics"
	)
	allowLocalMetricsV4 := iptables.Rule{
		RuleLabel:     localMetricsRuleLabel,
		MatchOpts:     []string{"-p", "tcp", "-s", "127.0.0.1", "-d", "127.0.0.1", "--dport", "9100"},
		Target:        "ACCEPT",
		AppliedBefore: []string{remoteMetricsRuleLabel},
		Description:   "Allow local access to node exporter metrics",
	}
	allowLocalMetricsV6 := iptables.Rule{
		RuleLabel:     localMetricsRuleLabel,
		MatchOpts:     []string{"-p", "tcp", "-s", "::1", "-d", "::1", "--dport", "9100"},
		Target:        "ACCEPT",
		AppliedBefore: []string{remoteMetricsRuleLabel},
		Description:   "Allow local access to node exporter metrics",
	}
	blockRemoteMetrics := iptables.Rule{
		RuleLabel:   remoteMetricsRuleLabel,
		MatchOpts:   []string{"-p", "tcp", "--dport", "9100"},
		Target:      "REJECT",
		TargetOpts:  []string{"--reject-with", "tcp-reset"},
		Description: "Block remote access to node exporter metrics",
	}
	inputV4Rules = append(inputV4Rules, allowLocalMetricsV4, blockRemoteMetrics)
	inputV6Rules = append(inputV6Rules, allowLocalMetricsV6, blockRemoteMetrics)

	// Allow/block SSH access.
	gcpAllowSSH := gcp.GlobalValueString(types.SSHAuthorizedKeys) != ""
	sshRule := iptables.Rule{
		RuleLabel: "SSH Rule",
		MatchOpts: []string{"-p", "tcp", "--dport", "22"},
	}
	if gcpAllowSSH {
		sshRule.Target = "ACCEPT"
		sshRule.Description = "SSH access is allowed"
	} else {
		sshRule.Target = "REJECT"
		sshRule.TargetOpts = []string{"--reject-with", "tcp-reset"}
		sshRule.Description = "SSH access is not allowed by device config"
	}
	inputV4Rules = append(inputV4Rules, sshRule)
	inputV6Rules = append(inputV6Rules, sshRule)

	// Allow/block VNC access.
	const (
		localVNCRuleLabel  = "Local VNC"
		remoteVNCRuleLabel = "Remote VNC"
	)
	gcpAllowRemoteVNC := gcp.GlobalValueBool(types.AllowAppVnc)
	if !gcpAllowRemoteVNC {
		// Remote VNC rule applies to any VNC traffic (incl. local), meaning that Local VNC
		// rules must precede them to work correctly.
		allowLocalVNCv4 := iptables.Rule{
			RuleLabel: localVNCRuleLabel,
			MatchOpts: []string{"-p", "tcp", "-s", "127.0.0.1", "-d", "127.0.0.1",
				"--dport", "5900:5999"},
			Target:        "ACCEPT",
			AppliedBefore: []string{remoteVNCRuleLabel},
			Description:   "Local VNC traffic is always allowed",
		}
		allowLocalVNCv6 := iptables.Rule{
			RuleLabel: localVNCRuleLabel,
			MatchOpts: []string{"-p", "tcp", "-s", "::1", "-d", "::1",
				"--dport", "5900:5999"},
			Target:        "ACCEPT",
			AppliedBefore: []string{remoteVNCRuleLabel},
			Description:   "Local VNC traffic is always allowed",
		}
		inputV4Rules = append(inputV4Rules, allowLocalVNCv4)
		inputV6Rules = append(inputV6Rules, allowLocalVNCv6)
	}
	remoteVNCRule := iptables.Rule{
		RuleLabel: remoteVNCRuleLabel,
		MatchOpts: []string{"-p", "tcp", "--dport", "5900:5999"},
	}
	if gcpAllowRemoteVNC {
		remoteVNCRule.Target = "ACCEPT"
		remoteVNCRule.Description = "VNC traffic is allowed"
	} else {
		remoteVNCRule.Target = "REJECT"
		remoteVNCRule.TargetOpts = []string{"--reject-with", "tcp-reset"}
		remoteVNCRule.Description = "VNC traffic originating from outside is not allowed"
	}
	inputV4Rules = append(inputV4Rules, remoteVNCRule)
	inputV6Rules = append(inputV6Rules, remoteVNCRule)

	// Allow traffic initiated by DHCP server to enter the device.
	// Most of the DHCP communication is initiated by the client and replies
	// from the server will be accepted by the allowEstablishedConn rule.
	// But in some rare cases, such as DHCPFORCERENEW defined in RFC 3203,
	// the server might be the initiator and we should allow it.
	dhcpRule := iptables.Rule{
		RuleLabel:   "Allow DHCP",
		MatchOpts:   []string{"-p", "udp", "--dport", "bootps:bootpc"},
		Target:      "ACCEPT",
		Description: "Allow traffic initiated by DHCP server to enter the device",
	}
	inputV4Rules = append(inputV4Rules, dhcpRule)

	// Allow ICMP echo request to enter the device from outside.
	icmpRule := iptables.Rule{
		RuleLabel:   "Allow ICMP echo request",
		MatchOpts:   []string{"-p", "icmp", "--icmp-type", "echo-request"},
		Target:      "ACCEPT",
		Description: "Allow ICMP echo request to enter the device from outside",
	}
	inputV4Rules = append(inputV4Rules, icmpRule)
	icmpV6Rule := icmpRule // copy
	icmpV6Rule.MatchOpts = []string{"-p", "ipv6-icmp"}
	inputV6Rules = append(inputV6Rules, icmpV6Rule)

	clusterPort := dpc.LookupPortByLogicallabel(clusterStatus.ClusterInterface)
	if r.HVTypeKube && clusterPort != nil && !clusterPort.InvalidConfig &&
		clusterPort.IfName != "" && clusterStatus.ClusterIPPrefix != nil {
		// LookupExtInterface in k3s/pkg/agent/flannel/flannel.go will pick
		// whatever the first IP address is returned by netlink for the cluster
		// interface. This means that VXLAN tunnel may be configured with EVE
		// mgmt/app-shared IP instead of the cluster IP and we have to allow it.
		// Therefore, we do not use "-d" filter for the VXLAN rule.
		vxlanRule := iptables.Rule{
			RuleLabel: "Allow VXLAN",
			MatchOpts: []string{"-p", "udp", "-i", clusterPort.IfName,
				"--dport", "8472"},
			Target: "ACCEPT",
			Description: "Allow VXLAN-encapsulated traffic to enter the device " +
				"via cluster interface",
		}
		etcdRule := iptables.Rule{
			RuleLabel: "Allow etcd traffic",
			MatchOpts: []string{"-p", "tcp", "-i", clusterPort.IfName,
				"-d", clusterStatus.ClusterIPPrefix.IP.String(), "--dport", "2379:2380"},
			Target:      "ACCEPT",
			Description: "Allow etcd client and server-to-server communication",
		}
		k3sMetricsRule := iptables.Rule{
			RuleLabel: "Allow K3s metrics",
			MatchOpts: []string{"-p", "tcp", "-i", clusterPort.IfName,
				"-d", clusterStatus.ClusterIPPrefix.IP.String(), "--dport", "10250"},
			Target: "ACCEPT",
			Description: "Allow traffic carrying K3s metrics to enter the device " +
				"via cluster interface",
		}
		k3sAPIServerRule := iptables.Rule{
			RuleLabel: "Allow K3s API requests",
			MatchOpts: []string{"-p", "tcp", "-i", clusterPort.IfName,
				"-d", clusterStatus.ClusterIPPrefix.IP.String(), "--dport", "6443"},
			Target: "ACCEPT",
			Description: "Allow K3s API requests to enter the device " +
				"via cluster interface",
		}
		clusterStatusRule := iptables.Rule{
			RuleLabel: "Allow access to Cluster Status",
			MatchOpts: []string{"-p", "tcp", "-i", clusterPort.IfName,
				"-d", clusterStatus.ClusterIPPrefix.IP.String(), "--dport", "12346"},
			Target:      "ACCEPT",
			Description: "Allow access to Cluster Status via cluster interface",
		}
		forIPv6 := clusterStatus.ClusterIPPrefix.IP.To4() == nil
		if forIPv6 {
			inputV6Rules = append(inputV6Rules, vxlanRule, etcdRule,
				k3sMetricsRule, k3sAPIServerRule, clusterStatusRule)
		} else {
			inputV4Rules = append(inputV4Rules, vxlanRule, etcdRule,
				k3sMetricsRule, k3sAPIServerRule, clusterStatusRule)
		}
	}

	// When the kubernetes has Authorized Cluster Endpoint (ACE) enabled, accept the api-server port 6443
	if r.HVTypeKube && r.KubeACEEnabled(services) {
		k3sAPIServerRule := iptables.Rule{
			RuleLabel:   "Allow K3s API Servier requests",
			MatchOpts:   []string{"-p", "tcp", "--dport", "6443"},
			Target:      "ACCEPT",
			Description: "Allow K3s API Server requests to enter the device",
		}
		forIPv6 := clusterStatus.ClusterIPPrefix != nil && clusterStatus.ClusterIPPrefix.IP.To4() == nil
		if forIPv6 {
			inputV6Rules = append(inputV6Rules, k3sAPIServerRule)
		} else {
			inputV4Rules = append(inputV4Rules, k3sAPIServerRule)
		}
	}

	// Allow all traffic that belongs to an already established connection.
	allowEstablishedConn := iptables.Rule{
		RuleLabel:   "Allow established connection",
		MatchOpts:   []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"},
		Target:      "ACCEPT",
		Description: "Allow all traffic that belongs to an already established connection",
	}
	allowEstablishedV4Conn := allowEstablishedConn
	for _, inputV4Rule := range inputV4Rules {
		allowEstablishedV4Conn.AppliedBefore = append(allowEstablishedV4Conn.AppliedBefore,
			inputV4Rule.RuleLabel)
	}
	inputV4Rules = append(inputV4Rules, allowEstablishedV4Conn)
	allowEstablishedV6Conn := allowEstablishedConn
	for _, inputV6Rule := range inputV6Rules {
		allowEstablishedV6Conn.AppliedBefore = append(allowEstablishedV6Conn.AppliedBefore,
			inputV6Rule.RuleLabel)
	}
	inputV6Rules = append(inputV6Rules, allowEstablishedV6Conn)

	// Drop all input traffic not matched by any rule above.
	var defaultDropRules []iptables.Rule
	for _, port := range dpc.Ports {
		if port.IfName == "" || !port.IsL3Port || port.InvalidConfig {
			continue
		}
		defaultInputDrop := iptables.Rule{
			RuleLabel: fmt.Sprintf("Default input drop for port %s", port.IfName),
			MatchOpts: []string{"-i", port.IfName},
			Target:    "DROP",
			Description: fmt.Sprintf("Drop input traffic received via port %s "+
				"which is not explicitly allowed", port.IfName),
		}
		for i := range inputV4Rules {
			inputV4Rules[i].AppliedBefore = append(inputV4Rules[i].AppliedBefore,
				defaultInputDrop.RuleLabel)
		}
		for i := range inputV6Rules {
			inputV6Rules[i].AppliedBefore = append(inputV6Rules[i].AppliedBefore,
				defaultInputDrop.RuleLabel)
		}
		defaultDropRules = append(defaultDropRules, defaultInputDrop)
	}
	for _, rule := range defaultDropRules {
		inputV4Rules = append(inputV4Rules, rule)
		inputV6Rules = append(inputV6Rules, rule)
	}

	// Submit filtering INPUT rules.
	for _, inputV4Rule := range inputV4Rules {
		inputV4Rule.ChainName = "INPUT" + iptables.DeviceChainSuffix
		inputV4Rule.Table = "filter"
		inputV4Rule.ForIPv6 = false
		intendedIPv4ACLs.PutItem(inputV4Rule, nil)
	}
	for _, inputV6Rule := range inputV6Rules {
		inputV6Rule.ChainName = "INPUT" + iptables.DeviceChainSuffix
		inputV6Rule.Table = "filter"
		inputV6Rule.ForIPv6 = true
		intendedIPv6ACLs.PutItem(inputV6Rule, nil)
	}

	// Deny traffic hoping from one device port to another (e.g. from eth0 to eth1).
	// Only switch NIs with multiple ports allows traffic forwarding between ports.
	// Create a separate chains for this.
	const denyL3FwdChain = "DENY-L3-FORWARD"
	const denyL3FwdOutChain = denyL3FwdChain + "-OUTPUT"
	for _, chain := range []string{denyL3FwdChain, denyL3FwdOutChain} {
		intendedIPv4ACLs.PutItem(iptables.Chain{
			ChainName: chain,
			Table:     "filter",
			ForIPv6:   false,
		}, nil)
		intendedIPv6ACLs.PutItem(iptables.Chain{
			ChainName: chain,
			Table:     "filter",
			ForIPv6:   true,
		}, nil)
	}
	traverseL3FwdChain := iptables.Rule{
		RuleLabel:   "Traverse " + denyL3FwdChain,
		Table:       "filter",
		ChainName:   "FORWARD" + iptables.DeviceChainSuffix,
		Target:      denyL3FwdChain,
		Description: "Traverse rules used to prevent routing from one NIC to another",
	}
	intendedIPv4ACLs.PutItem(traverseL3FwdChain, nil)
	traverseL3FwdChainV6 := traverseL3FwdChain
	traverseL3FwdChainV6.ForIPv6 = true
	intendedIPv6ACLs.PutItem(traverseL3FwdChainV6, nil)
	for _, port := range dpc.Ports {
		if port.IfName == "" || !port.IsL3Port || port.InvalidConfig {
			continue
		}
		ruleLabel := fmt.Sprintf("Deny routing from %s to another NIC", port.IfName)
		portInputRule := iptables.Rule{
			RuleLabel:   ruleLabel,
			Table:       "filter",
			ChainName:   denyL3FwdChain,
			MatchOpts:   []string{"-i", port.IfName},
			Target:      denyL3FwdOutChain,
			Description: ruleLabel,
		}
		intendedIPv4ACLs.PutItem(portInputRule, nil)
		portInputRuleV6 := portInputRule
		portInputRuleV6.ForIPv6 = true
		intendedIPv6ACLs.PutItem(portInputRuleV6, nil)
		ruleLabel = fmt.Sprintf("Deny routing to %s from another NIC", port.IfName)
		portOutputRule := iptables.Rule{
			RuleLabel:   ruleLabel,
			Table:       "filter",
			ChainName:   denyL3FwdOutChain,
			MatchOpts:   []string{"-o", port.IfName},
			Target:      "DROP",
			Description: ruleLabel,
		}
		intendedIPv4ACLs.PutItem(portOutputRule, nil)
		portOutputRuleV6 := portOutputRule
		portOutputRuleV6.ForIPv6 = true
		intendedIPv6ACLs.PutItem(portOutputRuleV6, nil)
	}
}

// Marking rules are only used if at least one Network instance has flow logging enabled.
func (r *LinuxDpcReconciler) getIntendedMarkingRules(dpc types.DevicePortConfig,
	intendedIPv4ACLs, intendedIPv6ACLs dg.Graph, kubeUserServices types.KubeUserServices) {
	// Mark ingress control-flow traffic.
	// For connections originating from outside we use App ID = 0.
	markSSHAndGuacamole := iptables.Rule{
		RuleLabel:   "SSH and Guacamole mark",
		MatchOpts:   []string{"-p", "tcp", "--match", "multiport", "--dports", "22,4822"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_http_ssh_guacamole")},
		Description: "Mark ingress SSH and Guacamole traffic",
	}
	markVnc := iptables.Rule{
		RuleLabel:   "VNC mark",
		MatchOpts:   []string{"-p", "tcp", "--match", "multiport", "--dports", "5900:5999"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_vnc")},
		Description: "Mark ingress VNC traffic",
	}
	markIcmpV4 := iptables.Rule{
		RuleLabel:   "ICMP mark",
		MatchOpts:   []string{"-p", "icmp"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_icmp")},
		Description: "Mark ingress ICMP traffic",
	}
	markIcmpV6 := iptables.Rule{
		RuleLabel:   "ICMPv6 traffic",
		MatchOpts:   []string{"-p", "icmpv6"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_icmp")},
		Description: "Mark ingress ICMPv6 traffic",
	}
	markDhcp := iptables.Rule{
		RuleLabel:   "DHCP mark",
		MatchOpts:   []string{"-p", "udp", "--dport", "bootps:bootpc"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_dhcp")},
		Description: "Mark ingress DHCP traffic",
	}

	protoMarkV4Rules := []iptables.Rule{
		markSSHAndGuacamole, markVnc, markIcmpV4, markDhcp,
	}
	protoMarkV6Rules := []iptables.Rule{
		markSSHAndGuacamole, markVnc, markIcmpV6,
	}

	if r.HVTypeKube {
		protoMarkV4Rules = append(protoMarkV4Rules, defaultKubernetesIptablesRules()...)
		// Add Marking rules for Kubernetes user services.
		// The reason kubernetes service ports need to add to marking rules and not adding
		// to the Input rules in getIntendedFilterRules() is that the Kubernetes kube-proxy
		// will install the service ports and using DNAT rules to forwarding to the service
		// destination. We only need to enable the mangle table marking rules to allow it.
		protoMarkV4Rules = append(protoMarkV4Rules, r.AddKubeServiceRules(kubeUserServices)...)
	}

	// Do not overwrite mark that was already added be rules from zedrouter
	// for application traffic.
	skipMarkedFlowRule := iptables.Rule{
		RuleLabel: "Skip marked ingress",
		ChainName: "PREROUTING" + iptables.DeviceChainSuffix,
		Table:     "mangle",
		MatchOpts: []string{"-m", "mark", "!", "--mark", "0"},
		Target:    "RETURN",
	}
	for _, markV4Rule := range protoMarkV4Rules {
		skipMarkedFlowRule.AppliedBefore = append(skipMarkedFlowRule.AppliedBefore,
			markV4Rule.RuleLabel)
	}
	intendedIPv4ACLs.PutItem(skipMarkedFlowRule, nil)
	restoreConnmarkRule := iptables.Rule{
		RuleLabel:     "Restore ingress mark",
		ChainName:     "PREROUTING" + iptables.DeviceChainSuffix,
		Table:         "mangle",
		Target:        "CONNMARK",
		TargetOpts:    []string{"--restore-mark"},
		AppliedBefore: []string{skipMarkedFlowRule.RuleLabel},
	}
	intendedIPv4ACLs.PutItem(restoreConnmarkRule, nil)
	// The same for IPv6:
	skipMarkedFlowRule.ForIPv6 = true
	skipMarkedFlowRule.AppliedBefore = nil
	for _, markV6Rule := range protoMarkV6Rules {
		skipMarkedFlowRule.AppliedBefore = append(skipMarkedFlowRule.AppliedBefore,
			markV6Rule.RuleLabel)
	}
	intendedIPv6ACLs.PutItem(skipMarkedFlowRule, nil)
	restoreConnmarkRule.ForIPv6 = true
	intendedIPv6ACLs.PutItem(restoreConnmarkRule, nil)

	// Mark ingress traffic not matched by the rules above with the DROP action.
	// Create a separate chain for marking.
	const dropIngressChain = "DROP-INGRESS"
	intendedIPv4ACLs.PutItem(iptables.Chain{
		ChainName: dropIngressChain,
		Table:     "mangle",
		ForIPv6:   false,
	}, nil)
	intendedIPv6ACLs.PutItem(iptables.Chain{
		ChainName: dropIngressChain,
		Table:     "mangle",
		ForIPv6:   true,
	}, nil)
	ingressDefDrop := iptables.GetConnmark(0, iptables.DefaultDropAceID, false, true)
	ingressDefDropStr := strconv.FormatUint(uint64(ingressDefDrop), 10)
	ingressDefDropRules := []iptables.Rule{
		{
			RuleLabel:  "Restore ingress mark",
			Target:     "CONNMARK",
			TargetOpts: []string{"--restore-mark"},
		},
		{
			RuleLabel: "Accept marked ingress",
			MatchOpts: []string{"-m", "mark", "!", "--mark", "0"},
			Target:    "ACCEPT",
		},
		{
			RuleLabel:  "Default ingress mark",
			Target:     "MARK",
			TargetOpts: []string{"--set-mark", ingressDefDropStr},
		},
		{
			RuleLabel:  "Save ingress mark",
			Target:     "CONNMARK",
			TargetOpts: []string{"--save-mark"},
		},
	}
	for i, rule := range ingressDefDropRules {
		rule.ChainName = dropIngressChain
		rule.Table = "mangle"
		// Keep exact order.
		if i < len(ingressDefDropRules)-1 {
			rule.AppliedBefore = []string{ingressDefDropRules[i+1].RuleLabel}
		}
		rule.ForIPv6 = false
		intendedIPv4ACLs.PutItem(rule, nil)
		rule.ForIPv6 = true
		intendedIPv6ACLs.PutItem(rule, nil)
	}
	// Send everything UNMARKED coming through a device port to "drop-ingress" chain,
	// i.e. these rules are below protoMarkV4Rules/protoMarkV6Rules
	var dropMarkRules []iptables.Rule
	for _, port := range dpc.Ports {
		if port.IfName == "" || !port.IsL3Port || port.InvalidConfig {
			continue
		}
		dropIngressRule := iptables.Rule{
			RuleLabel: fmt.Sprintf("Ingress from %s", port.IfName),
			MatchOpts: []string{"-i", port.IfName},
			Target:    dropIngressChain,
		}
		dropMarkRules = append(dropMarkRules, dropIngressRule)
	}

	// Submit rules marking ingress traffic.
	for _, markV4Rule := range protoMarkV4Rules {
		markV4Rule.ChainName = "PREROUTING" + iptables.DeviceChainSuffix
		markV4Rule.Table = "mangle"
		markV4Rule.ForIPv6 = false
		for _, dropMarkRule := range dropMarkRules {
			markV4Rule.AppliedBefore = append(markV4Rule.AppliedBefore, dropMarkRule.RuleLabel)
		}
		intendedIPv4ACLs.PutItem(markV4Rule, nil)
	}
	for _, markV6Rule := range protoMarkV6Rules {
		markV6Rule.ChainName = "PREROUTING" + iptables.DeviceChainSuffix
		markV6Rule.Table = "mangle"
		markV6Rule.ForIPv6 = true
		for _, dropMarkRule := range dropMarkRules {
			markV6Rule.AppliedBefore = append(markV6Rule.AppliedBefore, dropMarkRule.RuleLabel)
		}
		intendedIPv6ACLs.PutItem(markV6Rule, nil)
	}
	for _, markRule := range dropMarkRules {
		markRule.ChainName = "PREROUTING" + iptables.DeviceChainSuffix
		markRule.Table = "mangle"
		markRule.ForIPv6 = false
		intendedIPv4ACLs.PutItem(markRule, nil)
		markRule.ForIPv6 = true
		intendedIPv6ACLs.PutItem(markRule, nil)
	}

	// Mark all un-marked local traffic generated by local services.
	outputRules := []iptables.Rule{
		{
			RuleLabel:  "Restore egress mark",
			Target:     "CONNMARK",
			TargetOpts: []string{"--restore-mark"},
		},
		{
			RuleLabel: "Accept marked egress",
			MatchOpts: []string{"-m", "mark", "!", "--mark", "0"},
			Target:    "ACCEPT",
		},
		{
			RuleLabel:  "Default egress mark",
			Target:     "MARK",
			TargetOpts: []string{"--set-mark", controlProtoMark("out_all")},
		},
		{
			RuleLabel:  "Save egress mark",
			Target:     "CONNMARK",
			TargetOpts: []string{"--save-mark"},
		},
	}
	for i, outputRule := range outputRules {
		outputRule.ChainName = "OUTPUT" + iptables.DeviceChainSuffix
		outputRule.Table = "mangle"
		// Keep exact order.
		if i < len(outputRules)-1 {
			outputRule.AppliedBefore = []string{outputRules[i+1].RuleLabel}
		}
		outputRule.ForIPv6 = false
		intendedIPv4ACLs.PutItem(outputRule, nil)
		outputRule.ForIPv6 = true
		intendedIPv6ACLs.PutItem(outputRule, nil)
	}
}

func controlProtoMark(protoName string) string {
	mark := iptables.ControlProtocolMarkingIDMap[protoName]
	return strconv.FormatUint(uint64(mark), 10)
}

func defaultKubernetesIptablesRules() []iptables.Rule {
	// Allow all traffic from Kubernetes pods to Kubernetes services.
	// Note that traffic originating from another node is already D-NATed
	// and will get marked with the kube_pod mark.
	markKubeSvc := iptables.Rule{
		RuleLabel:   "Kubernetes service mark",
		MatchOpts:   []string{"-s", kubePodCIDR.String(), "-d", kubeSvcCIDR.String()},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("kube_svc")},
		Description: "Mark traffic from Kubernetes pods to Kubernetes services",
	}

	// Allow all traffic from the Kubernetes network to pods or external endpoints.
	markKubePod := iptables.Rule{
		RuleLabel:   "Kubernetes pod mark",
		MatchOpts:   []string{"-s", kubePodCIDR.String()},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("kube_pod")},
		Description: "Mark all traffic directly forwarded between Kubernetes pods",
	}

	// Allow all DNS requests made from the Kubernetes network.
	markKubeDNS := iptables.Rule{
		RuleLabel:   "Kubernetes DNS mark",
		MatchOpts:   []string{"-p", "udp", "--dport", "domain"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("kube_dns")},
		Description: "Mark DNS requests made from the Kubernetes network",
	}

	// XXX some kube cluster rules
	markK3s := iptables.Rule{
		RuleLabel:   "K3s mark",
		MatchOpts:   []string{"-p", "tcp", "--dport", "6443"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_k3s")},
		Description: "Mark K3S API server traffic for kubernetes",
	}

	markEtcd := iptables.Rule{
		RuleLabel:   "Etcd mark",
		MatchOpts:   []string{"-p", "tcp", "--dport", "2379:2381"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_etcd")},
		Description: "Mark K3S HA with embedded etcd traffic for kubernetes",
	}

	markFlannel := iptables.Rule{
		RuleLabel:   "Flannel mark",
		MatchOpts:   []string{"-p", "udp", "--dport", "8472"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_flannel")},
		Description: "Mark K3S with Flannel VxLan traffic for kubernetes",
	}

	markMetrics := iptables.Rule{
		RuleLabel:   "Metrics mark",
		MatchOpts:   []string{"-p", "tcp", "--dport", "10250"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_metrics")},
		Description: "Mark K3S metrics traffic for kubernetes",
	}

	markLongHornWebhook := iptables.Rule{
		RuleLabel:   "Longhorn Webhook",
		MatchOpts:   []string{"-p", "tcp", "--dport", "9501:9503"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_lhweb")},
		Description: "Mark K3S HA with longhorn webhook for kubernetes",
	}
	markLongHornInstMgr := iptables.Rule{
		RuleLabel:   "Longhorn Instance Manager",
		MatchOpts:   []string{"-p", "tcp", "--dport", "8500:8501"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_lhinstmgr")},
		Description: "Mark K3S HA with longhorn instance manager for kubernetes",
	}
	markIscsi := iptables.Rule{
		RuleLabel:   "Iscsi",
		MatchOpts:   []string{"-p", "tcp", "--dport", "3260"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_iscsi")},
		Description: "Mark K3S HA with longhorn iscsi for kubernetes",
	}
	markNFS := iptables.Rule{
		RuleLabel:   "NFS",
		MatchOpts:   []string{"-p", "tcp", "--dport", "2049"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_nfs")},
		Description: "Mark K3S HA with longhorn nfs for kubernetes",
	}
	markClusterStatus := iptables.Rule{ // cluster bootstrap status
		RuleLabel:   "EncBootstrap",
		MatchOpts:   []string{"-p", "tcp", "--dport", "12346"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", controlProtoMark("in_cluster_status")},
		Description: "Mark EdgeNode Cluster bootstrap status traffic",
	}

	return []iptables.Rule{
		markKubeDNS,
		markKubeSvc,
		markKubePod,
		markK3s,
		markEtcd,
		markFlannel,
		markMetrics,
		markLongHornWebhook,
		markLongHornInstMgr,
		markIscsi,
		markNFS,
		markClusterStatus,
	}
}

// AddKubeServiceRules creates iptables rules for Kubernetes services and ingresses
func (r *LinuxDpcReconciler) AddKubeServiceRules(kubeUserServices types.KubeUserServices) []iptables.Rule {
	var rules []iptables.Rule

	// 1. Create TCP rules for nodePort services and LoadBalancer services
	// First, collect TCP LoadBalancer services with IPs for IP-specific rules

	// tcpLoadBalancerIPRules is used to track TCP LoadBalancer services with specific IPs
	// as the first key of the map, and the second keys are the ports associated with that IP.
	tcpLoadBalancerIPRules := make(map[string]map[string]struct{}) // map[ip]map[port]struct{}

	// Track NodePort TCP ports and LoadBalancer TCP ports without IPs
	tcpPortsMap := make(map[string]bool)

	for _, svc := range kubeUserServices.UserService {
		if svc.Protocol == "TCP" {
			if svc.ACEenabled { // this is handled in the interface filter section
				continue
			}
			// Handle NodePort services
			if svc.Type == "NodePort" && svc.NodePort > 0 {
				tcpPortsMap[strconv.Itoa(int(svc.NodePort))] = true
			} else if svc.Type == "LoadBalancer" && svc.Port > 0 {
				portStr := strconv.Itoa(int(svc.Port))
				// For LoadBalancer with IP, create IP-specific rules
				if svc.LoadBalancerIP == "" {
					// For LoadBalancer without IP, add to generic port list
					tcpPortsMap[portStr] = true
					continue
				}

				// For LoadBalancer with IP, ensure the inner map exists
				if _, exists := tcpLoadBalancerIPRules[svc.LoadBalancerIP]; !exists {
					tcpLoadBalancerIPRules[svc.LoadBalancerIP] = make(map[string]struct{})
				}

				// Add port to this IP's map
				tcpLoadBalancerIPRules[svc.LoadBalancerIP][portStr] = struct{}{}
			}
		}
	}

	// Create IP-specific rules for TCP LoadBalancer services
	ruleIndex := 0
	for ip, ports := range tcpLoadBalancerIPRules {
		var tcpPorts []string
		for port := range ports {
			tcpPorts = append(tcpPorts, port)
		}

		// If there are ports for this IP
		if len(tcpPorts) > 0 {
			markTCPSvcPortIP := iptables.Rule{
				RuleLabel:   fmt.Sprintf("KubeSvcPortTCP_IP_%d", ruleIndex),
				MatchOpts:   []string{"-p", "tcp", "-d", ip, "--match", "multiport", "--dports", strings.Join(tcpPorts, ",")},
				Target:      "CONNMARK",
				TargetOpts:  []string{"--set-mark", controlProtoMark("in_tcp_svc_port")},
				Description: fmt.Sprintf("Mark Kubernetes TCP service port traffic for LoadBalancer IP %s", ip),
			}
			rules = append(rules, markTCPSvcPortIP)
			ruleIndex++
		}
	}

	// Create generic rule for TCP NodePorts and LoadBalancer services without IPs
	if len(tcpPortsMap) > 0 {
		var tcpPorts []string
		for port := range tcpPortsMap {
			tcpPorts = append(tcpPorts, port)
		}

		markTCPSvcPort := iptables.Rule{
			RuleLabel:   "KubeSvcPortTCP",
			MatchOpts:   []string{"-p", "tcp", "--match", "multiport", "--dports", strings.Join(tcpPorts, ",")},
			Target:      "CONNMARK",
			TargetOpts:  []string{"--set-mark", controlProtoMark("in_tcp_svc_port")},
			Description: "Mark Kubernetes TCP service port traffic",
		}
		rules = append(rules, markTCPSvcPort)
	}

	// 2. Create UDP rules for nodePort services and LoadBalancer services
	// First, collect UDP LoadBalancer services with IPs for IP-specific rules

	// udpLoadBalancerIPRules is used to track UDP LoadBalancer services with specific IPs
	// as the first key of the map, and the second keys are the ports associated with that IP.
	udpLoadBalancerIPRules := make(map[string]map[string]struct{}) // map[ip]map[port]struct{}

	// Track NodePort UDP ports and LoadBalancer UDP ports without IPs
	udpPortsMap := make(map[string]bool)

	for _, svc := range kubeUserServices.UserService {
		if svc.Protocol == "UDP" {
			// Handle NodePort services
			if svc.Type == "NodePort" && svc.NodePort > 0 {
				udpPortsMap[strconv.Itoa(int(svc.NodePort))] = true
			} else if svc.Type == "LoadBalancer" && svc.Port > 0 {
				// For LoadBalancer with IP, create IP-specific rules
				if svc.LoadBalancerIP != "" {
					portStr := strconv.Itoa(int(svc.Port))

					// Initialize map for this IP if it doesn't exist
					if _, exists := udpLoadBalancerIPRules[svc.LoadBalancerIP]; !exists {
						udpLoadBalancerIPRules[svc.LoadBalancerIP] = make(map[string]struct{})
					}

					// Add port to this IP's map
					udpLoadBalancerIPRules[svc.LoadBalancerIP][portStr] = struct{}{}
				} else {
					// For LoadBalancer without IP, add to generic port list
					udpPortsMap[strconv.Itoa(int(svc.Port))] = true
				}
			}
		}
	}

	// Create IP-specific rules for UDP LoadBalancer services
	ruleIndex = 0
	for ip, ports := range udpLoadBalancerIPRules {
		var udpPorts []string
		for port := range ports {
			udpPorts = append(udpPorts, port)
		}

		// If there are ports for this IP
		if len(udpPorts) > 0 {
			markUDPSvcPortIP := iptables.Rule{
				RuleLabel:   fmt.Sprintf("KubeSvcPortUDP_IP_%d", ruleIndex),
				MatchOpts:   []string{"-p", "udp", "-d", ip, "--match", "multiport", "--dports", strings.Join(udpPorts, ",")},
				Target:      "CONNMARK",
				TargetOpts:  []string{"--set-mark", controlProtoMark("in_udp_svc_port")},
				Description: fmt.Sprintf("Mark Kubernetes UDP service port traffic for LoadBalancer IP %s", ip),
			}
			rules = append(rules, markUDPSvcPortIP)
			ruleIndex++
		}
	}

	// Create generic rule for UDP NodePorts and LoadBalancer services without IPs
	if len(udpPortsMap) > 0 {
		var udpPorts []string
		for port := range udpPortsMap {
			udpPorts = append(udpPorts, port)
		}

		markUDPSvcPort := iptables.Rule{
			RuleLabel:   "KubeSvcPortUDP",
			MatchOpts:   []string{"-p", "udp", "--match", "multiport", "--dports", strings.Join(udpPorts, ",")},
			Target:      "CONNMARK",
			TargetOpts:  []string{"--set-mark", controlProtoMark("in_udp_svc_port")},
			Description: "Mark Kubernetes UDP service port traffic",
		}
		rules = append(rules, markUDPSvcPort)
	}

	// 3. Create rules for HTTP and HTTPS ingresses
	// Track which protocols are used and collect unique ingress IPs
	httpIngressIPs := make(map[string]bool)
	httpsIngressIPs := make(map[string]bool)
	var hasHTTPNoIP bool
	var hasHTTPSNoIP bool

	// Collect information about ingresses, unique IPs and protocols
	// Two cases, with IP and protocol or the protocol only for non-loadBalancer services
	for _, ing := range kubeUserServices.UserIngress {
		// Only process ingress IPs for LoadBalancer services
		// For NodePort types, the addresses will be cluster-prefixes which we use 10.244.244.0
		// private addresses, and user may not have access to them.
		if ing.ServiceType == corev1.ServiceTypeLoadBalancer {
			// Process IPs for LoadBalancer
			for _, ip := range ing.IngressIP {
				if ip == "" {
					continue
				}
				if ing.Protocol == "http" {
					httpIngressIPs[ip] = true
				} else { // https
					httpsIngressIPs[ip] = true
				}
			}
		} else if ing.Protocol == "http" {
			// For NodePort HTTP, we don't track IPs, just mark the port
			hasHTTPNoIP = true
		} else if ing.Protocol == "https" {
			// For NodePort HTTPS, we don't track IPs, just mark the port
			hasHTTPSNoIP = true
		}
	}

	// Add HTTP ingress rules
	if len(httpIngressIPs) > 0 {
		// Create one rule per unique ingress IP for HTTP
		ruleIndex := 0
		for ingressIP := range httpIngressIPs {
			markHTTPIngressIP := iptables.Rule{
				RuleLabel:   fmt.Sprintf("KubeIngressHTTP_IP_%d", ruleIndex),
				MatchOpts:   []string{"-p", "tcp", "-d", ingressIP, "--dport", "80"},
				Target:      "CONNMARK",
				TargetOpts:  []string{"--set-mark", controlProtoMark("in_http_ingress")},
				Description: fmt.Sprintf("Mark Kubernetes HTTP ingress traffic for IP %s", ingressIP),
			}
			rules = append(rules, markHTTPIngressIP)
			ruleIndex++
		}
	}

	// Add generic HTTP ingress rule if no IngressIP (only one rule for port 80 without IPs)
	if hasHTTPNoIP {
		markHTTPIngress := iptables.Rule{
			RuleLabel:   "KubeIngressHTTP",
			MatchOpts:   []string{"-p", "tcp", "--dport", "80"},
			Target:      "CONNMARK",
			TargetOpts:  []string{"--set-mark", controlProtoMark("in_http_ingress")},
			Description: "Mark Kubernetes HTTP ingress traffic",
		}
		rules = append(rules, markHTTPIngress)
	}

	// Add HTTPS ingress rules
	if len(httpsIngressIPs) > 0 {
		// Create one rule per unique ingress IP for HTTPS
		ruleIndex := 0
		for ingressIP := range httpsIngressIPs {
			markHTTPSIngressIP := iptables.Rule{
				RuleLabel:   fmt.Sprintf("KubeIngressHTTPS_IP_%d", ruleIndex),
				MatchOpts:   []string{"-p", "tcp", "-d", ingressIP, "--dport", "443"},
				Target:      "CONNMARK",
				TargetOpts:  []string{"--set-mark", controlProtoMark("in_https_ingress")},
				Description: fmt.Sprintf("Mark Kubernetes HTTPS ingress traffic for IP %s", ingressIP),
			}
			rules = append(rules, markHTTPSIngressIP)
			ruleIndex++
		}
	}

	// Add generic HTTPS ingress rule if needed (only one rule for port 443 without IPs)
	if hasHTTPSNoIP {
		markHTTPSIngress := iptables.Rule{
			RuleLabel:   "KubeIngressHTTPS",
			MatchOpts:   []string{"-p", "tcp", "--dport", "443"},
			Target:      "CONNMARK",
			TargetOpts:  []string{"--set-mark", controlProtoMark("in_https_ingress")},
			Description: "Mark Kubernetes HTTPS ingress traffic",
		}
		rules = append(rules, markHTTPSIngress)
	}

	return rules
}

// GetLastArgs returns the last arguments used by the reconciler
func (r *LinuxDpcReconciler) GetLastArgs() Args {
	return r.lastArgs
}
