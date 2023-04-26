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

	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"

	generic "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// Device connectivity configuration is modeled using dependency graph (see libs/depgraph).
// Config graph with all sub-graphs and config item types used for Linux network stack:
//
//	+----------------------------------------------------------------------------------------+
//	|                                    DeviceConnectivity                                  |
//	|                                                                                        |
//	|   +--------------------------------------+    +------------------------------------+   |
//	|   |              PhysicalIO              |    |                Global              |   |
//	|   |                                      |    |                                    |   |
//	|   | +-----------+    +------------+      |    | +-------------+   +-------------+  |   |
//	|   | | PhysIf    |    | PhysIf     |      |    | | ResolvConf  |   | LocalIPRule |  |   |
//	|   | | (external)|    | (external) |  ... |    | | (singleton) |   | (singleton) |  |   |
//	|   | +-----------+    +------------+      |    | +-------------+   +-------------+  |   |
//	|   +--------------------------------------+    +------------------------------------+   |
//	|                                                                                        |
//	|   +--------------------------------------+    +------------------------------------+   |
//	|   |              LogicalIO (L2)          |    |               Wireless             |   |
//	|   |                                      |    |                                    |   |
//	|   |            +----------+              |    | +-------------+   +-------------+  |   |
//	|   |            | IOHandle | ...          |    | |    Wwan     |   |    Wlan     |  |   |
//	|   |            +----------+              |    | | (singleton) |   | (singleton) |  |   |
//	|   |       +------+      +------+         |    | +-------------+   +-------------+  |   |
//	|   |       | Vlan | ...  | Bond | ...     |    +------------------------------------+   |
//	|   |       +------+      +------+         |                                             |
//	|   +--------------------------------------+                                             |
//	|                                                                                        |
//	|  +----------------------------------------------------------------------------------+  |
//	|  |                                         L3                                       |  |
//	|  |                                                                                  |  |
//	|  |                                               +-------------------------------+  |  |
//	|  |                                               |            IPRules            |  |  |
//	|  |  +----------------------------------------+   |                               |  |  |
//	|  |  |               Adapters                 |   | +---------+  +----------+     |  |  |
//	|  |  |                                        |   | |SrcIPRule|  |SrcIPRule | ... |  |  |
//	|  |  | +---------+      +---------+           |   | +---------+  +----------+     |  |  |
//	|  |  | | Adapter |      | Adapter |  ...      |   +-------------------------------+  |  |
//	|  |  | +---------+      +---------+           |                                      |  |
//	|  |  | +------------+   +------------+        |   +-------------------------------+  |  |
//	|  |  | | DhcpClient |   | DhcpClient | ...    |   |            Routes             |  |  |
//	|  |  | +------------+   +------------+        |   |                               |  |  |
//	|  |  | +------------------------------------+ |   | +-------+  +-------+          |  |  |
//	|  |  | |            AdapterAddrs            | |   | | Route |  | Route | ...      |  |  |
//	|  |  | |                                    | |   | +-------+  +-------+          |  |  |
//	|  |  | |        +--------------+            | |   +-------------------------------+  |  |
//	|  |  | |        | AdapterAddrs | ...        | |                                      |  |
//	|  |  | |        |  (external)  |            | |   +-------------------------------+  |  |
//	|  |  | |        +--------------+            | |   |             ARPs              |  |  |
//	|  |  | +------------------------------------+ |   |                               |  |  |
//	|  |  +----------------------------------------+   | +-----+  +-----+              |  |  |
//	|  |                                               | | Arp |  | Arp | ...          |  |  |
//	|  |                                               | +-----+  +-----+              |  |  |
//	|  |                                               +-------------------------------+  |  |
//	|  |                                                                                  |  |
//	|  +----------------------------------------------------------------------------------+  |
//	|                                                                                        |
//	|  +----------------------------------------------------------------------------------+  |
//	|  |                                       ACLs                                       |  |
//	|  |                                                                                  |  |
//	|  |                                +---------------+                                 |  |
//	|  |                                |  SSHAuthKeys  |                                 |  |
//	|  |                                |  (singleton)  |                                 |  |
//	|  |                                +---------------+                                 |  |
//	|  |     +--------------------------------+    +--------------------------------+     |  |
//	|  |     |           IPv4Rules            |    |           IPv6Rules            |     |  |
//	|  |     |                                |    |                                |     |  |
//	|  |     |      +---------------+         |    |      +---------------+         |     |  |
//	|  |     |      | IptablesChain | ...     |    |      | IptablesChain | ...     |     |  |
//	|  |     |      +---------------+         |    |      +---------------+         |     |  |
//	|  |     |      +---------------+         |    |      +---------------+         |     |  |
//	|  |     |      | IptablesRule  | ...     |    |      | IptablesRule  | ...     |     |  |
//	|  |     |      +---------------+         |    |      +---------------+         |     |  |
//	|  |     +--------------------------------+    +--------------------------------+     |  |
//	|  +----------------------------------------------------------------------------------+  |
//	+----------------------------------------------------------------------------------------+
const (
	// GraphName : name of the graph with the managed state as a whole.
	GraphName = "DeviceConnectivity"
	// GlobalSG : name of the sub-graph with global configuration.
	GlobalSG = "Global"
	// PhysicalIoSG : name of the sub-graph with physical network interfaces.
	PhysicalIoSG = "PhysicalIO"
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

	prevArgs     Args
	prevStatus   ReconcileStatus
	radioSilence types.RadioSilence
}

type pendingReconcile struct {
	isPending   bool
	forSubGraph string
	reasons     []string
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
func (r *LinuxDpcReconciler) GetCurrentState() dg.GraphR {
	return r.currentState
}

// GetIntendedState : get the intended state (read-only).
// Exported only for unit-testing purposes.
func (r *LinuxDpcReconciler) GetIntendedState() dg.GraphR {
	return r.intendedState
}

func (r *LinuxDpcReconciler) init() (startWatcher func()) {
	r.Lock()
	if r.initialized {
		r.Log.Fatal("Already initialized")
	}
	registry := &reconciler.DefaultRegistry{}
	if err := generic.RegisterItems(r.Log, registry); err != nil {
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
					changed := r.updateCurrentPhysicalIO(r.prevArgs.DPC, r.prevArgs.AA)
					if changed {
						r.addPendingReconcile(
							PhysicalIoSG, "interface added/deleted", true)
					}
				}
				if ev.Deleted {
					changed := r.updateCurrentRoutes(r.prevArgs.DPC)
					if changed {
						r.addPendingReconcile(
							L3SG, "interface delete triggered route change", true)
					}
				}
			case netmonitor.AddrChange:
				changed := r.updateCurrentAdapterAddrs(r.prevArgs.DPC)
				if changed {
					r.addPendingReconcile(L3SG, "address change", true)
				}
				changed = r.updateCurrentRoutes(r.prevArgs.DPC)
				if changed {
					r.addPendingReconcile(L3SG, "address change triggered route change", true)
				}

			case netmonitor.DNSInfoChange:
				newGlobalCfg := r.getIntendedGlobalCfg(r.prevArgs.DPC)
				prevGlobalCfg := r.intendedState.SubGraph(GlobalSG)
				if len(prevGlobalCfg.DiffItems(newGlobalCfg)) > 0 {
					r.addPendingReconcile(GlobalSG, "DNS info change", true)
				}
			}

		case ctrl = <-r.watcherControl:
			if ctrl == watcherCtrlPause {
				r.Unlock()
				for ctrl != watcherCtrlCont {
					ctrl = <-r.watcherControl
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
			changed := r.updateCurrentPhysicalIO(args.DPC, args.AA)
			if changed {
				r.addPendingReconcile(PhysicalIoSG, "AA change", false)
			}
			r.addPendingReconcile(WirelessSG, "AA change", false)
		}
		if r.rsChanged(args.RS) {
			r.addPendingReconcile(WirelessSG, "RS change", false)
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
			intSG = r.getIntendedGlobalCfg(args.DPC)
		case PhysicalIoSG:
			intSG = r.getIntendedPhysicalIO(args.DPC)
		case LogicalIoSG:
			intSG = r.getIntendedLogicalIO(args.DPC)
		case L3SG:
			intSG = r.getIntendedL3Cfg(args.DPC)
		case WirelessSG:
			intSG = r.getIntendedWirelessCfg(args.DPC, args.AA, args.RS)
		case ACLsSG:
			intSG = r.getIntendedACLs(args.DPC, args.GCP)
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
	// XXX Do we want to have this always logged or only with DEBUG enabled?
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
		CancelAsyncOps:  rs.CancelAsyncOps,
		WaitForAsyncOps: rs.WaitForAsyncOps,
		FailingItems:    failingItems,
		RS: RadioSilenceStatus{
			RadioSilence:       r.radioSilence,
			WwanConfigChecksum: r.wwanConfigurator.LastChecksum,
		},
		DNS: DNSStatus{
			Error:   dnsError,
			Servers: resolvConf.DNSServers,
		},
	}

	// Update the internal state.
	r.prevArgs = args
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

func (r *LinuxDpcReconciler) dpcChanged(newDPC types.DevicePortConfig) bool {
	return !r.prevArgs.DPC.MostlyEqual(&newDPC)
}

func (r *LinuxDpcReconciler) aaChanged(newAA types.AssignableAdapters) bool {
	if len(newAA.IoBundleList) != len(r.prevArgs.AA.IoBundleList) {
		return true
	}
	for i := range newAA.IoBundleList {
		newIo := newAA.IoBundleList[i]
		prevIo := r.prevArgs.AA.IoBundleList[i]
		// Compare only attributes used by DpcReconciler.
		if prevIo.Logicallabel != newIo.Logicallabel ||
			prevIo.Ifname != newIo.Ifname ||
			prevIo.UsbAddr != newIo.UsbAddr ||
			prevIo.PciLong != newIo.PciLong ||
			prevIo.IsPCIBack != newIo.IsPCIBack {
			return true
		}
	}
	return false
}

func (r *LinuxDpcReconciler) rsChanged(newRS types.RadioSilence) bool {
	return r.prevArgs.RS.Imposed != newRS.Imposed
}

func (r *LinuxDpcReconciler) gcpChanged(newGCP types.ConfigItemValueMap) bool {
	prevAuthKeys := r.prevArgs.GCP.GlobalValueString(types.SSHAuthorizedKeys)
	newAuthKeys := newGCP.GlobalValueString(types.SSHAuthorizedKeys)
	if prevAuthKeys != newAuthKeys {
		return true
	}
	prevAllowVNC := r.prevArgs.GCP.GlobalValueBool(types.AllowAppVnc)
	newAllowVNC := newGCP.GlobalValueBool(types.AllowAppVnc)
	if prevAllowVNC != newAllowVNC {
		return true
	}
	return false
}

func (r *LinuxDpcReconciler) updateCurrentState(args Args) (changed bool) {
	if r.currentState == nil {
		// Initialize only subgraphs with external items.
		addrsSG := dg.InitArgs{Name: AdapterAddrsSG}
		adaptersSG := dg.InitArgs{Name: AdaptersSG, Subgraphs: []dg.InitArgs{addrsSG}}
		routesSG := dg.InitArgs{Name: RoutesSG}
		l3SG := dg.InitArgs{Name: L3SG, Subgraphs: []dg.InitArgs{adaptersSG, routesSG}}
		physIoSG := dg.InitArgs{Name: PhysicalIoSG}
		graph := dg.InitArgs{Name: GraphName, Subgraphs: []dg.InitArgs{physIoSG, l3SG}}
		r.currentState = dg.New(graph)
		changed = true
	}
	if ioChanged := r.updateCurrentPhysicalIO(args.DPC, args.AA); ioChanged {
		changed = true
	}
	if addrsChanged := r.updateCurrentAdapterAddrs(args.DPC); addrsChanged {
		changed = true
	}
	if routesChanged := r.updateCurrentRoutes(args.DPC); routesChanged {
		changed = true
	}
	return changed
}

func (r *LinuxDpcReconciler) updateCurrentPhysicalIO(
	dpc types.DevicePortConfig, aa types.AssignableAdapters) (changed bool) {
	currentIO := dg.New(dg.InitArgs{Name: PhysicalIoSG})
	for _, port := range dpc.Ports {
		if port.L2Type != types.L2LinkTypeNone {
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
			r.Log.Errorf("updateCurrentPhysicalIO: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		currentIO.PutItem(generic.PhysIf{
			LogicalLabel: port.Logicallabel,
			IfName:       port.IfName,
		}, &reconciler.ItemStateData{
			State:         reconciler.ItemStateCreated,
			LastOperation: reconciler.OperationCreate,
		})
	}
	prevSG := r.currentState.SubGraph(PhysicalIoSG)
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
		if !port.IsL3Port {
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

func (r *LinuxDpcReconciler) updateCurrentRoutes(dpc types.DevicePortConfig) (changed bool) {
	sgPath := dg.NewSubGraphPath(L3SG, RoutesSG)
	currentRoutes := dg.New(dg.InitArgs{Name: RoutesSG})
	for _, port := range dpc.Ports {
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("updateCurrentRoutes: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		table := devicenetwork.BaseRTIndex + ifIndex
		routes, err := r.NetworkMonitor.ListRoutes(netmonitor.RouteFilters{
			FilterByTable: true,
			Table:         table,
			FilterByIf:    true,
			IfIndex:       ifIndex,
		})
		if err != nil {
			r.Log.Errorf("updateCurrentRoutes: ListRoutes failed for ifIndex %d: %v",
				ifIndex, err)
			continue
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
	r.intendedState.PutSubGraph(r.getIntendedGlobalCfg(args.DPC))
	r.intendedState.PutSubGraph(r.getIntendedPhysicalIO(args.DPC))
	r.intendedState.PutSubGraph(r.getIntendedLogicalIO(args.DPC))
	r.intendedState.PutSubGraph(r.getIntendedL3Cfg(args.DPC))
	r.intendedState.PutSubGraph(r.getIntendedWirelessCfg(args.DPC, args.AA, args.RS))
	r.intendedState.PutSubGraph(r.getIntendedACLs(args.DPC, args.GCP))
}

func (r *LinuxDpcReconciler) getIntendedGlobalCfg(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        GlobalSG,
		Description: "Global configuration",
	}
	intendedCfg := dg.New(graphArgs)
	// Move IP rule that matches local destined packets below network instance rules.
	intendedCfg.PutItem(linux.LocalIPRule{Priority: devicenetwork.PbrLocalDestPrio}, nil)
	if len(dpc.Ports) == 0 {
		return intendedCfg
	}
	// Intended content of /etc/resolv.conf
	dnsServers := make(map[string][]net.IP)
	for _, port := range dpc.Ports {
		if !port.IsMgmt {
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

func (r *LinuxDpcReconciler) getIntendedPhysicalIO(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        PhysicalIoSG,
		Description: "Physical network interfaces",
	}
	intendedIO := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		if port.L2Type == types.L2LinkTypeNone {
			intendedIO.PutItem(generic.PhysIf{
				LogicalLabel: port.Logicallabel,
				IfName:       port.IfName,
			}, nil)
		}
	}
	return intendedIO
}

func (r *LinuxDpcReconciler) getIntendedLogicalIO(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        LogicalIoSG,
		Description: "Logical (L2) network interfaces",
	}
	intendedIO := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		switch port.L2Type {
		case types.L2LinkTypeVLAN:
			parent := dpc.LookupPortByLogicallabel(port.VLAN.ParentPort)
			if parent != nil {
				vlan := linux.Vlan{
					LogicalLabel: port.Logicallabel,
					IfName:       port.IfName,
					ParentLL:     port.VLAN.ParentPort,
					ParentIfName: parent.IfName,
					ParentL2Type: parent.L2Type,
					ID:           port.VLAN.ID,
				}
				intendedIO.PutItem(vlan, nil)
				if parent.L2Type == types.L2LinkTypeNone {
					// Allocate the physical interface for use as a VLAN parent.
					intendedIO.PutItem(generic.IOHandle{
						PhysIfLL:   parent.Logicallabel,
						PhysIfName: parent.IfName,
						Usage:      generic.IOUsageVlanParent,
					}, nil)
				}
			}

		case types.L2LinkTypeBond:
			var aggrIfNames []string
			for _, aggrPort := range port.Bond.AggregatedPorts {
				if nps := dpc.LookupPortByLogicallabel(aggrPort); nps != nil {
					aggrIfNames = append(aggrIfNames, nps.IfName)
					// Allocate the physical interface for use by the bond.
					intendedIO.PutItem(generic.IOHandle{
						PhysIfLL:     nps.Logicallabel,
						PhysIfName:   nps.IfName,
						Usage:        generic.IOUsageBondAggrIf,
						MasterIfName: port.IfName,
					}, nil)
				}
			}
			var usage generic.IOUsage
			if port.IsL3Port {
				usage = generic.IOUsageL3Adapter
			} else {
				// Nothing other than VLAN is supported at the higher-layer currently.
				// It is also possible that the bond is not being used at all, but we
				// do not need to treat that case differently.
				usage = generic.IOUsageVlanParent
			}
			intendedIO.PutItem(linux.Bond{
				BondConfig:        port.Bond,
				LogicalLabel:      port.Logicallabel,
				IfName:            port.IfName,
				AggregatedIfNames: aggrIfNames,
				Usage:             usage,
			}, nil)
		}
	}
	return intendedIO
}

func (r *LinuxDpcReconciler) getIntendedL3Cfg(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        L3SG,
		Description: "Network Layer3 configuration",
	}
	intendedL3 := dg.New(graphArgs)
	intendedL3.PutSubGraph(r.getIntendedAdapters(dpc))
	intendedL3.PutSubGraph(r.getIntendedSrcIPRules(dpc))
	intendedL3.PutSubGraph(r.getIntendedRoutes(dpc))
	intendedL3.PutSubGraph(r.getIntendedArps(dpc))
	return intendedL3
}

func (r *LinuxDpcReconciler) getIntendedAdapters(dpc types.DevicePortConfig) dg.Graph {
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
		if !port.IsL3Port {
			continue
		}
		adapter := linux.Adapter{
			LogicalLabel: port.Logicallabel,
			IfName:       port.IfName,
			L2Type:       port.L2Type,
		}
		intendedAdapters.PutItem(adapter, nil)
		if port.L2Type == types.L2LinkTypeNone {
			// Allocate the physical interface for use by the adapter.
			intendedAdapters.PutItem(generic.IOHandle{
				PhysIfLL:   port.Logicallabel,
				PhysIfName: port.IfName,
				Usage:      generic.IOUsageL3Adapter,
			}, nil)
		}
		if port.Dhcp != types.DT_NONE &&
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
			intendedRules.PutItem(linux.SrcIPRule{
				AdapterLL:     port.Logicallabel,
				AdapterIfName: port.IfName,
				IPAddr:        ipAddr.IP,
				Priority:      devicenetwork.PbrLocalOrigPrio,
			}, nil)
		}
	}
	return intendedRules
}

func (r *LinuxDpcReconciler) getIntendedRoutes(dpc types.DevicePortConfig) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        RoutesSG,
		Description: "IP routes",
	}
	intendedRoutes := dg.New(graphArgs)
	for _, port := range dpc.Ports {
		ifIndex, found, err := r.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if err != nil {
			r.Log.Errorf("getIntendedRoutes: failed to get ifIndex for %s: %v",
				port.IfName, err)
			continue
		}
		if !found {
			continue
		}
		// Routes copied from the main table.
		srcTable := syscall.RT_TABLE_MAIN
		dstTable := devicenetwork.BaseRTIndex + ifIndex
		routes, err := r.NetworkMonitor.ListRoutes(netmonitor.RouteFilters{
			FilterByTable: true,
			Table:         srcTable,
			FilterByIf:    true,
			IfIndex:       ifIndex,
		})
		if err != nil {
			r.Log.Errorf("getIntendedRoutes: ListRoutes failed for ifIndex %d: %v",
				ifIndex, err)
			continue
		}
		for _, rt := range routes {
			rtCopy := rt.Data.(netlink.Route)
			rtCopy.Table = dstTable
			// Multiple IPv6 link-locals can't be added to the same
			// table unless the Priority differs.
			// Different LinkIndex, Src, Scope doesn't matter.
			if rt.Dst != nil && rt.Dst.IP.IsLinkLocalUnicast() {
				if r.Log != nil {
					r.Log.Tracef("Forcing IPv6 priority to %v", rtCopy.LinkIndex)
				}
				// Hack to make the kernel routes not appear identical.
				rtCopy.Priority = rtCopy.LinkIndex
			}
			intendedRoutes.PutItem(linux.Route{
				Route:         rtCopy,
				AdapterIfName: port.IfName,
				AdapterLL:     port.Logicallabel,
			}, nil)
		}
	}
	return intendedRoutes
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
			if devicenetwork.HostFamily(ipAddr.IP) != syscall.AF_INET {
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
	rsImposed := radioSilence.Imposed
	intendedWirelessCfg.PutItem(
		r.getIntendedWlanConfig(dpc, rsImposed), nil)
	intendedWirelessCfg.PutItem(
		r.getIntendedWwanConfig(dpc, aa, rsImposed), nil)
	return intendedWirelessCfg
}

func (r *LinuxDpcReconciler) getIntendedWlanConfig(
	dpc types.DevicePortConfig, radioSilence bool) dg.Item {
	var wifiPort *types.NetworkPortConfig
	for _, portCfg := range dpc.Ports {
		if portCfg.WirelessCfg.WType == types.WirelessTypeWifi {
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
		EnableRF: wifiPort != nil && !radioSilence,
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
			Log:               r.Log,
			AgentName:         r.AgentName,
			AgentMetrics:      r.CipherMetrics,
			SubControllerCert: r.SubControllerCert,
			SubEdgeNodeCert:   r.SubEdgeNodeCert,
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
	aa types.AssignableAdapters, radioSilence bool) dg.Item {
	config := types.WwanConfig{RadioSilence: radioSilence, Networks: []types.WwanNetworkConfig{}}

	for _, port := range dpc.Ports {
		if port.WirelessCfg.WType != types.WirelessTypeCellular || len(port.WirelessCfg.Cellular) == 0 {
			continue
		}
		ioBundle := aa.LookupIoBundleLogicallabel(port.Logicallabel)
		if ioBundle == nil {
			r.Log.Warnf("Failed to find adapter with logical label '%s'", port.Logicallabel)
			continue
		}
		if ioBundle.IsPCIBack {
			r.Log.Warnf("wwan adapter with the logical label '%s' is assigned to pciback, skipping",
				port.Logicallabel)
			continue
		}
		// XXX Limited to a single APN for now
		cellCfg := port.WirelessCfg.Cellular[0]
		network := types.WwanNetworkConfig{
			LogicalLabel: port.Logicallabel,
			PhysAddrs: types.WwanPhysAddrs{
				Interface: ioBundle.Ifname,
				USB:       ioBundle.UsbAddr,
				PCI:       ioBundle.PciLong,
			},
			Apns:    []string{cellCfg.APN},
			Proxies: port.Proxies,
			Probe: types.WwanProbe{
				Disable: cellCfg.DisableProbe,
				Address: cellCfg.ProbeAddr,
			},
			LocationTracking: cellCfg.LocationTracking,
		}
		config.Networks = append(config.Networks, network)
	}
	return generic.Wwan{Config: config}
}

func (r *LinuxDpcReconciler) getIntendedACLs(
	dpc types.DevicePortConfig, gcp types.ConfigItemValueMap) dg.Graph {
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

	// Create chains for both device-wide ACLs as well as for application ACLs.
	// Link them from top-level chains, with app ACLs always preceding device ACLs.
	// Do this only for chains which are actually used.
	usedChains := map[iptables.Chain]struct{ devACLs, appACLs bool }{
		{Table: "raw", ChainName: "PREROUTING"}:     {devACLs: false, appACLs: true},
		{Table: "filter", ChainName: "INPUT"}:       {devACLs: true, appACLs: true},
		{Table: "filter", ChainName: "FORWARD"}:     {devACLs: false, appACLs: true},
		{Table: "mangle", ChainName: "PREROUTING"}:  {devACLs: true, appACLs: true},
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

	var filterV4Rules, filterV6Rules []iptables.Rule

	// Ports which are always blocked.
	block8080 := iptables.Rule{
		RuleLabel:   "Port 8080",
		MatchOpts:   []string{"-p", "tcp", "--dport", "8080"},
		Target:      "REJECT",
		TargetOpts:  []string{"--reject-with", "tcp-reset"},
		Description: "Port 8080 is always blocked",
	}
	filterV4Rules = append(filterV4Rules, block8080)
	filterV6Rules = append(filterV6Rules, block8080)

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
	filterV4Rules = append(filterV4Rules, allowLocalGuacamoleV4, blockNonLocalGuacamole)
	filterV6Rules = append(filterV6Rules, allowLocalGuacamoleV6, blockNonLocalGuacamole)

	// Allow/block SSH access.
	gcpSSHAuthKeys := gcp.GlobalValueString(types.SSHAuthorizedKeys)
	intendedACLs.PutItem(generic.SSHAuthKeys{Keys: gcpSSHAuthKeys}, nil)
	gcpAllowSSH := gcp.GlobalValueString(types.SSHAuthorizedKeys) != ""
	blockSSH := iptables.Rule{
		RuleLabel:   "Block SSH",
		MatchOpts:   []string{"-p", "tcp", "--dport", "22"},
		Target:      "REJECT",
		TargetOpts:  []string{"--reject-with", "tcp-reset"},
		Description: "SSH access is not allowed by device config",
	}
	if !gcpAllowSSH {
		filterV4Rules = append(filterV4Rules, blockSSH)
		filterV6Rules = append(filterV6Rules, blockSSH)
	}

	// Allow/block VNC access.
	const (
		localVNCRuleLabel  = "Local VNC"
		remoteVNCRuleLabel = "Remote VNC"
	)
	gcpAllowRemoteVNC := gcp.GlobalValueBool(types.AllowAppVnc)
	allowLocalVNCv4 := iptables.Rule{
		RuleLabel: localVNCRuleLabel,
		MatchOpts: []string{"-p", "tcp", "-s", "127.0.0.1", "-d", "127.0.0.1",
			"--dport", "5900:5999"},
		Target:      "ACCEPT",
		Description: "Local VNC traffic is always allowed",
	}
	allowLocalVNCv6 := iptables.Rule{
		RuleLabel: localVNCRuleLabel,
		MatchOpts: []string{"-p", "tcp", "-s", "::1", "-d", "::1",
			"--dport", "5900:5999"},
		Target:      "ACCEPT",
		Description: "Local VNC traffic is always allowed",
	}
	if !gcpAllowRemoteVNC {
		// Remote VNC rules block any VNC traffic (incl. local), meaning that Local VNC
		// rules must precede them to work correctly.
		allowLocalVNCv4.AppliedBefore = []string{remoteVNCRuleLabel}
		allowLocalVNCv6.AppliedBefore = []string{remoteVNCRuleLabel}
	}
	filterV4Rules = append(filterV4Rules, allowLocalVNCv4)
	filterV6Rules = append(filterV6Rules, allowLocalVNCv6)
	if !gcpAllowRemoteVNC {
		blockRemoteVNC := iptables.Rule{
			RuleLabel:  remoteVNCRuleLabel,
			MatchOpts:  []string{"-p", "tcp", "--dport", "5900:5999"},
			Target:     "REJECT",
			TargetOpts: []string{"--reject-with", "tcp-reset"},
			Description: "VNC traffic originating from outside is not allowed " +
				"by device config",
		}
		filterV4Rules = append(filterV4Rules, blockRemoteVNC)
		filterV6Rules = append(filterV6Rules, blockRemoteVNC)
	}

	// Submit filtering rules.
	for _, filterV4Rule := range filterV4Rules {
		filterV4Rule.ChainName = "INPUT" + iptables.DeviceChainSuffix
		filterV4Rule.Table = "filter"
		filterV4Rule.ForIPv6 = false
		intendedIPv4ACLs.PutItem(filterV4Rule, nil)
	}
	for _, filterV6Rule := range filterV6Rules {
		filterV6Rule.ChainName = "INPUT" + iptables.DeviceChainSuffix
		filterV6Rule.Table = "filter"
		filterV6Rule.ForIPv6 = true
		intendedIPv6ACLs.PutItem(filterV6Rule, nil)
	}

	// Mark ingress control-flow traffic.
	// For connections originating from outside we use App ID = 0.
	markSSHAndGuacamole := iptables.Rule{
		RuleLabel:   "SSH and Guacamole mark",
		MatchOpts:   []string{"-p", "tcp", "--match", "multiport", "--dports", "22,4822"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", iptables.ControlProtocolMarkingIDMap["in_http_ssh_guacamole"]},
		Description: "Mark ingress SSH and Guacamole traffic",
	}
	markVnc := iptables.Rule{
		RuleLabel:   "VNC mark",
		MatchOpts:   []string{"-p", "tcp", "--match", "multiport", "--dports", "5900:5999"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", iptables.ControlProtocolMarkingIDMap["in_vnc"]},
		Description: "Mark ingress VNC traffic",
	}
	markIcmpV4 := iptables.Rule{
		RuleLabel:   "ICMP mark",
		MatchOpts:   []string{"-p", "icmp"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", iptables.ControlProtocolMarkingIDMap["in_icmp"]},
		Description: "Mark ingress ICMP traffic",
	}
	markIcmpV6 := iptables.Rule{
		RuleLabel:   "ICMPv6 traffic",
		MatchOpts:   []string{"-p", "icmpv6"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", iptables.ControlProtocolMarkingIDMap["in_icmp"]},
		Description: "Mark ingress ICMPv6 traffic",
	}
	markDhcp := iptables.Rule{
		RuleLabel:   "DHCP mark",
		MatchOpts:   []string{"-p", "udp", "--dport", "bootps:bootpc"},
		Target:      "CONNMARK",
		TargetOpts:  []string{"--set-mark", iptables.ControlProtocolMarkingIDMap["in_dhcp"]},
		Description: "Mark ingress DHCP traffic",
	}
	protoMarkV4Rules := []iptables.Rule{
		markSSHAndGuacamole, markVnc, markIcmpV4, markDhcp,
	}
	protoMarkV6Rules := []iptables.Rule{
		markSSHAndGuacamole, markVnc, markIcmpV6,
	}

	// Mark ingress traffic not matched by the rules above with the DROP action.
	// Create a separate chain for marking.
	const dropIngressChain = "drop-ingress"
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
	ingressDefDrop := iptables.GetConnmark(0, iptables.DefaultDropAceID, true)
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
			TargetOpts: []string{"--set-mark", iptables.ControlProtocolMarkingIDMap["out_all"]},
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
	return intendedACLs
}
