// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nireconciler

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/nireconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// File where the current state graph is exported (as DOT) after each reconcile.
	// Can be used for troubleshooting purposes.
	currentStateFile = "/run/zedrouter-current-state.dot"
	// File where the intended state graph is exported (as DOT) after each reconcile.
	// Can be used for troubleshooting purposes.
	intendedStateFile = "/run/zedrouter-intended-state.dot"
)

var emptyUUID = uuid.UUID{} // used as a constant

// LinuxNIReconciler is a network instance reconciler for Linux network stack,
// i.e. it configures and uses Linux networking to provide application connectivity.
type LinuxNIReconciler struct {
	log *base.LogObject
	// Logrus logger is needed to create separate log object for every HTTP server
	// (serving app metadata).
	logger          *logrus.Logger
	netMonitor      netmonitor.NetworkMonitor
	metadataHandler http.Handler

	exportCurrentState  bool
	exportIntendedState bool

	// From GCP
	disableAllOnesNetmask bool

	reconcileMu   sync.Mutex
	currentState  dg.Graph
	intendedState dg.Graph

	initialized bool
	registry    reconciler.ConfiguratorRegistry

	// To manage asynchronous operations.
	watcherControl   chan watcherCtrl
	pendingReconcile pendingReconcile
	resumeAsync      <-chan string // nil if no async ops
	cancelAsync      reconciler.CancelFunc

	// Publishing of reconciler updates.
	// When reconcileMu and publishMu are both needed to acquire,
	// reconcileMu is locked first.
	publishMu       sync.Mutex
	updateSubs      []chan ReconcilerUpdate
	wakeupPublisher chan bool
	pendingUpdates  []ReconcilerUpdate

	// Current configuration
	nis  map[uuid.UUID]*niInfo
	apps map[uuid.UUID]*appInfo
}

type pendingReconcile struct {
	// True if we need to resume reconciliation because async op(s) finalized.
	asyncFinalized bool
	// Non-nil if the intended state of the global config is outdated
	// and needs to be rebuilt before triggering reconciliation.
	rebuildGlobalCfg *pendingCfgRebuild
	// A map of network instances whose intended state is outdated
	// and needs to be rebuilt before triggering reconciliation.
	rebuildNICfg map[uuid.UUID]pendingCfgRebuild
}

type pendingCfgRebuild struct {
	reasons []string
}

type watcherCtrl uint8

const (
	watcherCtrlUndefined watcherCtrl = iota
	watcherCtrlStart
	watcherCtrlPause
	watcherCtrlCont
)

type niInfo struct {
	config   types.NetworkInstanceConfig
	bridge   NIBridge
	brIfName string
	deleted  bool
	status   NIReconcileStatus
}

type appInfo struct {
	config    types.AppNetworkConfig
	appNum    int
	deleted   bool
	vifs      []vifInfo                        // maps 1:1 to config.UnderlayNetworkList
	vifStatus map[string]AppVIFReconcileStatus // key = net adapter name
}

type vifInfo struct {
	AppVIF
	hostIfName string
}

// NewLinuxNIReconciler is a constructor for LinuxNIReconciler.
// Enable exportCurrentState to have the current state exported to currentStateFile
// on every change.
// Enable exportIntendedState to have the intended state exported to intendedStateFile
// on every change.
func NewLinuxNIReconciler(log *base.LogObject, logger *logrus.Logger,
	netMonitor netmonitor.NetworkMonitor, metadataHandler http.Handler,
	exportCurrentState, exportIntendedState bool) *LinuxNIReconciler {
	return &LinuxNIReconciler{
		log:                 log,
		logger:              logger,
		netMonitor:          netMonitor,
		metadataHandler:     metadataHandler,
		exportCurrentState:  exportCurrentState,
		exportIntendedState: exportIntendedState,
	}
}

// GetCurrentState : get the current state (read-only).
// Exported only for unit-testing purposes.
func (r *LinuxNIReconciler) GetCurrentState() dg.GraphR {
	return r.currentState
}

// GetIntendedState : get the intended state (read-only).
// Exported only for unit-testing purposes.
func (r *LinuxNIReconciler) GetIntendedState() dg.GraphR {
	return r.intendedState
}

// init is called once Reconciler receives first config.
func (r *LinuxNIReconciler) init() (startWatcher func()) {
	r.reconcileMu.Lock()
	if r.initialized {
		r.log.Fatalf("%s: Already initialized", LogAndErrPrefix)
	}
	registry := &reconciler.DefaultRegistry{}
	if err := generic.RegisterItems(r.log, r.logger, registry); err != nil {
		r.log.Fatal(err)
	}
	if err := linux.RegisterItems(r.log, registry, r.netMonitor); err != nil {
		r.log.Fatal(err)
	}
	if err := iptables.RegisterItems(r.log, registry); err != nil {
		r.log.Fatal(err)
	}
	r.registry = registry
	r.currentState = r.initialDepGraph()
	r.intendedState = r.initialDepGraph()
	r.nis = make(map[uuid.UUID]*niInfo)
	r.apps = make(map[uuid.UUID]*appInfo)
	r.pendingReconcile.rebuildNICfg = make(map[uuid.UUID]pendingCfgRebuild)
	r.wakeupPublisher = make(chan bool, 1)
	go r.runPublisher()
	r.watcherControl = make(chan watcherCtrl, 10)
	netEvents := r.netMonitor.WatchEvents(context.Background(), "linux-ni-reconciler")
	go r.runWatcher(netEvents)
	r.initialized = true
	return func() {
		r.watcherControl <- watcherCtrlStart
		r.reconcileMu.Unlock()
	}
}

// runPublisher publishes ReconcilerUpdate from a separate Go routine.
func (r *LinuxNIReconciler) runPublisher() {
	for {
		select {
		case <-r.wakeupPublisher:
			r.publishMu.Lock()
			subs := r.updateSubs
			updates := r.pendingUpdates
			r.pendingUpdates = []ReconcilerUpdate{}
			r.publishMu.Unlock()
			for _, update := range updates {
				for _, sub := range subs {
					sub <- update
				}
			}
		}
	}
}

// WatchReconcilerUpdates returns channel with updates about the reconciliation
// status, which is provided separately for every network instance and connected
// application.
func (r *LinuxNIReconciler) WatchReconcilerUpdates() <-chan ReconcilerUpdate {
	r.publishMu.Lock()
	defer r.publishMu.Unlock()
	watcherCh := make(chan ReconcilerUpdate)
	r.updateSubs = append(r.updateSubs, watcherCh)
	return watcherCh
}

func (r *LinuxNIReconciler) publishReconcilerUpdates(updates ...ReconcilerUpdate) {
	r.publishMu.Lock()
	r.pendingUpdates = append(r.pendingUpdates, updates...)
	r.publishMu.Unlock()
	select {
	case r.wakeupPublisher <- true:
	default:
	}
}

// Watcher monitors changes in the current state and gets notified when async
// operation completes.
func (r *LinuxNIReconciler) runWatcher(netEvents <-chan netmonitor.Event) {
	var ctrl watcherCtrl
	for ctrl != watcherCtrlStart {
		ctrl = <-r.watcherControl
	}
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()
	for {
		select {
		case <-r.resumeAsync:
			r.pendingReconcile.asyncFinalized = true
			updateMsg := ReconcilerUpdate{UpdateType: AsyncOpDone}
			r.publishReconcilerUpdates(updateMsg)

		case event := <-netEvents:
			var needReconcile bool
			switch ev := event.(type) {
			case netmonitor.RouteChange:
				if ev.Table == unix.RT_TABLE_MAIN {
					attrs, err := r.netMonitor.GetInterfaceAttrs(ev.IfIndex)
					if err != nil {
						r.log.Warnf("%s: failed to get attributes for ifindex %d "+
							"(route update): %v", LogAndErrPrefix, ev.IfIndex, err)
						continue
					}
					ifName := attrs.IfName
					for _, ni := range r.nis {
						if ni.config.Type == types.NetworkInstanceTypeSwitch {
							continue
						}
						if ifName == ni.brIfName || ifName == ni.bridge.Uplink.IfName {
							r.updateCurrentNIRoutes(ni.config.UUID)
							r.scheduleNICfgRebuild(ni.config.UUID, "route change")
							needReconcile = true
						}
					}
				}

			case netmonitor.IfChange:
				ifName := ev.Attrs.IfName
				// Check if this is intended and/or current uplink, bridge or vif.
				uplinkRef := dg.Reference(generic.Uplink{IfName: ifName})
				brRef := dg.Reference(linux.Bridge{IfName: ifName})
				vifRef := dg.Reference(generic.VIF{IfName: ifName})
				graphs := []dg.GraphR{r.intendedState, r.currentState}
				var found bool
				for _, graph := range graphs {
					if _, _, _, found = graph.Item(uplinkRef); found {
						uplinkChanged := r.updateCurrentGlobalState(true)
						if uplinkChanged {
							for _, ni := range r.getNIsUsingUplink(ifName) {
								r.updateCurrentNIRoutes(ni.config.UUID)
								r.scheduleNICfgRebuild(ni.config.UUID,
									"uplink state change")
								needReconcile = true
							}
						}
						break
					}
					iter := graph.SubGraphs()
					for iter.Next() {
						subG := iter.SubGraph()
						niID := SGNameToNI(subG.Name())
						if niID == emptyUUID {
							continue
						}
						if _, _, _, found = subG.Item(brRef); found {
							brChanged := r.updateCurrentNIBridge(niID)
							if brChanged {
								r.scheduleNICfgRebuild(niID, "bridge state change")
								needReconcile = true
							}
							break
						}
						if _, _, _, found = subG.Item(vifRef); found {
							vifChanged := r.updateCurrentVIFs(niID)
							if vifChanged {
								r.scheduleNICfgRebuild(niID, "VIF state change")
								needReconcile = true
							}
							break
						}
					}
					if found {
						break
					}
				}

			case netmonitor.AddrChange:
				attrs, err := r.netMonitor.GetInterfaceAttrs(ev.IfIndex)
				if err != nil {
					r.log.Warnf("%s: failed to get attributes for ifindex %d "+
						"(addr update): %v", LogAndErrPrefix, ev.IfIndex, err)
					continue
				}
				ifName := attrs.IfName
				brForNI := r.getNIWithBridge(ifName)
				if brForNI != nil {
					if r.niBridgeIsCreatedByNIM(brForNI) {
						// When bridge used by switch NI gets IP address from external
						// DHCP server, zedrouter can start HTTP server with app metadata.
						// Also, DHCP ACLs need to be updated.
						brIPChanged := r.updateCurrentNIBridge(brForNI.config.UUID)
						if brIPChanged {
							r.scheduleNICfgRebuild(brForNI.config.UUID,
								"bridge IP change")
							needReconcile = true
						}
					}
				}
				uplinkForNIs := r.getNIsUsingUplink(ifName)
				if len(uplinkForNIs) > 0 {
					// When uplink IP addresses change, port-map ACLs might need
					// to be updated.
					uplinkChanged := r.updateCurrentGlobalState(true)
					if uplinkChanged {
						for _, ni := range uplinkForNIs {
							r.updateCurrentNIRoutes(ni.config.UUID)
							r.scheduleNICfgRebuild(ni.config.UUID,
								"uplink IP change")
							needReconcile = true
						}
					}
				}
			}
			if needReconcile {
				updateMsg := ReconcilerUpdate{UpdateType: CurrentStateChanged}
				r.publishReconcilerUpdates(updateMsg)
			}

		case ctrl = <-r.watcherControl:
			if ctrl == watcherCtrlPause {
				r.reconcileMu.Unlock()
				for ctrl != watcherCtrlCont {
					ctrl = <-r.watcherControl
				}
				r.reconcileMu.Lock()
			}
		}
	}
}

func (r *LinuxNIReconciler) pauseWatcher() (cont func()) {
	if !r.initialized {
		return r.init()
	}
	r.watcherControl <- watcherCtrlPause
	r.reconcileMu.Lock()
	return func() {
		r.watcherControl <- watcherCtrlCont
		r.reconcileMu.Unlock()
	}
}

// reconcile the current state of network instances and application connectivity with
// the intended state.
func (r *LinuxNIReconciler) reconcile(ctx context.Context) (updates []ReconcilerUpdate) {
	// Stage 1: Rebuild intended state if needed
	var reconcileReasons []string
	// Rebuild intended state and reconcile with clear network monitor cache to avoid
	// working with stale data.
	r.netMonitor.ClearCache()
	if r.pendingReconcile.rebuildGlobalCfg != nil {
		reasons := r.pendingReconcile.rebuildGlobalCfg.reasons
		r.log.Noticef("%s: Rebuilding intended global config, reasons: %s",
			LogAndErrPrefix, strings.Join(reasons, ", "))
		reconcileReasons = append(reconcileReasons,
			"rebuilt intended state for global config")
		r.intendedState.PutSubGraph(r.getIntendedGlobalState())
	}
	for niID, pReconcile := range r.pendingReconcile.rebuildNICfg {
		reasons := pReconcile.reasons
		r.log.Noticef("%s: Rebuilding intended config for NI %s, reasons: %s",
			LogAndErrPrefix, niID, strings.Join(reasons, ", "))
		reconcileReasons = append(reconcileReasons,
			fmt.Sprintf("rebuilt intended state for NI %s", niID))
		sgName := NIToSGName(niID)
		niInfo := r.nis[niID]
		deleted := niInfo == nil || niInfo.deleted
		if deleted {
			r.intendedState.DelSubGraph(sgName)
		} else {
			r.intendedState.PutSubGraph(r.getIntendedNICfg(niID))
		}
	}

	// Stage 2: Run reconciliation between the intended and the current state
	if r.pendingReconcile.asyncFinalized {
		reconcileReasons = append(reconcileReasons, "async op finalized")
	}
	if len(reconcileReasons) == 0 {
		return
	}
	reconcileStartTime := time.Now()
	stateReconciler := reconciler.New(r.registry)
	r.log.Noticef("%s: Running state reconciliation, reasons: %s",
		LogAndErrPrefix, strings.Join(reconcileReasons, ", "))
	rs := stateReconciler.Reconcile(ctx, r.currentState, r.intendedState)
	r.resumeAsync = rs.ReadyToResume
	r.cancelAsync = rs.CancelAsyncOps
	r.logReconciliation(rs, reconcileStartTime)
	// Clear pending reconciliation.
	r.pendingReconcile.rebuildGlobalCfg = nil
	r.pendingReconcile.asyncFinalized = false
	r.pendingReconcile.rebuildNICfg = make(map[uuid.UUID]pendingCfgRebuild)

	// Stage 3: Collect NI and VIF status updates
	for niID := range r.nis {
		niStatus, changed := r.updateNIStatus(niID)
		if changed {
			updates = append(updates, ReconcilerUpdate{
				UpdateType: NIReconcileStatusChanged,
				NIStatus:   &niStatus,
			})
		}
	}
	for appID := range r.apps {
		appConnStatus, changed := r.updateAppConnStatus(appID)
		if changed {
			updates = append(updates, ReconcilerUpdate{
				UpdateType:    AppConnReconcileStatusChanged,
				AppConnStatus: &appConnStatus,
			})
		}
	}

	// Stage 4: Clear UDP flows if any NAT ACL rule has changed.
	for appID, app := range r.apps {
		for i, vif := range app.vifs {
			var natV4RuleChanged, natV6RuleChanged bool
			acls := app.config.UnderlayNetworkList[i].ACLs
			for _, log := range rs.OperationLog {
				rule, isRule := log.Item.(iptables.Rule)
				if !isRule || rule.Table != "nat" {
					continue
				}
				preRChain := vifChain("PREROUTING", vif)
				postRChain := vifChain("POSTROUTING", vif)
				if rule.ChainName == preRChain || rule.ChainName == postRChain {
					if rule.ForIPv6 {
						natV6RuleChanged = true
					} else {
						natV4RuleChanged = true
					}
				}
			}
			if natV4RuleChanged {
				r.log.Noticef("%s: Clearing IPv4 UDP flows for app VIF %s/%s",
					LogAndErrPrefix, appID, vif.NetAdapterName)
				r.clearUDPFlows(acls, false)
			}
			if natV6RuleChanged {
				r.log.Noticef("%s: Clearing IPv6 UDP flows for app VIF %s/%s",
					LogAndErrPrefix, appID, vif.NetAdapterName)
				r.clearUDPFlows(acls, true)
			}
		}
	}
	return updates
}

func (r *LinuxNIReconciler) logReconciliation(rs reconciler.Status,
	reconcileStartTime time.Time) {
	// Log every executed operation.
	for _, log := range rs.OperationLog {
		var withErr string
		if log.Err != nil {
			withErr = fmt.Sprintf(" with error: %v", log.Err)
		}
		var action string
		if log.InProgress {
			action = "Started async execution of"
		} else {
			if log.StartTime.Before(reconcileStartTime) {
				action = "Finalized async execution of"
			} else {
				// synchronous operation
				action = "Executed"
			}
		}
		r.log.Noticef("%s: %s %v for %v%s, content: %s",
			LogAndErrPrefix, action, log.Operation, dg.Reference(log.Item),
			withErr, log.Item.String())
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
		r.log.Errorf("%s: Newly failed config items: %s",
			LogAndErrPrefix, strings.Join(failed, ", "))
	}
	if len(fixed) > 0 {
		r.log.Noticef("%s: Fixed config items: %s",
			LogAndErrPrefix, strings.Join(fixed, ", "))
	}

	// Output the current state into a file for troubleshooting purposes.
	if r.exportCurrentState {
		dotExporter := &dg.DotExporter{CheckDeps: true}
		dot, err := dotExporter.Export(r.currentState)
		if err != nil {
			r.log.Warnf("%s: Failed to export the current state to DOT: %v",
				LogAndErrPrefix, err)
		} else {
			err := fileutils.WriteRename(currentStateFile, []byte(dot))
			if err != nil {
				r.log.Warnf("%s: WriteRename failed for %s: %v",
					LogAndErrPrefix, currentStateFile, err)
			}
		}
	}

	// Output the intended state into a file for troubleshooting purposes.
	if r.exportIntendedState {
		dotExporter := &dg.DotExporter{CheckDeps: true}
		dot, err := dotExporter.Export(r.intendedState)
		if err != nil {
			r.log.Warnf("%s: Failed to export the intended state to DOT: %v",
				LogAndErrPrefix, err)
		} else {
			err := fileutils.WriteRename(intendedStateFile, []byte(dot))
			if err != nil {
				r.log.Warnf("%s: WriteRename failed for %s: %v",
					LogAndErrPrefix, intendedStateFile, err)
			}
		}
	}
}

// Called after reconciliation to update status of the given network instance.
func (r *LinuxNIReconciler) updateNIStatus(
	niID uuid.UUID) (niStatus NIReconcileStatus, changed bool) {
	var brIfName string
	var brIfIndex int
	niInfo := r.nis[niID] // guaranteed not to be nil
	brIfName = niInfo.brIfName
	brIfIndex, _, _ = r.netMonitor.GetInterfaceIndex(brIfName)
	deleted := niInfo == nil || niInfo.deleted
	sgName := NIToSGName(niID)
	currSG := r.currentState.SubGraph(sgName)
	intSG := r.intendedState.SubGraph(sgName)
	inProgress, failedItems := r.getSubgraphState(intSG, currSG, false)
	niStatus = NIReconcileStatus{
		NI:          niID,
		Deleted:     deleted,
		BrIfName:    brIfName,
		BrIfIndex:   brIfIndex,
		InProgress:  inProgress,
		FailedItems: failedItems,
	}
	if !niInfo.status.Equal(niStatus) {
		changed = true
		niInfo.status = niStatus
	}
	if deleted && !inProgress {
		changed = true
		delete(r.nis, niID)
		if currSG != nil {
			r.currentState.DelSubGraph(sgName)
		}
		r.log.Noticef("%s: Deleted niInfo for NI %s", LogAndErrPrefix, niID)
	}
	return
}

// Called after reconciliation to update connectivity status of the given app.
func (r *LinuxNIReconciler) updateAppConnStatus(
	appID uuid.UUID) (appConnStatus AppConnReconcileStatus, changed bool) {
	appInfo := r.apps[appID] // guaranteed not to be nil
	appConnStatus = AppConnReconcileStatus{
		App:     appID,
		Deleted: appInfo.deleted,
	}
	var anyInProgress bool
	for _, vif := range appInfo.vifs {
		var currSG, intSG dg.GraphR
		if niSG := r.currentState.SubGraph(NIToSGName(vif.NI)); niSG != nil {
			currSG = niSG.SubGraph(AppConnSGName(vif.App, vif.NetAdapterName))
		}
		if niSG := r.intendedState.SubGraph(NIToSGName(vif.NI)); niSG != nil {
			intSG = niSG.SubGraph(AppConnSGName(vif.App, vif.NetAdapterName))
		}
		inProgress, failedItems := r.getSubgraphState(intSG, currSG, true)
		anyInProgress = anyInProgress || inProgress
		vifStatus := AppVIFReconcileStatus{
			NetAdapterName: vif.NetAdapterName,
			VIFNum:         vif.VIFNum,
			HostIfName:     vif.hostIfName,
			InProgress:     inProgress,
			FailedItems:    failedItems,
		}
		if appInfo.vifStatus == nil {
			appInfo.vifStatus = make(map[string]AppVIFReconcileStatus)
		}
		if !appInfo.vifStatus[vif.NetAdapterName].Equal(vifStatus) {
			appInfo.vifStatus[vif.NetAdapterName] = vifStatus
			changed = true
		}
		appConnStatus.VIFs = append(appConnStatus.VIFs, vifStatus)
	}
	// Sort VIF status for deterministic order and easier unit-testing.
	appConnStatus.SortVIFs()
	if !anyInProgress && appInfo.deleted {
		changed = true
		delete(r.apps, appID)
		r.log.Noticef("%s: Deleted appInfo for app %s", LogAndErrPrefix, appID)
	}
	return
}

// This function looks for any UDP port map rules among the ACLs and if so clears
// any sessions corresponding only to them.
func (r *LinuxNIReconciler) clearUDPFlows(ACLs []types.ACE, ipv6 bool) {
	for _, ace := range ACLs {
		var protocol, port string
		for _, match := range ace.Matches {
			switch match.Type {
			case "protocol":
				protocol = match.Value
			case "lport":
				port = match.Value
			}
		}
		if protocol == "" && port != "" {
			// malformed rule.
			continue
		}
		// Not interested in non-UDP sessions
		if protocol != "udp" {
			continue
		}
		for _, action := range ace.Actions {
			if action.PortMap != true {
				continue
			}
			var family netlink.InetFamily = netlink.FAMILY_V4
			if ipv6 {
				family = netlink.FAMILY_V6
			}
			dport, err := strconv.ParseInt(port, 10, 32)
			if err != nil {
				r.log.Errorf(
					"%s: clearUDPFlows: Port number %s cannot be parsed to integer",
					LogAndErrPrefix, port)
				continue
			}
			targetPort := uint16(action.TargetPort)
			filter := conntrack.PortMapFilter{
				Protocol:     17, // UDP
				ExternalPort: uint16(dport),
				InternalPort: targetPort,
			}
			flowsDeleted, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable,
				family, filter)
			if err != nil {
				r.log.Errorf(
					"%s: clearUDPFlows: Failed clearing UDP flows for lport: %v, "+
						"target port: %v", LogAndErrPrefix, dport, targetPort)
				continue
			}
			r.log.Noticef(
				"%s: clearUDPFlows: Cleared %v UDP flows for lport: %v, "+
					"target port: %v", LogAndErrPrefix, flowsDeleted, dport, targetPort)
		}
	}
}

func (r *LinuxNIReconciler) scheduleGlobalCfgRebuild(reason string) {
	if r.pendingReconcile.rebuildGlobalCfg == nil {
		r.pendingReconcile.rebuildGlobalCfg = &pendingCfgRebuild{}
	}
	rebuild := r.pendingReconcile.rebuildGlobalCfg
	if !generics.ContainsItem(rebuild.reasons, reason) {
		rebuild.reasons = append(rebuild.reasons, reason)
	}
}

func (r *LinuxNIReconciler) scheduleNICfgRebuild(niID uuid.UUID, reason string) {
	rebuild := r.pendingReconcile.rebuildNICfg[niID]
	if !generics.ContainsItem(rebuild.reasons, reason) {
		rebuild.reasons = append(rebuild.reasons, reason)
	}
	r.pendingReconcile.rebuildNICfg[niID] = rebuild
}

// RunInitialReconcile is called once by zedrouter at startup before any NI
// or Application connection is created.
// It is expected to apply the initial configuration of the network stack.
func (r *LinuxNIReconciler) RunInitialReconcile(ctx context.Context) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	// Initial state after a boot.
	r.updateCurrentGlobalState(false)
	// Build and reconcile the global configuration (primarily for BlackHole config).
	r.scheduleGlobalCfgRebuild("initial reconciliation")
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
}

// ResumeReconcile : resume reconciliation to follow-up on completed async operations
// or externally changed current state.
func (r *LinuxNIReconciler) ResumeReconcile(ctx context.Context) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
}

// ApplyUpdatedGCP : apply change in the global config properties.
func (r *LinuxNIReconciler) ApplyUpdatedGCP(ctx context.Context,
	newGCP types.ConfigItemValueMap) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	disableAllOnesNetmask := newGCP.GlobalValueBool(types.DisableDHCPAllOnesNetMask)
	if r.disableAllOnesNetmask == disableAllOnesNetmask {
		// No change in GCP relevant for network instances.
		return
	}
	r.disableAllOnesNetmask = disableAllOnesNetmask
	for niID, ni := range r.nis {
		if ni.config.Type == types.NetworkInstanceTypeSwitch {
			// Not running DHCP server for switch NI inside EVE.
			continue
		}
		r.scheduleNICfgRebuild(niID,
			fmt.Sprintf("global config property %s changed to %t",
				types.DisableDHCPAllOnesNetMask, r.disableAllOnesNetmask))
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
}

// AddNI : create this new network instance inside the network stack.
func (r *LinuxNIReconciler) AddNI(ctx context.Context,
	niConfig types.NetworkInstanceConfig, br NIBridge) (NIReconcileStatus, error) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	var niStatus NIReconcileStatus
	niID := niConfig.UUID
	if _, duplicate := r.nis[niID]; duplicate {
		return niStatus, fmt.Errorf("%s: NI %v is already added", LogAndErrPrefix, niID)
	}
	brIfName, err := r.generateBridgeIfName(niConfig, br)
	if err != nil {
		return niStatus, err
	}
	r.nis[niID] = &niInfo{
		config:   niConfig,
		bridge:   br,
		brIfName: brIfName,
	}
	reconcileReason := fmt.Sprintf("adding new NI (%v)", niID)
	// Rebuild and reconcile also global config to update the set of intended/current
	// uplinks.
	r.updateCurrentGlobalState(true) // uplinks only
	// Get the current state of external items used by NI.
	r.updateCurrentNIState(niID)
	r.scheduleGlobalCfgRebuild(reconcileReason)
	r.scheduleNICfgRebuild(niID, reconcileReason)
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	niStatus = r.nis[niID].status
	return niStatus, nil
}

// UpdateNI : apply a change in the intended NI configuration inside the network stack.
// Note that BrNum and NI Type is not allowed to change.
func (r *LinuxNIReconciler) UpdateNI(ctx context.Context,
	niConfig types.NetworkInstanceConfig, br NIBridge) (NIReconcileStatus, error) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	var niStatus NIReconcileStatus
	niID := niConfig.UUID
	if _, exists := r.nis[niID]; !exists {
		return niStatus, fmt.Errorf("%s: Cannot update NI %v: does not exist",
			LogAndErrPrefix, niID)
	}
	r.nis[niID].config = niConfig
	r.nis[niID].bridge = br
	// Re-generate bridge interface name to support change in the select uplink port
	// for switch network instances.
	brIfName, err := r.generateBridgeIfName(niConfig, br)
	if err != nil {
		return niStatus, err
	}
	r.nis[niID].brIfName = brIfName
	reconcileReason := fmt.Sprintf("updating NI (%v)", niID)
	// Get the current state of external items to be used by NI.
	r.updateCurrentNIState(niID)
	// Rebuild and reconcile also global config to update the set of intended/current
	// uplinks.
	r.updateCurrentGlobalState(true) // uplinks only
	r.scheduleGlobalCfgRebuild(reconcileReason)
	r.scheduleNICfgRebuild(niID, reconcileReason)
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	niStatus = r.nis[niID].status
	return niStatus, nil
}

// DelNI : remove network instance from the network stack.
func (r *LinuxNIReconciler) DelNI(ctx context.Context,
	niID uuid.UUID) (NIReconcileStatus, error) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	var niStatus NIReconcileStatus
	if _, exists := r.nis[niID]; !exists {
		return niStatus, fmt.Errorf("%s: Cannot delete NI %v: does not exist",
			LogAndErrPrefix, niID)
	}
	// Deleted from the map when removal is completed successfully (incl. async ops).
	r.nis[niID].deleted = true
	niStatus = r.nis[niID].status
	reconcileReason := fmt.Sprintf("deleting NI (%v)", niID)
	// Rebuild and reconcile also global config to update the set of intended/current
	// uplinks.
	r.updateCurrentGlobalState(true) // uplinks only
	r.scheduleGlobalCfgRebuild(reconcileReason)
	r.scheduleNICfgRebuild(niID, reconcileReason)
	// Cancel any in-progress configuration changes previously
	// submitted for this NI.
	sg := r.currentState.SubGraph(NIToSGName(niID))
	if sg != nil && r.cancelAsync != nil {
		r.cancelAsync(func(ref dg.ItemRef) bool {
			_, _, _, isForThisNI := sg.Item(ref)
			return isForThisNI
		})
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	// r.nis[niID] could be deleted by this point
	for _, update := range updates {
		if update.UpdateType == NIReconcileStatusChanged && update.NIStatus.NI == niID {
			niStatus = *update.NIStatus
		}
	}
	return niStatus, nil
}

// ConnectApp : make necessary changes inside the network stack to connect a new
// application into the desired set of network instance(s).
// This is called by zedrouter before the guest VM is started, meaning that
// some of the operations will be completed later from within ResumeReconcile() after
// domainmgr starts the VM.
func (r *LinuxNIReconciler) ConnectApp(ctx context.Context,
	appNetConfig types.AppNetworkConfig, appNum int, vifs []AppVIF) (
	AppConnReconcileStatus, error) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	appID := appNetConfig.UUIDandVersion.UUID
	appStatus := AppConnReconcileStatus{App: appID}
	if _, duplicate := r.apps[appID]; duplicate {
		return appStatus, fmt.Errorf("%s: App %v is already connected",
			LogAndErrPrefix, appID)
	}
	appInfo := &appInfo{
		config: appNetConfig,
		appNum: appNum,
	}
	for _, vif := range vifs {
		appInfo.vifs = append(appInfo.vifs, vifInfo{
			AppVIF:     vif,
			hostIfName: r.generateVifHostIfName(vif.VIFNum, appNum),
		})
	}
	r.apps[appID] = appInfo
	reconcileReason := fmt.Sprintf("connecting new app (%v)", appID)
	// Rebuild and reconcile also global config to update the set of intended IPSets.
	r.scheduleGlobalCfgRebuild(reconcileReason)
	// Rebuild and reconcile config of every NI that this app is trying to connect into.
	for _, vif := range vifs {
		r.scheduleNICfgRebuild(vif.NI, reconcileReason)
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	for _, vifStatus := range r.apps[appID].vifStatus {
		appStatus.VIFs = append(appStatus.VIFs, vifStatus)
	}
	// Sort VIF status for deterministic order and easier unit-testing.
	appStatus.SortVIFs()
	return appStatus, nil
}

// ReconnectApp : (re)connect application with changed config into the (possibly
// changed) desired set of network instance(s).
func (r *LinuxNIReconciler) ReconnectApp(ctx context.Context,
	appNetConfig types.AppNetworkConfig, vifs []AppVIF) (AppConnReconcileStatus, error) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	appID := appNetConfig.UUIDandVersion.UUID
	appStatus := AppConnReconcileStatus{App: appID}
	if _, exists := r.apps[appID]; !exists {
		return appStatus, fmt.Errorf("%s: Cannot reconnect App %v: does not exist",
			LogAndErrPrefix, appID)
	}
	appInfo := r.apps[appID]
	appInfo.config = appNetConfig
	prevVifs := appInfo.vifs
	appInfo.vifs = nil
	appInfo.vifStatus = nil
	for _, vif := range vifs {
		appInfo.vifs = append(appInfo.vifs, vifInfo{
			AppVIF:     vif,
			hostIfName: r.generateVifHostIfName(vif.VIFNum, appInfo.appNum),
		})
	}
	r.apps[appID] = appInfo
	reconcileReason := fmt.Sprintf("reconnecting app (%v)", appID)
	// Rebuild and reconcile also global config to update the set of intended IPSets.
	r.scheduleGlobalCfgRebuild(reconcileReason)
	// Reconcile every NI that this app is either disconnecting from or trying
	// to (re)connect into.
	for _, vif := range prevVifs {
		r.scheduleNICfgRebuild(vif.NI, reconcileReason)
	}
	for _, vif := range vifs {
		r.scheduleNICfgRebuild(vif.NI, reconcileReason)
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	for _, vifStatus := range r.apps[appID].vifStatus {
		appStatus.VIFs = append(appStatus.VIFs, vifStatus)
	}
	// Sort VIF status for deterministic order and easier unit-testing.
	appStatus.SortVIFs()
	return appStatus, nil
}

// DisconnectApp : disconnect (removed) application from network instance(s).
func (r *LinuxNIReconciler) DisconnectApp(ctx context.Context,
	appID uuid.UUID) (AppConnReconcileStatus, error) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	appStatus := AppConnReconcileStatus{App: appID, Deleted: true}
	if _, exists := r.apps[appID]; !exists {
		return appStatus, fmt.Errorf("%s: Cannot disconnect App %v: does not exist",
			LogAndErrPrefix, appID)
	}
	// Deleted from the map when removal is completed successfully (incl. async ops).
	r.apps[appID].deleted = true
	reconcileReason := fmt.Sprintf("disconnecting app (%v)", appID)
	// Rebuild and reconcile also global config to update the set of intended IPSets.
	r.scheduleGlobalCfgRebuild(reconcileReason)
	// Reconcile every NI that this app is trying to disconnect from.
	for _, vif := range r.apps[appID].vifs {
		r.scheduleNICfgRebuild(vif.NI, reconcileReason)
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	// r.apps[appID] could be deleted by this point
	for _, update := range updates {
		if update.UpdateType == AppConnReconcileStatusChanged &&
			update.AppConnStatus.App == appID {
			appStatus = *update.AppConnStatus
		}
	}
	return appStatus, nil
}

func (r *LinuxNIReconciler) getNIsUsingUplink(ifName string) (nis []*niInfo) {
	for _, ni := range r.nis {
		switch ni.config.Type {
		case types.NetworkInstanceTypeSwitch:
			if ifName == uplinkPhysIfName(ni.bridge.Uplink.IfName) {
				nis = append(nis, ni)
			}
		case types.NetworkInstanceTypeLocal:
			if ifName == ni.bridge.Uplink.IfName {
				nis = append(nis, ni)
			}
		}
	}
	return nis
}

func (r *LinuxNIReconciler) getNIWithBridge(ifName string) *niInfo {
	for _, ni := range r.nis {
		switch ni.config.Type {
		case types.NetworkInstanceTypeSwitch:
			if ifName == ni.bridge.Uplink.IfName {
				return ni
			}
		case types.NetworkInstanceTypeLocal:
			if ifName == ni.brIfName {
				return ni
			}
		}
	}
	return nil
}

// Function returns inProgress as true if any intended item is missing or is still being
// asynchronously updated or if there is an unintended item not yet deleted.
// Additionally, returns a map of items for which the last operation failed.
func (r *LinuxNIReconciler) getSubgraphState(intSG, currSG dg.GraphR, forApp bool) (
	inProgress bool, failedItems map[dg.ItemRef]error) {
	if currSG == nil {
		if intSG == nil {
			return false, nil
		}
		emptyIntSG := intSG.Items(true).Next() == false
		return !emptyIntSG, nil
	}
	itemIsForApp := func(item dg.Item) bool {
		// XXX Better would be to check if item is inside AppConn-* subgraph
		// but depgraph API does not allow to do that.
		if item.Type() == generic.VIFTypename {
			return true
		}
		if item.Type() == linux.VLANPortTypename {
			if item.(linux.VLANPort).BridgePort.VIFIfName != "" {
				return true
			}
		}
		return false
	}
	ignoreExtraItem := func(item dg.Item) bool {
		// Ignore if extra item is external.
		if item.External() {
			return true
		}
		// Also ignore extra routes added by kernel.
		route, isRoute := item.(linux.Route)
		if isRoute && route.Dst != nil && route.Dst.IP.IsLinkLocalUnicast() {
			return true
		}
		return false
	}
	iter := currSG.Items(true)
	for iter.Next() {
		item, state := iter.Item()
		if !forApp && itemIsForApp(item) {
			continue
		}
		if state.InTransition() {
			inProgress = true
		}
		if itemErr := state.WithError(); itemErr != nil {
			if failedItems == nil {
				failedItems = make(map[dg.ItemRef]error)
			}
			failedItems[dg.Reference(item)] = itemErr
		}
	}
	if intSG == nil {
		iter := currSG.Items(true)
		for iter.Next() {
			item, _ := iter.Item()
			if !forApp && itemIsForApp(item) {
				continue
			}
			if ignoreExtraItem(item) {
				continue
			}
			inProgress = true
		}
		return inProgress, failedItems
	}
	diff := currSG.DiffItems(intSG)
	for _, itemRef := range diff {
		intItem, _, _, shouldExist := intSG.Item(itemRef)
		currItem, _, _, exists := currSG.Item(itemRef)
		item := intItem
		if item == nil {
			item = currItem
		}
		if !forApp && item != nil && itemIsForApp(item) {
			continue
		}
		if exists && !shouldExist && ignoreExtraItem(item) {
			continue
		}
		inProgress = true
	}
	return inProgress, failedItems
}
