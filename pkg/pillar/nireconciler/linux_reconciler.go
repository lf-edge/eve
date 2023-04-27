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

	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/nireconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
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

const (
	vifIfNamePrefix    = "nbu"
	bridgeIfNamePrefix = "bn"
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
	pendingReconcile map[string]pendingReconcile // key : subgraph name
	resumeAsync      <-chan string               // nil if no async ops

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
	// Either forGlobalSG is true or forNI is non-empty.
	forGlobalSG bool
	forNI       uuid.UUID
	reasons     []string
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
	r.pendingReconcile = make(map[string]pendingReconcile)
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
		case subgraph := <-r.resumeAsync:
			reconcileReason := "async op finalized"
			if subgraph == GlobalSG {
				r.addPendingReconcile(true, emptyUUID, reconcileReason)
			} else {
				niID := SGNameToNI(subgraph)
				if niID == emptyUUID {
					r.log.Errorf(
						"%s: received resumeAsync signal for unrecognized subgraph: %s",
						LogAndErrPrefix, subgraph)
					continue
				}
				r.addPendingReconcile(false, niID, reconcileReason)
			}
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
							r.addPendingReconcile(false, ni.config.UUID, "route change")
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
								r.addPendingReconcile(false, ni.config.UUID,
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
								r.addPendingReconcile(false, niID, "bridge state change")
								needReconcile = true
							}
							break
						}
						if _, _, _, found = subG.Item(vifRef); found {
							vifChanged := r.updateCurrentVIFs(niID)
							if vifChanged {
								r.addPendingReconcile(false, niID, "VIF state change")
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
					if brForNI.config.Type == types.NetworkInstanceTypeSwitch {
						// When bridge used by switch NI gets IP address from external
						// DHCP server, zedrouter can start HTTP server with app metadata.
						// Also, DHCP ACLs need to be updated.
						brChanged := r.updateCurrentNIBridge(brForNI.config.UUID)
						if brChanged {
							r.addPendingReconcile(false, brForNI.config.UUID,
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
							r.addPendingReconcile(false, ni.config.UUID,
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
	if len(r.pendingReconcile) == 0 {
		// Nothing to reconcile.
		return nil
	}
	statusUpdateMap := make(map[uuid.UUID]ReconcilerUpdate)
	// Reconcile with clear network monitor cache to avoid working with stale data.
	r.netMonitor.ClearCache()
	for sgName, pReconcile := range r.pendingReconcile {
		// Prepare intended+current subgraphs for reconciliation.
		var intSG dg.Graph
		if pReconcile.forGlobalSG {
			intSG = r.getIntendedGlobalState()
			if r.currentState.SubGraph(GlobalSG) == nil {
				// Very first reconciliation.
				r.updateCurrentGlobalState(false)
			}
		} else {
			niInfo := r.nis[pReconcile.forNI]
			intSG = r.getIntendedNICfg(pReconcile.forNI)
			if r.currentState.SubGraph(sgName) == nil {
				if niInfo == nil || niInfo.deleted {
					// Nothing to do for removed NI.
					continue
				}
				// New network instance. Get the current state of external items.
				r.updateCurrentNIState(pReconcile.forNI)
			}
		}
		r.intendedState.PutSubGraph(intSG)
		currSG := r.currentState.SubGraph(sgName) // non-nil at this point

		// Run state reconciliation.
		r.log.Noticef("%s: Running state reconciliation for subgraph %s, reasons: %s",
			LogAndErrPrefix, sgName, strings.Join(pReconcile.reasons, ", "))
		reconcileStartTime := time.Now()
		stateReconciler := reconciler.New(r.registry)
		rs := stateReconciler.Reconcile(ctx, r.currentState.EditSubGraph(currSG), intSG)
		r.resumeAsync = rs.ReadyToResume

		// Detect and collect status updates.
		if pReconcile.forNI != emptyUUID {
			niStatus := r.updateNIStatus(pReconcile.forNI, currSG, statusUpdateMap)
			// Clear UDP flows if any NAT ACL rule has changed.
			var natV4RuleChanged, natV6RuleChanged bool
			for _, log := range rs.OperationLog {
				rule, isRule := log.Item.(iptables.Rule)
				if isRule && rule.Table == "nat" {
					if rule.ForIPv6 {
						natV6RuleChanged = true
					} else {
						natV4RuleChanged = true
					}
				}
			}
			if natV4RuleChanged || natV6RuleChanged {
				for _, app := range r.apps {
					for i, vif := range app.vifs {
						if vif.NI != pReconcile.forNI {
							continue
						}
						acls := app.config.UnderlayNetworkList[i].ACLs
						if natV4RuleChanged {
							r.clearUDPFlows(acls, false)
						}
						if natV6RuleChanged {
							r.clearUDPFlows(acls, true)
						}
					}
				}
			}
			// Remove NI subgraph if the network instance has been fully un-configured.
			niInfo := r.nis[pReconcile.forNI]
			if niInfo == nil || niInfo.deleted {
				r.intendedState.DelSubGraph(sgName)
				if !niStatus.AsyncInProgress {
					r.currentState.DelSubGraph(sgName)
				}
			}
		}

		// Log every executed operation.
		// XXX Do we want to have this always logged or only with DEBUG enabled?
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
		delete(r.pendingReconcile, sgName)
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

	// Return status updates for changed NIs and app connections.
	for _, statusUpdate := range statusUpdateMap {
		updates = append(updates, statusUpdate)
	}
	return updates
}

// Called after NI reconciliation to update status of the given network instance
// and VIFs that connect to it.
// Function adds detected status changes to statusUpdateMap.
func (r *LinuxNIReconciler) updateNIStatus(niID uuid.UUID, currNISG dg.GraphR,
	statusUpdateMap map[uuid.UUID]ReconcilerUpdate) (niStatus NIReconcileStatus) {
	asyncInProgress, failedItems := r.getSubgraphState(currNISG)
	var brIfName string
	niInfo := r.nis[niID]
	if niInfo != nil {
		brIfName = niInfo.brIfName
	}
	brIfIndex, _, _ := r.netMonitor.GetInterfaceIndex(brIfName)
	niStatus = NIReconcileStatus{
		NI:              niID,
		Deleted:         niInfo == nil || niInfo.deleted,
		BrIfName:        brIfName,
		BrIfIndex:       brIfIndex,
		AsyncInProgress: asyncInProgress,
		FailedItems:     failedItems,
	}
	if niInfo == nil || !niInfo.status.Equal(niStatus) {
		statusUpdateMap[niID] = ReconcilerUpdate{
			UpdateType: NIReconcileStatusChanged,
			NIStatus:   &niStatus,
		}
		if niInfo != nil {
			niInfo.status = niStatus
		}
	}

	// Update AppVIFReconcileStatus for all VIFs connected to this NI.
	for appID, app := range r.apps {
		var updated bool
		for _, vif := range app.vifs {
			if vif.NI != niID {
				continue
			}
			vifStatus := AppVIFReconcileStatus{
				NetAdapterName: vif.NetAdapterName,
				VIFNum:         vif.VIFNum,
				HostIfName:     vif.hostIfName,
			}
			appConnSG := currNISG.SubGraph(AppConnSGName(vif.App, vif.NetAdapterName))
			if appConnSG != nil && !app.deleted {
				vifStatus.AsyncInProgress, vifStatus.FailedItems =
					r.getSubgraphState(appConnSG)
				// Is VIF ready for use?
				vifRef := dg.Reference(generic.VIF{IfName: vif.hostIfName})
				item, state, _, found := appConnSG.Item(vifRef)
				vifStatus.Ready = found && state.IsCreated() &&
					!state.InTransition() && state.WithError() == nil
				if vifStatus.Ready {
					// Check that VIF is bridged.
					vifItem, isVifItem := item.(generic.VIF)
					vifStatus.Ready = isVifItem && vifItem.MasterIfName == niInfo.brIfName
				}
			}
			if app.vifStatus == nil {
				app.vifStatus = make(map[string]AppVIFReconcileStatus)
			}
			if !app.vifStatus[vif.NetAdapterName].Equal(vifStatus) {
				app.vifStatus[vif.NetAdapterName] = vifStatus
				updated = true
			}
		}
		if updated {
			appStatus := &AppConnReconcileStatus{
				App:     appID,
				Deleted: app.deleted,
			}
			for _, vif := range app.vifStatus {
				appStatus.VIFs = append(appStatus.VIFs, vif)
			}
			appStatus.SortVIFs()
			statusUpdateMap[appID] = ReconcilerUpdate{
				UpdateType:    AppConnReconcileStatusChanged,
				AppConnStatus: appStatus,
			}
		}
	}
	return niStatus
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

func (r *LinuxNIReconciler) addPendingReconcile(
	forGlobalSG bool, forNI uuid.UUID, reason string) {
	var sgName string
	if forGlobalSG {
		sgName = GlobalSG
	} else {
		sgName = NIToSGName(forNI)
	}
	pReconcile := r.pendingReconcile[sgName]
	pReconcile.forGlobalSG = forGlobalSG
	pReconcile.forNI = forNI
	var duplicateReason bool
	for _, prevReason := range pReconcile.reasons {
		if prevReason == reason {
			duplicateReason = true
			break
		}
	}
	if !duplicateReason {
		pReconcile.reasons = append(pReconcile.reasons, reason)
	}
	r.pendingReconcile[sgName] = pReconcile
}

// RunInitialReconcile is called once by zedrouter at startup before any NI
// or Application connection is created.
// It is expected to apply the initial configuration of the network stack.
func (r *LinuxNIReconciler) RunInitialReconcile(ctx context.Context) {
	contWatcher := r.pauseWatcher()
	defer contWatcher()
	// Just reconcile the global configuration (primarily for BlackHole config).
	r.addPendingReconcile(true, emptyUUID, "initial reconciliation")
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
		r.addPendingReconcile(false, niID,
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
	var brIfName string
	switch niConfig.Type {
	case types.NetworkInstanceTypeSwitch:
		if br.Uplink.IfName != "" {
			brIfName = br.Uplink.IfName
			break
		}
		// Air-gapped, create bridge just like for local NI.
		fallthrough
	case types.NetworkInstanceTypeLocal:
		brIfName = fmt.Sprintf("%s%d", bridgeIfNamePrefix, br.BrNum)
	default:
		return niStatus, fmt.Errorf("%s: Unsupported type %v for NI %v",
			LogAndErrPrefix, niConfig.Type, niID)
	}
	r.nis[niID] = &niInfo{
		config:   niConfig,
		bridge:   br,
		brIfName: brIfName,
	}
	reconcileReason := fmt.Sprintf("adding new NI (%v)", niID)
	// Reconcile also GlobalSG to update the set of intended/current uplinks.
	r.updateCurrentGlobalState(true) // uplinks only
	r.addPendingReconcile(true, emptyUUID, reconcileReason)
	r.addPendingReconcile(false, niID, reconcileReason)
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
	reconcileReason := fmt.Sprintf("updating NI (%v)", niID)
	// Reconcile also GlobalSG to update the set of intended/current uplinks.
	r.updateCurrentGlobalState(true) // uplinks only
	r.addPendingReconcile(true, emptyUUID, reconcileReason)
	r.addPendingReconcile(false, niID, reconcileReason)
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
	r.nis[niID].deleted = true
	reconcileReason := fmt.Sprintf("deleting NI (%v)", niID)
	// Reconcile also GlobalSG to update the set of intended/current uplinks.
	r.updateCurrentGlobalState(true) // uplinks only
	r.addPendingReconcile(true, emptyUUID, reconcileReason)
	r.addPendingReconcile(false, niID, reconcileReason)
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	niStatus = r.nis[niID].status
	delete(r.nis, niID)
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
			hostIfName: fmt.Sprintf("%s%dx%d", vifIfNamePrefix, vif.VIFNum, appNum),
		})
	}
	r.apps[appID] = appInfo
	reconcileReason := fmt.Sprintf("connecting new app (%v)", appID)
	// Reconcile also GlobalSG to update the set of intended IPSets.
	r.addPendingReconcile(true, emptyUUID, reconcileReason)
	// Reconcile every NI that this app is trying to connect into.
	for _, vif := range vifs {
		r.addPendingReconcile(false, vif.NI, reconcileReason)
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	for _, vifStatus := range r.apps[appID].vifStatus {
		appStatus.VIFs = append(appStatus.VIFs, vifStatus)
	}
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
			AppVIF: vif,
			hostIfName: fmt.Sprintf("%s%dx%d", vifIfNamePrefix, vif.VIFNum,
				appInfo.appNum),
		})
	}
	r.apps[appID] = appInfo
	reconcileReason := fmt.Sprintf("reconnecting app (%v)", appID)
	// Reconcile also GlobalSG to update the set of intended IPSets.
	r.addPendingReconcile(true, emptyUUID, reconcileReason)
	// Reconcile every NI that this app is either disconnecting from or trying
	// to (re)connect into.
	for _, vif := range prevVifs {
		r.addPendingReconcile(false, vif.NI, reconcileReason)
	}
	for _, vif := range vifs {
		r.addPendingReconcile(false, vif.NI, reconcileReason)
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	for _, vifStatus := range r.apps[appID].vifStatus {
		appStatus.VIFs = append(appStatus.VIFs, vifStatus)
	}
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
	r.apps[appID].deleted = true
	reconcileReason := fmt.Sprintf("disconnecting app (%v)", appID)
	// Reconcile also GlobalSG to update the set of intended IPSets.
	r.addPendingReconcile(true, emptyUUID, reconcileReason)
	// Reconcile every NI that this app is trying to disconnect from.
	for _, vif := range r.apps[appID].vifs {
		r.addPendingReconcile(false, vif.NI, reconcileReason)
	}
	updates := r.reconcile(ctx)
	r.publishReconcilerUpdates(updates...)
	for _, vifStatus := range r.apps[appID].vifStatus {
		appStatus.VIFs = append(appStatus.VIFs, vifStatus)
	}
	appStatus.SortVIFs()
	delete(r.apps, appID)
	return appStatus, nil
}

func (r *LinuxNIReconciler) getOrAddNISubgraph(niID uuid.UUID) dg.Graph {
	sgName := NIToSGName(niID)
	var niSG dg.Graph
	if readHandle := r.currentState.SubGraph(sgName); readHandle != nil {
		niSG = r.currentState.EditSubGraph(readHandle)
	} else {
		niSG = dg.New(dg.InitArgs{Name: sgName})
		r.currentState.PutSubGraph(niSG)
	}
	return niSG
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

func (r *LinuxNIReconciler) getSubgraphState(sg dg.GraphR) (
	asyncInProgress bool, failedItems map[dg.ItemRef]error) {
	iter := sg.Items(true)
	for iter.Next() {
		item, state := iter.Item()
		if state.InTransition() {
			asyncInProgress = true
		}
		if itemErr := state.WithError(); itemErr != nil {
			if failedItems == nil {
				failedItems = make(map[dg.ItemRef]error)
			}
			failedItems[dg.Reference(item)] = itemErr
		}
	}
	return asyncInProgress, failedItems
}
