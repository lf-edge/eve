// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"
)

// EdgeCluster represents a cluster of edge devices and provides operations
// that span across all cluster nodes (e.g. applying config, waiting for
// application deployment, running scripts inside cluster-scheduled apps).
type EdgeCluster struct {
	th          *TestHarness
	clusterName string
	devices     []*EdgeDevice
}

// NewEdgeCluster creates an EdgeCluster handle for the given cluster name.
// The typical workflow is to create the handle, then call ApplyConfig to
// push the cluster configuration to all devices, and finally interact with
// the cluster (e.g. WaitUntilNodesAreReady, deploy applications, etc.).
func NewEdgeCluster(clusterName string) *EdgeCluster {
	return &EdgeCluster{
		th:          getTestHarness(),
		clusterName: clusterName,
	}
}

// ApplyConfig applies the configuration from the given EdgeClusterConfig
// to all cluster devices in parallel. The waitUntilFetched and
// waitUntilConfirmed arguments are forwarded to each device's ApplyConfig;
// see EdgeDevice.ApplyConfig for their semantics. excludeFromWait names
// devices the config is still pushed to, but without waiting on either flag
// -- e.g. a device deliberately powered off for the test, which would
// otherwise block waitUntilFetched/waitUntilConfirmed forever.
// The set of cluster devices is collected from the EdgeClusterConfig nodes
// and stored for use by subsequent methods.
func (ec *EdgeCluster) ApplyConfig(clusterConfig *EdgeClusterConfig,
	waitUntilFetched, waitUntilConfirmed bool, excludeFromWait ...string) {
	excluded := make(map[string]bool, len(excludeFromWait))
	for _, name := range excludeFromWait {
		excluded[name] = true
	}

	// Set the cluster name on each device's config and collect devices.
	nodes := clusterConfig.nodes
	ec.devices = make([]*EdgeDevice, len(nodes))
	for i, node := range nodes {
		dc := clusterConfig.GetDeviceConfig(node.DevName)
		if dc.Cluster != nil {
			dc.Cluster.ClusterName = ec.clusterName
		}
		ec.devices[i] = GetEdgeDevice(node.DevName)
	}
	RunParallel(len(nodes), func(i int) {
		node := nodes[i]
		fetched, confirmed := waitUntilFetched, waitUntilConfirmed
		if excluded[node.DevName] {
			fetched, confirmed = false, false
		}
		ec.devices[i].ApplyConfig(
			clusterConfig.GetDeviceConfig(node.DevName), fetched, confirmed)
	})
}

// WaitUntilNodesAreReady waits until any device in the cluster reports
// all cluster nodes as Ready via ZInfoKubeCluster. Only the elected leader
// node publishes cluster info, so the function succeeds as soon as any
// single device reports all nodes ready. It fails if the timeout expires
// before that happens.
//
// It accepts the last report already received. After a node reboots, that
// report can predate the reboot and still show the node Ready, so use
// WaitForFreshNodesReady there.
func (ec *EdgeCluster) WaitUntilNodesAreReady(timeout time.Duration) {
	ec.waitUntilNodesAreReady(timeout, false)
}

// WaitForFreshNodesReady is WaitUntilNodesAreReady, except that it counts only
// reports that arrive after the call. Use it after a node reboots or is
// powered off and on. The leader's report can show a powered-off node Ready
// until Kubernetes marks it NotReady, so call it only once an outage has
// lasted that long.
func (ec *EdgeCluster) WaitForFreshNodesReady(timeout time.Duration) {
	ec.waitUntilNodesAreReady(timeout, true)
}

func (ec *EdgeCluster) waitUntilNodesAreReady(timeout time.Duration, freshOnly bool) {
	if len(ec.devices) == 0 {
		ec.th.t.Fatalf("WaitUntilNodesAreReady: no devices in cluster %q "+
			"(call ApplyConfig first)", ec.clusterName)
	}
	expectedNodes := make([]string, len(ec.devices))
	for i, dev := range ec.devices {
		expectedNodes[i] = dev.devName
	}
	ec.WaitUntilClusterInfoSatisfies(timeout, freshOnly,
		fmt.Sprintf("cluster nodes %v to become ready", expectedNodes),
		func(info *eveinfo.ZInfoKubeCluster) bool {
			return allNodesReady(info, expectedNodes)
		})
}

// WaitUntilClusterInfoSatisfies waits until any device in the cluster
// reports a ZInfoKubeCluster satisfying pred. Only the elected leader node
// publishes cluster info, and which device that is can change over the
// cluster's lifetime (e.g. after a quorum recovery promotes a different
// node), so every device is watched in parallel and the function succeeds
// as soon as any single one satisfies pred. It fails if the timeout
// expires before that happens. With freshOnly, reports received before the
// call are ignored. description is used only for logging.
func (ec *EdgeCluster) WaitUntilClusterInfoSatisfies(timeout time.Duration,
	freshOnly bool, description string, pred func(*eveinfo.ZInfoKubeCluster) bool) {
	if len(ec.devices) == 0 {
		ec.th.t.Fatalf("WaitUntilClusterInfoSatisfies: no devices in cluster %q "+
			"(call ApplyConfig first)", ec.clusterName)
	}
	ec.th.log.Infof("Waiting for %s in cluster %q...", description, ec.clusterName)

	ctx, cancel := context.WithTimeout(ec.th.ctx, timeout)
	defer cancel()
	// doneCh is closed when any device satisfies pred, signalling the
	// other goroutines to stop waiting.
	doneCh := make(chan struct{})
	closeOnce := sync.Once{}

	// Subscribe to every device before taking the snapshot, so a
	// transition landing between the two can never be missed.
	allUpdates := make([]<-chan *eveinfo.ZInfoKubeCluster, len(ec.devices))
	for i, dev := range ec.devices {
		updates, stop := dev.WatchClusterInfo()
		defer stop()
		allUpdates[i] = updates
	}

	// The snapshot is evaluated once, on the newest info any device has
	// reported, rather than once per device on that device's own. Only the
	// elected leader publishes, so a device that lost the election or was
	// powered off still offers its last snapshot, and letting that satisfy
	// pred would end the wait on a description of the cluster that no
	// longer holds.
	if info := ec.newestClusterInfo(nil); !freshOnly && info != nil && pred(info) {
		ec.th.log.Infof("%s: already satisfied", description)
		return
	}

	RunParallel(len(ec.devices), func(i int) {
		dev := ec.devices[i]
		updates := allUpdates[i]
		var tickerCh <-chan time.Time
		if i == 0 {
			ticker := time.NewTicker(1 * time.Minute)
			tickerCh = ticker.C
			defer ticker.Stop()
		}
		for {
			select {
			case info, ok := <-updates:
				if !ok {
					return
				}
				if pred(info) {
					ec.th.log.Infof(
						"%s: satisfied by device %q", description, dev.devName)
					closeOnce.Do(func() { close(doneCh) })
					return
				}
			case <-tickerCh:
				if i == 0 {
					ec.th.log.Infof("Still waiting for %s...", description)
				}
			case <-doneCh:
				return
			case <-ctx.Done():
				ec.th.t.Fatalf("Timed out waiting for %s in cluster %q (device %q)",
					description, ec.clusterName, dev.devName)
			}
		}
	})
}

// allNodesReady returns true if the cluster storage is healthy and every
// node in expectedNodes is reported as Ready.
func allNodesReady(info *eveinfo.ZInfoKubeCluster, expectedNodes []string) bool {
	for _, name := range expectedNodes {
		if !clusterNodeReady(info, name) {
			return false
		}
	}
	return true
}

// clusterNodeReady returns true if the given cluster info reports the named
// node as Ready and the cluster's storage as healthy.
func clusterNodeReady(info *eveinfo.ZInfoKubeCluster, nodeName string) bool {
	const nodeReadyCond = eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY
	if info.GetStorage().GetHealth() != eveinfo.ServiceStatus_SERVICE_STATUS_HEALTHY {
		return false
	}
	for _, node := range info.GetNodes() {
		if node.GetName() != nodeName {
			continue
		}
		for _, cond := range node.GetConditions() {
			if cond.GetType() == nodeReadyCond {
				return cond.GetSet()
			}
		}
		return false
	}
	return false
}

// FindDeviceHostingApp finds the cluster device that hosts the given application.
// It returns the device the newest stored ZInfoKubeCluster report places the
// app on (matched by display name in EveApps or EveVmApps), or else waits for
// a new report that does.
//
// Only the newest report is trusted: only the stats leader publishes cluster
// info, and a node that loses the lease stops publishing without retracting
// its last report, so an older report can name a node the app has left.
//
// Pass excludeDevNames to wait for the app to move OFF the named devices, which
// is what a failover test needs. Excluded devices are skipped as a source of
// cluster info and are never returned, so the answer can only come from a
// device that is still up.
func (ec *EdgeCluster) FindDeviceHostingApp(appUUID uuid.UUID,
	timeout time.Duration, excludeDevNames ...string) *EdgeDevice {
	ec.checkDevices("FindDeviceHostingApp")
	ctx, cancel := context.WithTimeout(ec.th.ctx, timeout)
	defer cancel()

	excluded := make(map[string]bool, len(excludeDevNames))
	for _, name := range excludeDevNames {
		excluded[name] = true
	}
	appDisplayName := ec.appDisplayName(appUUID)

	// hostingNode returns the first node the info places the app on that is
	// not excluded - an excluded node is what the caller is waiting for the
	// app to leave, so reporting it is never the answer.
	hostingNode := func(info *eveinfo.ZInfoKubeCluster) string {
		for _, nodeName := range appNodeNames(info, appDisplayName) {
			if !excluded[nodeName] {
				return nodeName
			}
		}
		return ""
	}
	hostDevice := func(nodeName string) *EdgeDevice {
		dev := ec.deviceByName(nodeName)
		if dev == nil {
			ec.th.t.Fatalf("Node %q reports hosting app %q, but no matching device "+
				"was found in cluster %q", nodeName, appUUID, ec.clusterName)
		}
		return dev
	}

	// Subscribe before reading the stored reports, so an update landing
	// between the two is not missed.
	updates := ec.watchClusterInfo(ctx, excluded)
	if info := ec.newestClusterInfo(excluded); info != nil {
		if nodeName := hostingNode(info); nodeName != "" {
			return hostDevice(nodeName)
		}
	}
	for {
		select {
		case info := <-updates:
			if nodeName := hostingNode(info); nodeName != "" {
				return hostDevice(nodeName)
			}
		case <-ctx.Done():
			if len(excludeDevNames) > 0 {
				ec.th.t.Fatalf("Timed out waiting for app %q to move off %v in cluster %q",
					appUUID, excludeDevNames, ec.clusterName)
			}
			ec.th.t.Fatalf("Timed out waiting for app %q to be scheduled in cluster %q",
				appUUID, ec.clusterName)
			return nil // unreachable
		}
	}
}

// WaitUntilAppIsHostedOn waits until the newest cluster info report places
// the app on devName and on no other node, and returns that device.
//
// Use it to verify placement after the app has moved. Like
// FindDeviceHostingApp it starts from the newest stored report, because EVE
// sends cluster info only when it changes, so a placement that settled before
// the call may never be reported again. Requiring the app on devName alone
// rides out the window where the VMI being replaced is still listed next to
// its successor.
func (ec *EdgeCluster) WaitUntilAppIsHostedOn(appUUID uuid.UUID, devName string,
	timeout time.Duration) *EdgeDevice {
	ec.checkDevices("WaitUntilAppIsHostedOn")
	hostDev := ec.deviceByName(devName)
	if hostDev == nil {
		ec.th.t.Fatalf("Device %q is not a member of cluster %q", devName, ec.clusterName)
	}
	appDisplayName := ec.appDisplayName(appUUID)
	ec.th.log.Infof("Waiting for cluster info to place app %q (%s) on %q only...",
		appUUID, appDisplayName, devName)

	ctx, cancel := context.WithTimeout(ec.th.ctx, timeout)
	defer cancel()
	onlyOnDev := func(nodes []string) bool {
		for _, node := range nodes {
			if node != devName {
				return false
			}
		}
		return len(nodes) > 0
	}

	updates := ec.watchClusterInfo(ctx, nil)
	var lastSeen []string
	if info := ec.newestClusterInfo(nil); info != nil {
		lastSeen = appNodeNames(info, appDisplayName)
		if onlyOnDev(lastSeen) {
			return hostDev
		}
	}
	for {
		select {
		case info := <-updates:
			lastSeen = appNodeNames(info, appDisplayName)
			if onlyOnDev(lastSeen) {
				return hostDev
			}
		case <-ctx.Done():
			ec.th.t.Fatalf("Timed out waiting for cluster info to place app %q (%s) "+
				"on %q only in cluster %q; last report placed it on %v",
				appUUID, appDisplayName, devName, ec.clusterName, lastSeen)
			return nil // unreachable
		}
	}
}

// appDisplayName returns the display name of the app in the cluster config.
func (ec *EdgeCluster) appDisplayName(appUUID uuid.UUID) string {
	for _, dev := range ec.devices {
		for _, app := range dev.getConfig(false).GetApps() {
			if app.GetUuidandversion().GetUuid() == appUUID.String() {
				return app.GetDisplayname()
			}
		}
	}
	ec.th.t.Fatalf("Application %q not found in any cluster device config", appUUID)
	return "" // unreachable
}

// deviceByName returns the cluster device named devName, or nil.
func (ec *EdgeCluster) deviceByName(devName string) *EdgeDevice {
	for _, dev := range ec.devices {
		if dev.devName == devName {
			return dev
		}
	}
	return nil
}

// newestClusterInfo returns the most recently sent ZInfoKubeCluster report
// stored for any cluster device not in excluded, or nil if there is none.
func (ec *EdgeCluster) newestClusterInfo(excluded map[string]bool) *eveinfo.ZInfoKubeCluster {
	var newest *eveinfo.ZInfoMsg
	for _, dev := range ec.devices {
		if excluded[dev.devName] {
			continue
		}
		dev.iterateInfoMsgs(dev.getDevUUID(),
			func(msg *eveinfo.ZInfoMsg) bool {
				return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeCluster &&
					msg.GetClusterInfo() != nil
			},
			func(msg *eveinfo.ZInfoMsg) {
				if newest == nil ||
					msg.GetAtTimeStamp().AsTime().After(newest.GetAtTimeStamp().AsTime()) {
					newest = msg
				}
			})
	}
	return newest.GetClusterInfo()
}

// watchClusterInfo merges new ZInfoKubeCluster reports from every cluster
// device not in excluded into one channel, until ctx is done.
func (ec *EdgeCluster) watchClusterInfo(ctx context.Context,
	excluded map[string]bool) <-chan *eveinfo.ZInfoKubeCluster {
	merged := make(chan *eveinfo.ZInfoKubeCluster, watchChannelBufSize)
	for _, dev := range ec.devices {
		if excluded[dev.devName] {
			continue
		}
		updates, stop := dev.WatchClusterInfo()
		go func() {
			defer stop()
			for {
				select {
				case info, ok := <-updates:
					if !ok {
						return
					}
					select {
					case merged <- info:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return merged
}

// appNodeNames returns every node the cluster info places the app on, skipping
// VMIs that have finished. Kubernetes adds a hash suffix to the display name
// (e.g. "my-app-abcde12345"), so names match by prefix with a "-" separator.
// A VMI being replaced can be listed next to its successor, so one report can
// name more than one node.
func appNodeNames(info *eveinfo.ZInfoKubeCluster, appDisplayName string) []string {
	prefix := appDisplayName + "-"
	matchesName := func(name string) bool {
		return name == appDisplayName || strings.HasPrefix(name, prefix)
	}
	var nodes []string
	for _, app := range info.GetEveApps() {
		if matchesName(app.GetName()) && app.GetNodeName() != "" {
			nodes = append(nodes, app.GetNodeName())
		}
	}
	for _, vm := range info.GetEveVmApps() {
		switch vm.GetStatus() {
		case eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_SUCCEEDED,
			eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_FAILED:
			continue
		}
		if matchesName(vm.GetName()) && vm.GetNodeName() != "" {
			nodes = append(nodes, vm.GetNodeName())
		}
	}
	return nodes
}

// WaitUntilAppIsRunning waits until the specified application is running
// on one of the cluster nodes. It first locates the destination device via
// cluster info, then delegates to that device's WaitUntilAppIsRunning.
func (ec *EdgeCluster) WaitUntilAppIsRunning(
	appUUID uuid.UUID, timeoutExcludingDownload time.Duration) {
	ec.checkDevices("WaitUntilAppIsRunning")
	start := time.Now()
	ec.th.log.Infof("Waiting for app %q to be scheduled in cluster %q...",
		appUUID, ec.clusterName)
	dev := ec.FindDeviceHostingApp(appUUID, timeoutExcludingDownload)
	ec.th.log.Infof("App %q scheduled on device %q", appUUID, dev.devName)

	remaining := timeoutExcludingDownload - time.Since(start)
	if remaining <= 0 {
		ec.th.t.Fatalf("WaitUntilAppIsRunning: no time remaining after "+
			"locating app %q on device %q", appUUID, dev.devName)
	}
	dev.WaitUntilAppIsRunning(appUUID, remaining)
}

// RunShellScriptInsideApp locates the cluster node hosting the specified
// application and executes a shell script inside it over SSH.
func (ec *EdgeCluster) RunShellScriptInsideApp(appUUID uuid.UUID, auth AuthMethod,
	script string, timeout time.Duration,
	stdoutWatchdogTimeout time.Duration) (stdout, stderr string, err error) {
	ec.checkDevices("RunShellScriptInsideApp")
	dev := ec.FindDeviceHostingApp(appUUID, timeout)
	return dev.RunShellScriptInsideApp(appUUID, auth, script, timeout, stdoutWatchdogTimeout)
}

// GetAppLogs collects log messages for the specified application from all
// cluster devices (since the app may have migrated between nodes during its
// lifespan) and returns them sorted by timestamp.
func (ec *EdgeCluster) GetAppLogs(appUUID uuid.UUID, match LogMsgMatch) []LogMsg {
	ec.checkDevices("GetAppLogs")
	perDevice := make([][]LogMsg, len(ec.devices))
	RunParallel(len(ec.devices), func(i int) {
		perDevice[i] = ec.devices[i].GetAppLogs(appUUID, match)
	})
	var all []LogMsg
	for _, logs := range perDevice {
		all = append(all, logs...)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.Before(all[j].Timestamp)
	})
	return all
}

// RebootApplication reboots the specified application across the cluster.
// The reboot counter is incremented on all devices, but the wait (if requested)
// is performed only on the device hosting the application.
func (ec *EdgeCluster) RebootApplication(appUUID uuid.UUID, waitUntilRebooted bool,
	timeout time.Duration) {
	ec.checkDevices("RebootApplication")
	hostDev := ec.FindDeviceHostingApp(appUUID, timeout)
	ec.forEachDeviceExcept(hostDev, func(dev *EdgeDevice) {
		dev.RebootApplication(appUUID, false, 0)
	})
	hostDev.RebootApplication(appUUID, waitUntilRebooted, timeout)
}

// PurgeApplication purges the specified application across the cluster.
// The purge counter is incremented on all devices, but the wait (if requested)
// is performed only on the device hosting the application. See
// EdgeDevice.PurgeApplication for volumeGen.
//
// Name in excludeDevNames any node that must not be taken for the host, such as
// one the caller has powered off: the cluster info it published before going
// down still names it as the host, and waiting there never completes.
func (ec *EdgeCluster) PurgeApplication(appUUID uuid.UUID, volumeGen VolumeGenerationPolicy,
	waitUntilPurged bool, timeout time.Duration, excludeDevNames ...string) {
	ec.checkDevices("PurgeApplication")
	hostDev := ec.FindDeviceHostingApp(appUUID, timeout, excludeDevNames...)
	ec.forEachDeviceExcept(hostDev, func(dev *EdgeDevice) {
		dev.PurgeApplication(appUUID, volumeGen, false, 0)
	})
	hostDev.PurgeApplication(appUUID, volumeGen, waitUntilPurged, timeout)
}

// ActivateApplication activates the specified application across the cluster.
// The activate flag is set on all devices, but the wait (if requested)
// is performed only on the device hosting the application.
func (ec *EdgeCluster) ActivateApplication(appUUID uuid.UUID, waitUntilActivated bool,
	timeout time.Duration) {
	ec.checkDevices("ActivateApplication")
	hostDev := ec.FindDeviceHostingApp(appUUID, timeout)
	ec.forEachDeviceExcept(hostDev, func(dev *EdgeDevice) {
		dev.ActivateApplication(appUUID, false, 0)
	})
	hostDev.ActivateApplication(appUUID, waitUntilActivated, timeout)
}

// DeactivateApplication deactivates the specified application across the cluster.
// The activate flag is cleared on all devices, but the wait (if requested)
// is performed only on the device hosting the application.
func (ec *EdgeCluster) DeactivateApplication(appUUID uuid.UUID, waitUntilDeactivated bool,
	timeout time.Duration) {
	ec.checkDevices("DeactivateApplication")
	hostDev := ec.FindDeviceHostingApp(appUUID, timeout)
	ec.forEachDeviceExcept(hostDev, func(dev *EdgeDevice) {
		dev.DeactivateApplication(appUUID, false, 0)
	})
	hostDev.DeactivateApplication(appUUID, waitUntilDeactivated, timeout)
}

// forEachDeviceExcept calls fn on every device except the excluded one,
// in parallel.
func (ec *EdgeCluster) forEachDeviceExcept(
	exclude *EdgeDevice, fn func(dev *EdgeDevice)) {
	var others []*EdgeDevice
	for _, dev := range ec.devices {
		if dev.devName != exclude.devName {
			others = append(others, dev)
		}
	}
	RunParallel(len(others), func(i int) {
		fn(others[i])
	})
}

func (ec *EdgeCluster) checkDevices(method string) {
	if len(ec.devices) == 0 {
		ec.th.t.Fatalf("%s: no devices in cluster %q (call ApplyConfig first)",
			method, ec.clusterName)
	}
}
