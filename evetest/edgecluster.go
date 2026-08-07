// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
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
// see EdgeDevice.ApplyConfig for their semantics.
// The set of cluster devices is collected from the EdgeClusterConfig nodes
// and stored for use by subsequent methods.
func (ec *EdgeCluster) ApplyConfig(
	clusterConfig *EdgeClusterConfig, waitUntilFetched bool, waitUntilConfirmed bool) {
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
		ec.devices[i].ApplyConfig(
			clusterConfig.GetDeviceConfig(node.DevName), waitUntilFetched, waitUntilConfirmed)
	})
}

// WaitUntilNodesAreReady waits until any device in the cluster reports
// all cluster nodes as Ready via ZInfoKubeCluster. Only the elected leader
// node publishes cluster info, so the function succeeds as soon as any
// single device reports all nodes ready. It fails if the timeout expires
// before that happens.
func (ec *EdgeCluster) WaitUntilNodesAreReady(timeout time.Duration) {
	if len(ec.devices) == 0 {
		ec.th.t.Fatalf("WaitUntilNodesAreReady: no devices in cluster %q "+
			"(call ApplyConfig first)", ec.clusterName)
	}
	ec.th.log.Infof("Waiting for %d cluster node(s) in %q to become ready...",
		len(ec.devices), ec.clusterName)

	expectedNodes := make([]string, len(ec.devices))
	for i, dev := range ec.devices {
		expectedNodes[i] = dev.devName
	}

	ctx, cancel := context.WithTimeout(ec.th.ctx, timeout)
	defer cancel()
	// doneCh is closed when any device reports all nodes ready,
	// signalling the other goroutines to stop waiting.
	doneCh := make(chan struct{})
	closeOnce := sync.Once{}
	RunParallel(len(ec.devices), func(i int) {
		dev := ec.devices[i]
		// Subscribe before taking the initial snapshot, so a transition
		// landing between the two calls can never be missed.
		updates, stop := dev.WatchClusterInfo()
		defer stop()
		if info := dev.GetClusterInfo(); info != nil && allNodesReady(info, expectedNodes) {
			ec.th.log.Infof("All cluster nodes already ready per device %q",
				dev.devName)
			closeOnce.Do(func() { close(doneCh) })
			return
		}
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
				if allNodesReady(info, expectedNodes) {
					ec.th.log.Infof("All cluster nodes reported as ready by device %q",
						dev.devName)
					closeOnce.Do(func() { close(doneCh) })
					return
				}
			case <-tickerCh:
				if i == 0 {
					ec.th.log.Infof("Waiting for cluster nodes %v to become ready...",
						expectedNodes)
				}
			case <-doneCh:
				return
			case <-ctx.Done():
				ec.th.t.Fatalf("Timed out waiting for cluster nodes to become ready "+
					"in cluster %q (device %q)", ec.clusterName, dev.devName)
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
// It watches ZInfoKubeCluster updates from all devices and returns the device
// whose cluster info reports the app (matched by display name) in EveApps
// or EveVmApps with a non-empty NodeName.
//
// Pass excludeDevNames to wait for the app to move OFF the named devices, which
// is what a failover test needs. Without it, this can return a device that no
// longer hosts the app: each device's last published cluster info is consulted
// first, and that snapshot can predate the event the caller is waiting for -
// most visibly when the excluded device is powered off, since its own stale
// snapshot still names it as the host and it publishes nothing further.
// Excluded devices are skipped as a source of cluster info and are never
// returned, so the answer can only come from a device that is still up.
func (ec *EdgeCluster) FindDeviceHostingApp(appUUID uuid.UUID,
	timeout time.Duration, excludeDevNames ...string) *EdgeDevice {
	ec.checkDevices("FindDeviceHostingApp")
	ctx, cancel := context.WithTimeout(ec.th.ctx, timeout)
	defer cancel()
	appUUIDStr := appUUID.String()

	excluded := make(map[string]bool, len(excludeDevNames))
	for _, name := range excludeDevNames {
		excluded[name] = true
	}

	// Look up the app display name from the first device's config.
	var appDisplayName string
	for _, dev := range ec.devices {
		config := dev.getConfig(false)
		for _, app := range config.GetApps() {
			if app.GetUuidandversion().GetUuid() == appUUIDStr {
				appDisplayName = app.GetDisplayname()
				break
			}
		}
		if appDisplayName != "" {
			break
		}
	}
	if appDisplayName == "" {
		ec.th.t.Fatalf("Application %q not found in any cluster device config",
			appUUID)
	}

	// hostingNode returns the node the info reports as hosting the app, unless
	// that node is excluded - an excluded node is what the caller is waiting for
	// the app to leave, so reporting it is never the answer.
	hostingNode := func(info *eveinfo.ZInfoKubeCluster) string {
		nodeName := findAppNodeName(info, appDisplayName)
		if nodeName == "" || excluded[nodeName] {
			return ""
		}
		return nodeName
	}

	// deviceByName maps a reported node name back to a cluster device.
	deviceByName := func(nodeName string) *EdgeDevice {
		for _, dev := range ec.devices {
			if dev.devName == nodeName {
				return dev
			}
		}
		ec.th.t.Fatalf("Node %q reports hosting app %q, but no matching device "+
			"was found in cluster %q", nodeName, appUUID, ec.clusterName)
		return nil
	}

	type result struct {
		nodeName string
	}
	resultCh := make(chan result, 1)

	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()

	// Subscribe before taking the cached snapshot below, so an update landing
	// between the two is not missed.
	for _, dev := range ec.devices {
		if excluded[dev.devName] {
			// A device the app must move off is not a trustworthy source: if it
			// is powered off it publishes nothing, and its last snapshot is
			// stale by definition.
			continue
		}
		updates, stop := dev.WatchClusterInfo()
		go func(updates <-chan *eveinfo.ZInfoKubeCluster, stop func()) {
			defer stop()
			for {
				select {
				case info, ok := <-updates:
					if !ok {
						return
					}
					if nodeName := hostingNode(info); nodeName != "" {
						select {
						case resultCh <- result{nodeName: nodeName}:
						default:
						}
						return
					}
				case <-subCtx.Done():
					return
				}
			}
		}(updates, stop)
	}

	// Then check the cluster info each still-eligible device has already
	// published, so the common case does not have to wait for a fresh message.
	for _, dev := range ec.devices {
		if excluded[dev.devName] {
			continue
		}
		if info := dev.GetClusterInfo(); info != nil {
			if nodeName := hostingNode(info); nodeName != "" {
				return deviceByName(nodeName)
			}
		}
	}

	select {
	case res := <-resultCh:
		subCancel()
		return deviceByName(res.nodeName)
	case <-ctx.Done():
		if len(excludeDevNames) > 0 {
			ec.th.t.Fatalf("Timed out waiting for app %q to move off %v in cluster %q",
				appUUID, excludeDevNames, ec.clusterName)
		}
		ec.th.t.Fatalf("Timed out waiting for app %q to be scheduled in cluster %q",
			appUUID, ec.clusterName)
	}
	return nil // unreachable
}

// findAppNodeName checks if the given cluster info contains the app
// (by display name) in EveApps or EveVmApps with a non-empty NodeName.
// Kubernetes adds a hash suffix to the display name (e.g. "my-app-abcde12345"),
// so we match by prefix with a "-" separator.
func findAppNodeName(info *eveinfo.ZInfoKubeCluster, appDisplayName string) string {
	prefix := appDisplayName + "-"
	matchesName := func(name string) bool {
		return name == appDisplayName || strings.HasPrefix(name, prefix)
	}
	for _, app := range info.GetEveApps() {
		if matchesName(app.GetName()) && app.GetNodeName() != "" {
			return app.GetNodeName()
		}
	}
	for _, vm := range info.GetEveVmApps() {
		if matchesName(vm.GetName()) && vm.GetNodeName() != "" {
			return vm.GetNodeName()
		}
	}
	return ""
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
// is performed only on the device hosting the application.
func (ec *EdgeCluster) PurgeApplication(appUUID uuid.UUID, waitUntilPurged bool,
	timeout time.Duration) {
	ec.checkDevices("PurgeApplication")
	hostDev := ec.FindDeviceHostingApp(appUUID, timeout)
	ec.forEachDeviceExcept(hostDev, func(dev *EdgeDevice) {
		dev.PurgeApplication(appUUID, false, 0)
	})
	hostDev.PurgeApplication(appUUID, waitUntilPurged, timeout)
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
