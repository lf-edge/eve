// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test collection and delivery of application logs to the controller.

package apps_test

import (
	"regexp"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// Banner printed once by lfedge/evetest-logger-ctr on container start.
	loggerAppStartupMsg = "evetest-logger-ctr: started"
	// Heartbeat printed by the same app every few seconds, with a counter
	// that restarts from 1 on every (re)creation of the container.
	loggerAppHeartbeatRE = `evetest-logger-ctr: heartbeat [0-9]+`
)

// TestAppLogs verifies that EVE captures the standard output of a container
// application and delivers it to the controller as application log messages,
// both for the very first output produced at container creation and for
// output produced continuously afterwards, and that log collection resumes
// after the application is stopped and started again.
//
// The application is lfedge/evetest-logger-ctr, a minimal container that
// prints a one-off startup banner and then a numbered heartbeat every few
// seconds. The banner is what makes the restart phase verifiable without
// relying on timestamps: the count of banner occurrences must grow from one
// to two once the app has been recreated. Device and application clocks can
// differ, so counting is preferred over filtering log entries by time.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- logs travel over the device's own
//     management connectivity, so a single mgmt+apps port with DHCP suffices.
//     The app needs no connectivity of its own.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps). Log delivery needs no tuning:
//     the framework already defaults newlog.allow.fastupload to true.
//   - Local NI "local-ni" (10.11.12.0/24, gateway .1) on ethernet0.
//   - Container app "logger-app" (lfedge/evetest-logger-ctr) with a single
//     VIF on the NI and an allow-all ACL. No port forwarding: the test never
//     enters the app, it only reads what the app printed.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied -> app-is-running: the container is up.
//  2. startup-log-received: the startup banner appears in the application
//     logs. This covers output produced before anything could be injected
//     into the app from the outside, i.e. the container-creation log path.
//  3. heartbeat-logs-received: at least three heartbeat lines arrive,
//     proving logs keep streaming rather than being captured only once.
//  4. app-stopped -> app-started: deactivate the app and wait for HALTED,
//     then activate it again and wait for RUNNING.
//  5. startup-log-received-after-restart: the startup banner is now present
//     twice, so the recreated container's output is being collected again.
//  6. Delete the app and wait until the device reports it gone.
//
// Log assertions poll GetAppLogs via Eventually; evetest has no channel-based
// watch for application logs yet (only WatchLogs for device logs), so a
// deliberately coarse polling interval is used.
//
// Test params
// -----------
//   - HYPERVISOR. Under Kubevirt the test waits for the cluster node to
//     become ready before deploying the app.
//
// Suite placement
// ---------------
//   - TestApplicationSuite (deploys an app, hence hypervisor-parameterized).
func TestAppLogs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := addLocalNI(devConfig)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "logger-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: loggerCtrImage,
			Tag:       loggerCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)
	evetest.Checkpoint("app-is-running")

	const (
		logTimeout        = 10 * time.Minute
		logPolling        = 10 * time.Second
		appRestartTimeout = 5 * time.Minute
	)

	// Phase 2: output produced at container creation reaches the controller.
	t.Eventually(func() int {
		return countAppLogs(device, appUUID, evetest.LogMsgMatch{
			MsgHasSubstring: loggerAppStartupMsg,
		})
	}, logTimeout, logPolling).Should(BeNumerically(">=", 1),
		"Application startup message was not reported to the controller")
	evetest.Checkpoint("startup-log-received")

	// Phase 3: logs keep streaming while the app runs.
	t.Eventually(func() int {
		return countAppLogs(device, appUUID, evetest.LogMsgMatch{
			MsgMatchesRegexp: *regexp.MustCompile(loggerAppHeartbeatRE),
		})
	}, logTimeout, logPolling).Should(BeNumerically(">=", 3),
		"Application heartbeat messages were not reported to the controller")
	evetest.Checkpoint("heartbeat-logs-received")

	// Phase 4: stop and start the application.
	device.DeactivateApplication(appUUID, true, appRestartTimeout)
	evetest.Checkpoint("app-stopped")
	device.ActivateApplication(appUUID, true, appRestartTimeout)
	evetest.Checkpoint("app-started")

	// Phase 5: the recreated container prints the banner again.
	t.Eventually(func() int {
		return countAppLogs(device, appUUID, evetest.LogMsgMatch{
			MsgHasSubstring: loggerAppStartupMsg,
		})
	}, logTimeout, logPolling).Should(BeNumerically(">=", 2),
		"Application startup message was not reported again after app restart")
	evetest.Checkpoint("startup-log-received-after-restart")

	// Phase 6: clean up.
	deleteAppAndWait(t, device, devConfig, appUUID)
}

// countAppLogs returns how many application log messages published so far
// match the given criteria.
func countAppLogs(device *evetest.EdgeDevice, appUUID uuid.UUID,
	match evetest.LogMsgMatch) int {
	return len(device.GetAppLogs(appUUID, match))
}
