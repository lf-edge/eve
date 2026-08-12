// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// purgeMarkerPath is written into the app's root filesystem before the purge.
// A purge keeps the app's existing volumes (zedmanager's doUpdate: "Keep the
// old volumes in place"), so the marker is expected to SURVIVE. Only a
// purge&update, where the controller sends volume refs with new generation
// counters, causes volumemgr to build fresh volumes.
const purgeMarkerPath = "/root/purge-marker"

// appPurgeMarkerState reports "PRESENT" or "ABSENT" for purgeMarkerPath inside
// the app. Phrased as an echo rather than relying on the exit status of `test`,
// so the result does not depend on how a non-zero exit is surfaced.
func appPurgeMarkerState(device *evetest.EdgeDevice, appUUID uuid.UUID,
	auth evetest.AuthMethod, timeout time.Duration) (string, string, error) {
	return device.RunShellScriptInsideApp(appUUID, auth,
		"test -f "+purgeMarkerPath+" && echo PRESENT || echo ABSENT", timeout, 0)
}

// clusterHasVMIWithPrefix reports whether ZInfoKubeCluster lists a VMI whose
// name starts with prefix. VMIs created by a VMIRS are named
// "<vmirs-name>-<random suffix>", so the prefix identifies the owning VMIRS.
func clusterHasVMIWithPrefix(info *eveinfo.ZInfoKubeCluster, prefix string) bool {
	for _, vmi := range info.GetEveVmApps() {
		if strings.HasPrefix(vmi.GetName(), prefix) {
			return true
		}
	}
	return false
}

// TestAppInstancePurge verifies the happy-path purge of a running application on
// a single-node EVE-K cluster: no node outage, no node reboot, no injected
// fault. The controller increments the app's purge counter and EVE is expected
// to tear the old workload down and bring an equivalent one back up.
//
// Under Kubevirt a purge changes the app's Kubernetes identity -- the VMIRS name
// embeds the purge counter (base.GetAppKubeNameWithPurge) -- so the old VMIRS
// must be deleted before the new one is created. That teardown runs through
// domainmgr's handleModify path with impatient=true, which deliberately bypasses
// the cluster-trust guard in doInactivate that otherwise leaves a VMIRS alone
// while UserActivate=true. This test is the happy-path counterpart to
// TestVMIRSStrandedReplicasRecovery: that one injects a fault, this one checks
// the ordinary lifecycle is not disturbed.
//
// Purge vs. purge&update
// ----------------------
// A purge on its own does NOT recreate the app's volumes: zedmanager's doUpdate
// hands the teardown to doRemove with uninstall=false explicitly to "keep the
// old volumes in place", and purgeCmdDone only drops volume refs that the new
// config no longer references. Volumes are rebuilt only when the config carries
// new volume generation counters, i.e. a purge&update. This test therefore
// asserts the marker file SURVIVES; a future purge&update test should assert the
// opposite.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, SDN DNS, controller
//     reachable. Port forwarding (2222->22) is needed so the marker file can be
//     written and re-checked inside the app over SSH.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirements (cluster_test.go): WithHypervisor=Kubevirt,
//     DeviceReusePolicy=CreateFromScratchWithLiveImage, ext4. That policy
//     re-creates the VM even when a matching one exists, so this test always
//     forms its own cluster; only the harness (Adam, SDN, broker) is shared with
//     the other subtests. Running it standalone therefore costs no more than
//     running it as part of the suite.
//   - SystemAdapter on eth0 (DHCP, mgmt+app, NetworkType=V4Only).
//   - One Local NI "local-ni" and one container app (VirtualizationMode left at
//     its default, i.e. not NOHYPER, so the app is backed by a VMIRS/VMI rather
//     than a plain k8s ReplicaSet -- the code path a purge has to rename).
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter() (suite-wide, see TestNodeClusterSuite).
//
// Phases
// ------
//  1. setup-done -> initial-config-applied: apply the device config.
//  2. app-is-deployed: WaitUntilAppIsRunning (10 min budget excluding download).
//  3. marker-written: touch purgeMarkerPath inside the app and confirm it reads
//     back as PRESENT, wrapped in Eventually since the app's SSH daemon comes up
//     some time after the app reports RUNNING.
//  4. watches-started: subscribe to ZInfoApp and ZInfoKubeCluster, and record the
//     pre-purge VMIRS name. The watches are started HERE, immediately before the
//     purge, and not earlier: they are live subscriptions with buffered channels,
//     so a watch opened before the deployment would hand the assertions below the
//     entire deploy backlog and they would match stale RUNNING / non-RUNNING
//     messages instantly, passing without observing the purge at all.
//  5. purge-requested: increment the purge counter via PurgeApplication.
//     waitUntilPurged=false because that helper waits via IterateDeviceInfoMsgs,
//     which replays Adam's stored messages before following and so would match
//     the pre-purge RUNNING immediately.
//  6. app-left-running: ZInfoApp reports a state other than RUNNING. This proves
//     the purge was acted on rather than coalescing into a no-op, and is
//     deliberately "not RUNNING" rather than a specific PURGING/HALTING so the
//     test does not depend on which transitional states get published.
//  7. app-recovered: ZInfoApp returns to State=RUNNING with no AppErr.
//  8. vmirs-renamed: ZInfoKubeCluster lists a VMI belonging to the purge-counter-1
//     VMIRS and none belonging to the purge-counter-0 one. This is what separates
//     a purge from a plain restart -- a restart reuses the VMIRS name -- and it is
//     the assertion that would catch the old VMIRS being left behind.
//  9. volumes-preserved: purgeMarkerPath still reads PRESENT (see "Purge vs.
//     purge&update" above).
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite (cluster tests are pinned to Kubevirt; purge under
//     Kubevirt is the path being exercised).
func TestAppInstancePurge(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)
	withTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := clusterDeviceRequirements(devName, withTPM, evetest.FilesystemEXT4)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	const appDisplayName = "purge-app"
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: appDisplayName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		CPUs:        1,
		MemoryBytes: 500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	device := evetest.GetEdgeDevice(devName)
	device.ApplyConfig(devConfig, true, true)
	log := evetest.Logger()
	log.Infof("Submitted config with app UUID=%v", appUUID)
	evetest.Checkpoint("initial-config-applied")

	timeoutExcludingDownload := 10 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-is-deployed")

	// Mark the app's root filesystem so volume handling across the purge is
	// observable. RunShellScriptInsideApp uses the 2222->22 port forwarding rule.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	sshReadyTimeout := 3 * time.Minute
	polling := 3 * time.Second
	log.Infof("Writing purge marker %s inside the app", purgeMarkerPath)
	t.Eventually(func(t Gomega) {
		_, stderr, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"touch "+purgeMarkerPath, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred(), stderr)
	}, sshReadyTimeout, polling).Should(Succeed())
	stdout, stderr, err := appPurgeMarkerState(device, appUUID, appAuth, sshTimeout)
	t.Expect(err).ToNot(HaveOccurred(), stderr)
	t.Expect(stdout).To(ContainSubstring("PRESENT"))
	evetest.Checkpoint("marker-written")

	// Start the watches only now: they are live subscriptions over buffered
	// channels, so opening them earlier would leave the assertions below matching
	// the deploy backlog instead of the purge.
	//
	// The VMIRS name is GetAppKubeName(displayName, uuid) + "-" + purgeCounter
	// (pkg/pillar/base/kubevirt.go, GetAppKubeNameWithPurge); the counter is 0 for
	// a freshly deployed app and 1 after this test's purge. Appended manually
	// rather than calling GetAppKubeNameWithPurge directly since that helper
	// postdates the pkg/pillar version currently pinned in evetest/go.mod.
	kubeName := base.GetAppKubeName(appDisplayName, appUUID)
	vmirsBeforePurge := fmt.Sprintf("%s-0", kubeName)
	vmirsAfterPurge := fmt.Sprintf("%s-1", kubeName)
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	clusterUpdates, stopClusterWatch := device.WatchClusterInfo()
	defer stopClusterWatch()
	evetest.Checkpoint("watches-started")

	// Request the purge.
	log.Infof("Purging app %v (VMIRS %s -> %s)", appUUID,
		vmirsBeforePurge, vmirsAfterPurge)
	device.PurgeApplication(appUUID, false, 0)
	evetest.Checkpoint("purge-requested")

	// The app must actually leave RUNNING, otherwise a purge dropped on the floor
	// would satisfy the recovery assertion below trivially.
	purgeStartTimeout := 3 * time.Minute
	t.Eventually(appUpdates, purgeStartTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app left the RUNNING state to be purged",
		func(ainfo *eveinfo.ZInfoApp) bool {
			return ainfo.GetState() != eveinfo.ZSwState_RUNNING
		})))
	evetest.Checkpoint("app-left-running")

	// The app should come back with no error reported.
	recoveryTimeout := 10 * time.Minute
	t.Eventually(appUpdates, recoveryTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app returned to RUNNING with no error after the purge",
		func(ainfo *eveinfo.ZInfoApp) bool {
			return ainfo.GetState() == eveinfo.ZSwState_RUNNING &&
				len(ainfo.GetAppErr()) == 0
		})))
	evetest.Checkpoint("app-recovered")

	// The purge counter is part of the VMIRS name, so the workload must have moved
	// to the new VMIRS and the old one must be gone. A plain restart would keep
	// the old name, and a failed teardown would leave both present.
	vmirsTimeout := 5 * time.Minute
	t.Eventually(clusterUpdates, vmirsTimeout).Should(Receive(matchers.SatisfyPredicate(
		fmt.Sprintf("VMI moved to VMIRS %s and none left on %s",
			vmirsAfterPurge, vmirsBeforePurge),
		func(info *eveinfo.ZInfoKubeCluster) bool {
			return clusterHasVMIWithPrefix(info, vmirsAfterPurge) &&
				!clusterHasVMIWithPrefix(info, vmirsBeforePurge)
		})))
	evetest.Checkpoint("vmirs-renamed")

	// A purge keeps the app's volumes, so the marker must still be there.
	log.Infof("Checking that purge marker %s survived the purge", purgeMarkerPath)
	t.Eventually(func(t Gomega) {
		stdout, stderr, err := appPurgeMarkerState(device, appUUID, appAuth, sshTimeout)
		t.Expect(err).ToNot(HaveOccurred(), stderr)
		t.Expect(stdout).To(ContainSubstring("PRESENT"))
	}, sshReadyTimeout, polling).Should(Succeed())
	evetest.Checkpoint("volumes-preserved")
}
