// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/base"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// TestVMIRSStrandedReplicasRecovery is a chaos-style test: it deploys an app
// on a single-node EVE-K cluster, then bypasses the controller entirely and
// scales the app's VirtualMachineInstanceReplicaSet to 0 replicas directly
// via kubectl over SSH -- reproducing the state an interrupted
// DetachUtilVmirsReplicaReset (pkg/pillar/kubeapi/kubeapi.go) can leave
// behind on a real failover, without needing to actually trigger a failover.
// It then verifies that EVE notices and self-heals: the app surfaces a
// retryable warning instead of silently staying "RUNNING", and later
// returns to RUNNING with no error once domainmgr's boot-retry loop repairs
// the replica count.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, SDN DNS, controller
//     reachable. No app-facing connectivity is exercised by this test, so no
//     port forwarding or outbound ACL is needed.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirements (cluster_test.go): WithHypervisor=Kubevirt,
//     DeviceReusePolicy=CreateFromScratchWithLiveImage, ext4.
//   - SystemAdapter on eth0 (DHCP, mgmt+app, NetworkType=V4Only).
//   - timer.boot.retry (DomainBootRetryTime) lowered to its 10s floor
//     (GlobalConfigMinimums), so domainmgr's boot-retry loop -- which
//     defaults to a 600s interval -- runs often enough to keep this test's
//     runtime reasonable.
//   - One Local NI "local-ni" and one container app (VirtualizationMode
//     left at its default, i.e. not NOHYPER, so the app is backed by a
//     VMIRS/VMI rather than a plain k8s ReplicaSet -- the code path this
//     bug is specific to).
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter() (suite-wide, see TestNodeClusterSuite).
//
// Phases
// ------
//  1. setup-done -> initial-config-applied: apply the device config and
//     start watching the app's ZInfoApp.
//  2. app-is-deployed: WaitUntilAppIsRunning (10 min budget excluding
//     download).
//  3. vmirs-scaled-to-zero: over SSH, `eve exec kube kubectl patch vmirs
//     --type=merge` (kubectl only exists inside the "kube" container) the
//     app's VMIRS (name computed via base.GetAppKubeName, matching how
//     pillar names it) to Spec.Replicas=0. This is the same
//     recipe used to reproduce the bug manually (see the design doc's
//     on-device reproduction section); StopReplicaVMI deletes the VMIRS
//     rather than scaling it, so zero replicas is never a state the
//     control plane produces on its own -- an SSH-injected patch is the
//     only way to reach it deterministically without a real, racy
//     failover.
//  4. stranded-vmirs-detected: ZInfoApp reports an AppErr with
//     Severity=WARNING and a non-empty RetryCondition -- domainmgr's
//     Info()/verifyStatus path noticing the stranded VMIRS, rather than
//     silently keeping the app "RUNNING" with a non-existent VMI.
//  5. app-recovered: ZInfoApp returns to State=RUNNING with no AppErr --
//     maybeRetryBoot re-invoked Start(), which raised Spec.Replicas back
//     to 1, and a new VMI/pod came up.
//
// Assertions are made purely against ZInfoApp (the EVE API); the SSH
// session is used only to inject the fault, never to read pillar's
// internal state.
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite (cluster tests are pinned to Kubevirt; this bug
//     is specific to the VMIRS/VMI code path).
func TestVMIRSStrandedReplicasRecovery(test *testing.T) {
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
	requiredDevice := clusterDeviceRequirements(devName, withTPM, evetest.FilesystemEXT4, false)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.DomainBootRetryTime, 10)
	devConfig.SetConfigProperties(cfgProps)
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
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	const appDisplayName = "vmirs-chaos-app"
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
			},
		},
	})

	device := evetest.GetEdgeDevice(devName)
	updates, stopWatch := device.WatchAppInfo(appUUID)
	defer stopWatch()
	device.ApplyConfig(devConfig, true, true)
	log := evetest.Logger()
	log.Infof("Submitted config with app UUID=%v", appUUID)
	evetest.Checkpoint("initial-config-applied")

	timeoutExcludingDownload := 10 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-is-deployed")

	// Scale the app's VMIRS to 0 replicas, bypassing the controller. This is
	// the exact state DetachUtilVmirsReplicaReset can strand a VMIRS in if
	// interrupted between its scale-to-0 and scale-to-1 writes.
	//
	// The VMIRS name is GetAppKubeName(displayName, uuid) + "-" + purgeCounter
	// (pkg/pillar/base/kubevirt.go, GetAppKubeNameWithPurge); purgeCounter is
	// 0 for a freshly deployed app. Appended manually rather than calling
	// GetAppKubeNameWithPurge directly since that helper postdates the
	// pkg/pillar version currently pinned in evetest/go.mod.
	vmirsName := fmt.Sprintf("%s-0", base.GetAppKubeName(appDisplayName, appUUID))
	sshTimeout := 20 * time.Second
	// kubectl only exists inside the "kube" container, not the host SSH
	// shell, so run it via "eve exec kube" (see vaultLogicalUsed in
	// tests/storage/vault_trim_test.go for the equivalent "eve exec pillar"
	// pattern).
	patchCmd := fmt.Sprintf(
		`eve exec kube kubectl -n eve-kube-app patch vmirs %s --type=merge -p '{"spec":{"replicas":0}}'`,
		vmirsName)
	log.Infof("Injecting fault: %s", patchCmd)
	_, stderr, err := device.RunShellScript(patchCmd, sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), stderr)
	evetest.Checkpoint("vmirs-scaled-to-zero")

	// EVE should notice the stranded VMIRS and report a retryable warning,
	// rather than silently keeping the app "RUNNING" (the pre-fix behavior:
	// Info() returned UNKNOWN with a nil error for a zero-replica VMIRS,
	// which verifyStatus never surfaces as an error).
	detectionTimeout := 3 * time.Minute
	t.Eventually(updates, detectionTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app reports a retryable warning for the stranded VMIRS",
		func(ainfo *eveinfo.ZInfoApp) bool {
			for _, appErr := range ainfo.GetAppErr() {
				if appErr.GetSeverity() == eveinfo.Severity_SEVERITY_WARNING &&
					appErr.GetRetryCondition() != "" {
					return true
				}
			}
			return false
		})))
	evetest.Checkpoint("stranded-vmirs-detected")

	// domainmgr's maybeRetryBoot should re-invoke Start(), which raises
	// Spec.Replicas back to 1 (ensureVmirsReplicas), and the app should
	// return to RUNNING with the error cleared, without any further
	// intervention.
	recoveryTimeout := 5 * time.Minute
	t.Eventually(updates, recoveryTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app recovered to RUNNING with no error",
		func(ainfo *eveinfo.ZInfoApp) bool {
			return ainfo.GetState() == eveinfo.ZSwState_RUNNING && len(ainfo.GetAppErr()) == 0
		})))
	evetest.Checkpoint("app-recovered")
}
