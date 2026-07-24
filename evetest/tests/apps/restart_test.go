// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Application life-cycle operations tested against the EVE API:
// controller-requested restart of an application instance.

package apps_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestAppRestart verifies that a controller-requested application restart
// (a bump of the restart counter in AppInstanceConfig, i.e. a domain
// restart *without* purge) brings the application back to the RUNNING
// state, several times in a row.
//
// A restart without purge tears the domain down and re-creates it under
// the same domain name, reusing the same QMP socket paths. That reuse is
// what exposes the stale-QMP-handler race: the torn-down qemu's leftover
// qmpEventHandler reacts to the final host-initiated SHUTDOWN event by
// issuing stop+quit on the executor socket *path*, retrying for ~30s; if
// the re-created qemu re-binds that path within the retry window, the
// handler quits the new instance instead. domainmgr then sees "unexpected
// state HALTED", marks the boot failed and retries only after the ~10
// minute boot-retry backoff -- so the app does not return within the
// per-restart budget below and the test fails.
//
// IMPORTANT: whether this test actually reproduces the race is timing
// dependent, so it fails only *sometimes*. The race fires only when the
// re-created qemu's QMP becomes reachable *before* the stale handler's
// ~36s stop+quit retry window elapses. On a plain restart the re-create is
// itself largely a race against that window: the teardown spends up to
// ~30s in a QMP-status retry loop (hypervisor Cleanup) before the new qemu
// is even created, so the new instance lands close to the edge of the
// window. Natural variance in that teardown time decides each restart --
// when it runs short the re-create slips inside the window and the stale
// handler quits the new qemu ("Giving up waiting to connect to QEMU
// Monitor Protocol socket" / "unexpected state HALTED" -> ~10 min
// boot-retry backoff -> this test's per-restart budget expires and it
// fails); when it runs long the handler harmlessly gives up first. The
// restart is repeated many times so that at least one iteration is likely
// to land inside the window.
//
// Note: adding device CPU load does NOT make this more likely -- the retry
// windows are wall-clock sleeps, whereas load only stretches the CPU-bound
// part of the re-create and widens the gap. With the fix in place the test
// always passes (the handler ignores the host-initiated SHUTDOWN).
//
// Because the reproduction is probabilistic, this test is meant to be run
// on demand rather than as part of an unattended suite. A deterministic,
// unit-level test of the handler is a better permanent regression guard.
func TestAppRestart(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	// Kubevirt is only supported by cluster tests.
	evetest.SkipIfHypervisorKubevirt()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    hypervisor,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build the device configuration: one mgmt+apps port, one Local NI and
	// one container app connected to it.
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
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "restarted-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen, shim VM fails to start
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
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

	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)

	evetest.Checkpoint("app-deployed")

	// An app reaching RUNNING does not mean it has fully booted -- wait
	// until its SSH daemon is reachable through the 2222->22 port-forwarding
	// rule before considering the deployment complete.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	timeout := 3 * time.Minute
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()
	verifyAppOverSSH := func() {
		t.Eventually(func(t Gomega) {
			log.Infof("Waiting for app SSH daemon to start and become reachable...")
			output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				"hostname", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
			t.Expect(output).To(ContainSubstring(appUUID.String()))
		}, timeout, polling).Should(Succeed())
	}
	verifyAppOverSSH()

	// Record the baseline boot time; every restart below must advance it.
	var appInfo *eveinfo.ZInfoApp
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App is RUNNING and reports its boot time",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			return info.State == eveinfo.ZSwState_RUNNING &&
				info.GetBootTime() != nil
		}).StopIf(appHasError)))
	prevBootTime := appInfo.GetBootTime().AsTime()

	// Restart the application many times in a row. Each restart re-creates
	// the domain under the same name and reused QMP socket path; repeating
	// it many times increases the chance that natural variance in the
	// teardown time dips the re-create below the stale handler's retry
	// window and triggers the race (see the test description).
	const restartCount = 5
	// A healthy restart completes in well under a minute; only a boot that
	// hit the race (and thus the ~10 minute boot-retry backoff) exceeds this
	// budget, so a race turns into a prompt failure here rather than a long
	// stall.
	restartTimeout := 5 * time.Minute
	for i := 1; i <= restartCount; i++ {
		log.Infof("Restarting app (%d/%d)...", i, restartCount)
		device.RebootApplication(appUUID, false, 0)

		t.Eventually(appUpdates, restartTimeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("App has restarted (advanced boot time) and is RUNNING (%d/%d)",
				i, restartCount),
			func(info *eveinfo.ZInfoApp) bool {
				appInfo = info
				return info.GetBootTime() != nil &&
					info.GetBootTime().AsTime().After(prevBootTime) &&
					info.State == eveinfo.ZSwState_RUNNING
			}).StopIf(appHasError)))
		prevBootTime = appInfo.GetBootTime().AsTime()

		// The restarted app must not just report RUNNING but also be
		// functional again.
		verifyAppOverSSH()

		evetest.Checkpoint(fmt.Sprintf("app-restarted-%d", i))
	}
}

func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	if info.State == eveinfo.ZSwState_ERROR {
		return "Application instance is in error state", true
	}
	return "", false
}
