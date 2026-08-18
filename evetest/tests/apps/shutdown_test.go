// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestDeviceShutdownAndRecovery verifies EVE's controller-driven "shut down
// all app instances" operation (Eden's `eden controller edge-node shutdown`)
// and recovery from it: the app must reach HALTED as the device passes
// through DEVICE_STATE_PREPARING_POWEROFF and DEVICE_STATE_PREPARED_POWEROFF,
// and it must come back to RUNNING -- along with its network instance --
// once the device is rebooted, even if connectivity is lost for a while
// right after the reboot starts.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port. Local NI "local-ni"
//     hosts a single app with a port-forwarded SSH endpoint, used to confirm
//     the app is actually reachable, not just reporting RUNNING.
//
// Phases
// ------
//  1. Deploy "shutdown-app". WaitUntilAppIsRunning, then confirm it is
//     reachable over SSH.
//  2. PrepareShutdown: bump the config's Shutdown counter. Confirm the
//     device reaches DEVICE_STATE_PREPARING_POWEROFF, the app reaches
//     HALTED, and the device then reaches DEVICE_STATE_PREPARED_POWEROFF.
//     PrepareShutdown has no power effect of its own -- the device sits in
//     PREPARED_POWEROFF indefinitely until a separate reboot/power-off step
//     moves it, which is what the next phase provides.
//  3. Recovery: RequestReboot(false) (fire-and-forget -- the device won't
//     confirm the reboot over the management path while that path is about
//     to be cut below, so waiting here would just time out). Shortly after,
//     simulate a network outage by setting the SDN port's AdminUp to false
//     for several minutes, mirroring Eden's qemu/vbox-specific outage
//     injection -- unlike Eden, this applies unconditionally here, since
//     evetest's AdminUp toggle is a provider-agnostic SDN mechanism rather
//     than a devmodel-specific one. Restore AdminUp afterwards.
//  4. Confirm recovery: the app reaches RUNNING again, the network instance
//     reaches ZNETINST_STATE_ONLINE again (Eden's "ACTIVATED"), and the app
//     is reachable over SSH again.
//  5. Cleanup: delete the app, confirm it is gone and detached from the NI,
//     then delete the NI and confirm it is gone too.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestAppsSuite.
func TestDeviceShutdownAndRecovery(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
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

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
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
		DisplayName: "shutdown-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
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

	// Open watches before applying config: subsequent Eventually calls on
	// these channels only ever consume forward-going messages, giving us
	// Eden's "-check-new" semantics for free.
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	device.ApplyConfig(devConfig, true, true)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-running")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	timeout := 5 * time.Minute
	polling := 3 * time.Second
	log := evetest.Logger()
	verifySSHReachable := func() {
		log.Infof("Waiting for app SSH daemon to become reachable...")
		t.Eventually(func(g Gomega) {
			_, _, err := device.RunShellScriptInsideApp(
				appUUID, appAuth, "echo hello", sshTimeout, 0)
			g.Expect(err).ToNot(HaveOccurred())
		}, timeout, polling).Should(Succeed())
	}
	verifySSHReachable()

	// Phase 2: shut down all app instances via the controller.
	log.Infof("Requesting device shutdown via the controller...")
	device.PrepareShutdown()

	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"device reaches PREPARING_POWEROFF",
		func(info *eveinfo.ZInfoDevice) bool {
			return info.GetState() == eveinfo.ZDeviceState_ZDEVICE_STATE_PREPARING_POWEROFF
		})))
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"shutdown-app reaches HALTED",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_HALTED
		}).StopIf(appHasError)))
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"device reaches PREPARED_POWEROFF",
		func(info *eveinfo.ZInfoDevice) bool {
			return info.GetState() == eveinfo.ZDeviceState_ZDEVICE_STATE_PREPARED_POWEROFF
		})))
	evetest.Checkpoint("shutdown-done")

	// Phase 3: reboot to recover, injecting a network outage during the
	// reboot window to confirm recovery does not depend on connectivity
	// being available right away.
	log.Infof("Rebooting the device to recover from the shutdown...")
	device.RequestReboot(false)
	time.Sleep(20 * time.Second)

	log.Infof("Simulating a network outage during the reboot window...")
	const outageWindow = 7 * time.Minute
	downModel := proto.Clone(netmodels.SingleEthWithDHCP).(*api.NetworkModel)
	for _, p := range downModel.Ports {
		if p.LogicalLabel == "eth0" {
			p.AdminUp = false
		}
	}
	evetest.UpdateNetworkModel(downModel)
	restoreModel := func() {
		evetest.UpdateNetworkModel(netmodels.SingleEthWithDHCP)
	}
	defer restoreModel()
	time.Sleep(outageWindow)

	log.Infof("Restoring the network...")
	restoreModel()
	evetest.Checkpoint("network-restored")

	// Phase 4: confirm recovery.
	recoveryTimeout := 10 * time.Minute
	t.Eventually(appUpdates, recoveryTimeout).Should(Receive(matchers.SatisfyPredicate(
		"shutdown-app is RUNNING again",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_RUNNING
		}).StopIf(appHasError)))
	t.Eventually(niUpdates, recoveryTimeout).Should(Receive(matchers.SatisfyPredicate(
		"local-ni is ONLINE again",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	verifySSHReachable()
	evetest.Checkpoint("recovered-with-outage")

	// Cleanup: delete the app first, confirm it is gone and detached from
	// the NI's VIF list, then delete the NI.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"shutdown-app is gone",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopAppWatch()
	evetest.Checkpoint("app-deleted")

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"local-ni has no VIFs attached",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return len(info.Vifs) == 0
		})))

	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"local-ni is gone",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		})))
	stopNIWatch()
}
