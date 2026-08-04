// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"strings"
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

// TestMountedVolumes verifies that an application can have additional,
// independently created volumes mounted alongside its root disk, that
// a mount can be dropped from a running application without affecting
// the underlying volume, and that the same volume can then be mounted again
// at a different MountDir without redownloading its content. Adding or
// removing a mount changes the app's VolumeRefList count, which EVE
// always treats as requiring a purge (a restart of the domain that preserves
// the app instance's identity -- not a full delete+recreate); UpdateApplication
// bumps the purge counter for this automatically, so each of these steps is
// followed by a PURGING -> RUNNING wait.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port; also provides
//     Internet access needed to pull the docker images used as mount content.
//
// Phases
// ------
//  1. Create two standalone volumes (AddVolume): tstVol from
//     docker://hello-world:linux, dirVol from docker://busybox:latest. Deploy
//     "mount-app" (lfedge/evetest-ubuntu-ctr:1.0, HVM) with an SSH
//     port-forward (2222->22) and Mounts referencing both volumes: tstVol at
//     /tst, dirVol at /dir. Wait for RUNNING and for the app's SSH daemon to
//     become reachable.
//  2. Verify (via RunShellScriptInsideApp) that /tst contains the
//     hello-world image's content and /dir contains busybox's. Then write a
//     marker file into /tst: hello-world's own baked-in content would look
//     identical whether tstVol is reused or redownloaded from scratch, so
//     the marker (written outside the image's own content) is what actually
//     proves reuse in step 4.
//  3. Update the app, dropping the /tst mount (UpdateApplication with only
//     dirVol in Mounts), and re-apply -- this triggers a purge (see above),
//     not a full redeploy. Verify /tst no longer has hello-world's content.
//     tstVol itself still exists (untouched by UpdateApplication; see
//     MountConfig).
//  4. Update the app again, mounting tstVol at MountDir "/dst" instead of
//     /tst. Verify /dst has both hello-world's content and the marker file
//     written in step 2 -- proof that this is the same volume from step 1,
//     not redownloaded -- while /dir (never touched) still has busybox's.
//  5. Cleanup: delete the app (removes its root volume only), wait for
//     ZSwState_INVALID, then delete tstVol and dirVol explicitly (their
//     lifecycle is independent of the app -- see MountConfig).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestMountedVolumes(test *testing.T) {
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
		evetest.RequireInternetConnectivity{},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

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
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "mount-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.21.21.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.21.21.2"),
			End:   evetest.IPAddress("10.21.21.254"),
		},
		Gateway: evetest.IPAddress("10.21.21.1"),
		MTU:     1500,
	})

	// Step 1: create the two volumes mounts will reference, then deploy the
	// app with Mounts pointing at them. appConfig is kept around and mutated
	// in later steps so each UpdateApplication call only changes Mounts,
	// leaving every other field (Image, CPUs, adapters, ...) exactly as
	// originally deployed.
	tstVolUUID := devConfig.AddVolume("mount-app-tst",
		evetest.DockerContainer{ImageName: "hello-world", Tag: "linux"}, 0)
	dirVolUUID := devConfig.AddVolume("mount-app-dir",
		evetest.DockerContainer{ImageName: "busybox", Tag: "latest"}, 0)

	appConfig := evetest.ApplicationInstanceConfig{
		DisplayName: "mount-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		Mounts: []evetest.MountConfig{
			{VolumeUUID: tstVolUUID, MountDir: "/tst"},
			{VolumeUUID: dirVolUUID, MountDir: "/dir"},
		},
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: 2222, AppPort: 22},
				},
			},
		},
	}
	appUUID := devConfig.AddApplication(appConfig)

	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("app-deployed")

	timeout := 15 * time.Minute
	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-running")

	sshTimeout := 20 * time.Second
	polling := 5 * time.Second
	log := evetest.Logger()

	log.Infof("Waiting for mount-app's SSH daemon to become reachable")
	t.Eventually(func(t Gomega) {
		_, _, err := device.RunShellScriptInsideApp(
			appUUID, ubuntuCtrAppAuth, "hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("ssh-ready")

	// Step 2: verify both mounts have the expected content.
	log.Infof("Verifying /tst (hello-world) and /dir (busybox) mount content")
	t.Eventually(func() (string, error) {
		out, _, err := device.RunShellScriptInsideApp(
			appUUID, ubuntuCtrAppAuth, "ls /tst", sshTimeout, 0)
		return out, err
	}, timeout, polling).Should(ContainSubstring("hello"))
	t.Eventually(func() (string, error) {
		out, _, err := device.RunShellScriptInsideApp(
			appUUID, ubuntuCtrAppAuth, "ls /dir/bin", sshTimeout, 0)
		return out, err
	}, timeout, polling).Should(ContainSubstring("busybox"))
	evetest.Checkpoint("mounts-verified")

	// Write a marker file into tstVol before detaching it. hello-world's own
	// baked-in content would look identical whether tstVol is reused or
	// redownloaded from scratch; a marker written here (outside the image's
	// content) only survives into step 4 if reattaching /dst reuses this
	// exact volume rather than recreating it.
	const markerContent = "mount-test-marker"
	_, _, err := device.RunShellScriptInsideApp(appUUID, ubuntuCtrAppAuth,
		"echo "+markerContent+" > /tst/marker.txt && sync", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	waitForPurge := func() {
		t.Eventually(appUpdates, 2*time.Minute).Should(Receive(matchers.SatisfyPredicate(
			"mount-app enters a transient purge state",
			func(info *eveinfo.ZInfoApp) bool {
				return info.State == eveinfo.ZSwState_PURGING ||
					info.State == eveinfo.ZSwState_HALTING
			})))
		device.WaitUntilAppIsRunning(appUUID, timeout)
	}

	// Step 3: drop the /tst mount. tstVol itself is untouched -- only the
	// app's VolumeRefList changes.
	log.Infof("Dropping the /tst mount")
	appConfig.Mounts = []evetest.MountConfig{
		{VolumeUUID: dirVolUUID, MountDir: "/dir"},
	}
	devConfig.UpdateApplication(appUUID, appConfig)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("tst-detached")
	waitForPurge()

	t.Eventually(func() (string, error) {
		out, _, err := device.RunShellScriptInsideApp(
			appUUID, ubuntuCtrAppAuth, "ls /tst", sshTimeout, 0)
		return out, err
	}, timeout, polling).ShouldNot(ContainSubstring("hello"))

	// Step 4: mount tstVol again, now at MountDir "/dst" -- the same volume,
	// so its already-downloaded content is reused, not redownloaded.
	log.Infof("Mounting tstVol at /dst")
	appConfig.Mounts = []evetest.MountConfig{
		{VolumeUUID: tstVolUUID, MountDir: "/dst"},
		{VolumeUUID: dirVolUUID, MountDir: "/dir"},
	}
	devConfig.UpdateApplication(appUUID, appConfig)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("tst-reattached")
	waitForPurge()

	t.Eventually(func() (string, error) {
		out, _, err := device.RunShellScriptInsideApp(
			appUUID, ubuntuCtrAppAuth, "ls /dst", sshTimeout, 0)
		return out, err
	}, timeout, polling).Should(ContainSubstring("hello"))

	// The marker written into tstVol before detaching it must have survived
	// -- proof that reattaching at /dst reused the same volume (and its
	// downloaded content), rather than recreating it from scratch.
	out, _, err := device.RunShellScriptInsideApp(
		appUUID, ubuntuCtrAppAuth, "cat /dst/marker.txt", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSpace(out)).To(Equal(markerContent))

	// /dir was never touched by the detach/reattach and must still be intact.
	out, _, err = device.RunShellScriptInsideApp(
		appUUID, ubuntuCtrAppAuth, "ls /dir/bin", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("busybox"))

	// Step 5: cleanup.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app is gone",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))

	// tstVol and dirVol outlive the app; remove them explicitly.
	devConfig.DeleteVolume(tstVolUUID)
	devConfig.DeleteVolume(dirVolUUID)
	device.ApplyConfig(devConfig, false, false)
}
