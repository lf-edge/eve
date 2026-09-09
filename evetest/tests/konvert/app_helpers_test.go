// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// The container app the escripts deploy, and how to get into it.
const (
	appSSHUser     = "root"
	appSSHPassword = "testpassword"
	appSSHFwdPort  = 2222
	sshTimeout     = 20 * time.Second

	// appImageName is the container image the escripts use as their test app
	// (eden's eclient equivalent for evetest).
	appImageName = "lfedge/evetest-ubuntu-ctr"
	appImageTag  = "1.0"

	// appMemoryBytes and appCPUs match what the escripts give the container
	// app (`--memory=512MB`).
	appMemoryBytes = 512 * evetest.MiB
	appCPUs        = 1

	// dataMountDir is where a container app's data volume is mounted on
	// EVE-kvm. On EVE-K it is not auto-mounted there (lf-edge/eve#6145), which
	// is why the marker is read back off the raw device instead.
	dataMountDir = "/mnt/data"
)

// appAuth is how every app in this package is logged into.
var appAuth = evetest.UsernamePasswordAuth{Username: appSSHUser, Password: appSSHPassword}

// addTestApp adds the standard container app on a switch network instance.
//
// A SWITCH (bridged L2) network instance rather than a local one: across the
// conversion, a local NI does not reconverge onto the kubevirt VMI, so a
// carried app never regains an address, while a switch NI does. The port
// forward is kept as a second way in for the case where the app's own address
// is not yet routable.
func addTestApp(devConfig *evetest.EdgeDeviceConfig, displayName string,
	niUUID uuid.UUID) uuid.UUID {
	return devConfig.AddApplication(testAppConfig(displayName, niUUID))
}

// addTestAppWithVolume is addTestApp with a data volume mounted at
// dataMountDir.
func addTestAppWithVolume(devConfig *evetest.EdgeDeviceConfig, displayName string,
	niUUID, dataVolUUID uuid.UUID) uuid.UUID {
	appConfig := testAppConfig(displayName, niUUID)
	appConfig.Mounts = []evetest.MountConfig{
		{VolumeUUID: dataVolUUID, MountDir: dataMountDir},
	}
	return devConfig.AddApplication(appConfig)
}

// testAppConfig is the app both forms share.
func testAppConfig(displayName string, niUUID uuid.UUID) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName:        displayName,
		Activate:           true,
		Image:              evetest.DockerContainer{ImageName: appImageName, Tag: appImageTag},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               appCPUs,
		MemoryBytes:        appMemoryBytes,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: appSSHFwdPort, AppPort: 22},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{Protocol: evetest.NetworkProtocolAny, RemoteSubnet: evetest.IPSubnet("0.0.0.0/0")},
				},
			},
		},
	}
}

// assertAppSSH asserts the app answers over SSH, retrying long enough to absorb
// the app's network reconvergence as well as SSH itself.
//
// No separate wait for a routable address first: the escripts do not have one,
// and folding both into a single retry means a slow reconvergence still passes
// while a genuinely stuck app fails here with the network capture attached.
func assertAppSSH(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) {
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, "hostname", sshTimeout, 0)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).NotTo(BeEmpty())
	}, appSSHTimeout, 10*time.Second).Should(Succeed())
}

// assertAppReady waits for an app to be usable end to end: running, then
// answering SSH. The caller chooses the running budget, which the escripts set
// per scenario.
func assertAppReady(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	runningTimeout time.Duration) {
	device.WaitUntilAppIsRunning(appUUID, runningTimeout)
	assertAppSSH(t, device, appUUID)
}

// assertContentTreeAvailable asserts a content tree's blobs are on the device:
// downloaded, verified, and available to anything that asks for them.
//
// DELIVERED is the success state, and the one to assert on. A content tree that
// has finished loading its blobs into the content-addressable store reaches
// pillar's internal LOADED, which is reported to the controller as
// ZSwState_DELIVERED -- pkg/pillar/types/types.go maps it that way behind a
// standing "TBD return info.ZSwState_LOADED". So ZSwState_LOADED is a value
// pillar does not currently send for a content tree, and waiting for it waits
// forever. LOADED is accepted too, so this keeps holding if that TBD is ever
// resolved.
func assertContentTreeAvailable(t Gomega, device *evetest.EdgeDevice,
	ctUUID uuid.UUID, timeout time.Duration) {
	t.Eventually(func(g Gomega) {
		info := device.GetContentTreeInfo(ctUUID)
		g.Expect(info).NotTo(BeNil(), "the device reports no such content tree")
		g.Expect(info.GetState()).To(BeElementOf(
			eveinfo.ZSwState_DELIVERED, eveinfo.ZSwState_LOADED),
			"content tree is %s; its blobs are not on the device", info.GetState())
	}, timeout, 10*time.Second).Should(Succeed())
}

// assertNoLiveVolumes asserts the device holds no volume that would block a
// cross-flavor upgrade. Volumes on their way out are tolerated -- the check is
// retried, so a delete still settling passes once it completes.
func assertNoLiveVolumes(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device,
			"eve exec pillar sh -c 'ls /run/volumemgr/VolumeStatus/*.json 2>/dev/null | wc -l'")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal("0"),
			"the device still has live volumes; this test needs none")
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// writeVolumeMarker writes a marker into the app's mounted data volume and
// flushes it, failing if the volume is not mounted where it should be.
//
// Run before the conversion, on EVE-kvm, where the shim does mount a blank
// volume at its MountDir.
func writeVolumeMarker(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	mountDir, marker string) {
	script := fmt.Sprintf(
		"grep -q ' %s ' /proc/mounts || { echo NOT-MOUNTED; cat /proc/mounts; exit 1; }; "+
			"echo %q > %s/marker && sync && echo WROTE-OK",
		mountDir, marker, mountDir)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, script, 60*time.Second, 0)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("WROTE-OK"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// assertVolumeMarker asserts the marker survived, by scanning the volume's raw
// block device from inside the app.
//
// Not by reading the mount point: on EVE-K the data volume is not auto-mounted
// at its MountDir (lf-edge/eve#6145), so a mount-based check would report the
// data lost when the volume is merely unmounted -- which is a different outcome
// entirely from the one this is meant to catch. The volume appears as a virtio
// disk after the rootfs.
func assertVolumeMarker(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, marker string) {
	script := fmt.Sprintf(
		"for d in /dev/vd[b-z] /dev/sd[b-z]; do [ -b \"$d\" ] || continue; "+
			"grep -aq %q \"$d\" 2>/dev/null && { echo FOUND-ON $d; exit 0; }; done; "+
			"echo NOT-FOUND; ls -l /dev/vd* /dev/sd* 2>/dev/null; lsblk 2>/dev/null; blkid 2>/dev/null; exit 1",
		marker)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, script, 90*time.Second, 0)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("FOUND-ON"))
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// assertVolumeCreated asserts a volume reaches CREATED_VOLUME, the state in
// which it is backed by real storage and an app can be started on it.
//
// Asserted separately from the app that uses it: an app that never starts
// because its volume was never created is a different finding from one that
// fails for its own reasons, and waiting on the app alone cannot tell them
// apart.
func assertVolumeCreated(t Gomega, device *evetest.EdgeDevice,
	volumeUUID uuid.UUID, timeout time.Duration) {
	t.Eventually(func(g Gomega) {
		info := device.GetVolumeInfo(volumeUUID)
		g.Expect(info).NotTo(BeNil(), "the device reports no such volume")
		g.Expect(info.GetState()).To(Equal(eveinfo.ZSwState_CREATED_VOLUME),
			"the volume is %s, not created", info.GetState())
	}, timeout, 15*time.Second).Should(Succeed())
}
