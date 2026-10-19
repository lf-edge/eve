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
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// The container app the tests deploy, and how to get into it.
const (
	appSSHUser     = "root"
	appSSHPassword = "testpassword"
	appSSHFwdPort  = 2222
	sshTimeout     = 20 * time.Second

	// appImageName is the test app: a container with sshd, so the tests can
	// write and read markers inside it.
	appImageName = "lfedge/evetest-ubuntu-ctr"
	appImageTag  = "1.0"

	// appMemoryBytes and appCPUs keep the app small next to the 8 GiB device,
	// so the app does not compete with EVE-K for memory.
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
// No separate wait for a routable address first: folding both into a single
// retry means a slow reconvergence still passes
// while a genuinely stuck app fails here with the network capture attached.
func assertAppSSH(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID) {
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, "hostname", sshTimeout, 0)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).NotTo(BeEmpty())
	}, appSSHTimeout, 10*time.Second).Should(Succeed())
}

// assertAppReady waits for an app to be usable end to end: running, then
// answering SSH. The caller chooses the running budget, which depends on
// whether the conversion repartitioned.
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
// retried, so a delete still settling passes once it completes; the budget is
// what a loaded host can take to tear an app's volumes down.
func assertNoLiveVolumes(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device,
			"eve exec pillar sh -c 'ls /run/volumemgr/VolumeStatus/*.json 2>/dev/null | wc -l'")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal("0"),
			"the device still has live volumes; this test needs none")
	}, 15*time.Minute, 10*time.Second).Should(Succeed())
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

// assertVolumeMarker asserts the marker survived, by mounting each of the app's
// extra block devices read-only and comparing the marker file exactly.
//
// Not by reading the mount point: on EVE-K the data volume is not auto-mounted
// at its MountDir (lf-edge/eve#6145), so a check there would report the data
// lost when the volume is merely unmounted. The marker must be per run (see
// perRunMarker), so a device carrying an older run's file cannot pass. A marker
// that a raw scan finds but no mount does means the filesystem around it is
// damaged, and fails as such.
func assertVolumeMarker(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, marker string) {
	script := fmt.Sprintf(
		"m=$(mktemp -d); for d in /dev/vd[b-z] /dev/sd[b-z]; do [ -b \"$d\" ] || continue; "+
			"mount -o ro -t ext4 \"$d\" \"$m\" 2>/dev/null || { echo UNMOUNTABLE $d; continue; }; "+
			"if grep -qxF %[1]q \"$m/marker\" 2>/dev/null; then umount \"$m\"; echo FOUND-ON $d; exit 0; fi; "+
			"echo OTHER-MARKER $d: $(head -c 120 \"$m/marker\" 2>/dev/null); umount \"$m\"; done; "+
			"for d in /dev/vd[b-z] /dev/sd[b-z]; do [ -b \"$d\" ] && grep -aq %[1]q \"$d\" 2>/dev/null && echo RAW-ONLY $d; done; "+
			"echo NOT-FOUND; ls -l /dev/vd* /dev/sd* 2>/dev/null; lsblk 2>/dev/null; blkid 2>/dev/null; exit 1",
		marker)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, script, 90*time.Second, 0)
		g.Expect(err).NotTo(HaveOccurred(), "marker %q not on any mountable volume:\n%s", marker, out)
		g.Expect(out).To(ContainSubstring("FOUND-ON"))
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// perRunMarker makes base unique to this run.
func perRunMarker(base string) string {
	return fmt.Sprintf("%s-%d", base, time.Now().UnixNano())
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

// deferContentDeleteSeconds keeps a deleted app's blobs alive across the
// conversion. Without it EVE reclaims them as soon as the app referencing them
// goes away, and the redeploy afterwards measures a fresh download rather than
// the reuse the test is about.
const deferContentDeleteSeconds = 24 * 60 * 60

// Kinds of network instance the redeployed app can be attached to.
const (
	appNetworkSwitch = "switch"
	appNetworkLocal  = "local"
)

// addAppNetworkInstance adds a network instance of kind on eth0. A local one
// NATs the app behind the device, so only the port forward reaches it.
func addAppNetworkInstance(devConfig *evetest.EdgeDeviceConfig, kind string) uuid.UUID {
	if kind == appNetworkLocal {
		return devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
			DisplayName: "local-ni",
			Port:        "eth0",
			Subnet:      evetest.IPSubnet("10.50.0.0/24"),
			DHCPRange: pillartypes.IPRange{
				Start: evetest.IPAddress("10.50.0.2"),
				End:   evetest.IPAddress("10.50.0.254"),
			},
			Gateway: evetest.IPAddress("10.50.0.1"),
		})
	}
	return devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
}

// deployAppThenDeleteKeepingBlobs deploys the test app, confirms it works, then
// deletes it with the deferred content delete stretched past the conversion, so
// the device converts with no volume while its blobs stay behind for
// redeployAssertingBlobReuse. network is the kind of network instance, see
// addAppNetworkInstance. It returns the app's network instance, which stays in
// devConfig to be redeployed onto.
func deployAppThenDeleteKeepingBlobs(t Gomega, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, network string) uuid.UUID {
	log := evetest.Logger()

	log.Infof("deploying the app before the conversion, on a %s network instance", network)
	niUUID := addAppNetworkInstance(devConfig, network)
	appUUID := addTestApp(devConfig, "konvert-repartition-app", niUUID)
	device.ApplyConfig(devConfig, false, false)
	assertAppReady(t, device, appUUID, 15*time.Minute)
	dumpAppNetwork(device, "before the conversion (working)")

	log.Infof("stretching the deferred content delete past the conversion")
	props := shortBaseImageCooldown()
	props.SetGlobalValueInt(pillartypes.DeferContentDelete, deferContentDeleteSeconds)
	devConfig.SetConfigProperties(props)
	device.ApplyConfig(devConfig, true, true)

	// The conversion's cross-flavor gate refuses to shrink while a volume
	// exists, and the app's image is one.
	log.Infof("deleting the app, keeping its network and blobs")
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, true, true)
	assertNoLiveVolumes(t, device)
	evetest.Checkpoint("app-deleted")
	return niUUID
}

// redeployAssertingBlobReuse redeploys the app deployAppThenDeleteKeepingBlobs
// deleted, onto the same network instance, asserts it runs on EVE-K and
// downloaded nothing, and puts the content-delete timer back so a device reused
// by the next test is not holding blobs for a day. It must be called after the
// conversion's last reboot, so both downloader readings belong to one boot.
// persistRecreated is passed through to assertBlobsReused. It returns the
// redeployed app.
func redeployAssertingBlobReuse(t Gomega, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, niUUID uuid.UUID, persistRecreated bool) uuid.UUID {
	beforeBytes := snapshotDownloaderBytes(t, device)
	// Onto the network instance the device already has: a second switch
	// instance on the same port would leave two of them bound to eth0, and the
	// app never starts.
	evetest.Logger().Infof("redeploying the app on EVE-K")
	appUUID := addTestApp(devConfig, "konvert-repartition-app", niUUID)
	device.ApplyConfig(devConfig, false, false)

	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "after the conversion (app FAILED)")
		}
	}()
	waitClusterStorageReady(t, device)
	assertAppReady(t, device, appUUID, appRunningAfterRepartitionTimeout)
	appOK = true
	assertBlobsReused(t, device, beforeBytes, persistRecreated)
	evetest.Checkpoint("app-redeployed")

	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)
	return appUUID
}
