// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test delivery of application user-data (cloud-init) from the controller.

package apps_test

import (
	"encoding/base64"
	"strings"
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
	// Path of the file that the cloud-config user-data asks EVE to write into
	// the container rootfs.
	injectedFilePath = "/etc/injected_file.txt"

	// Marker env variable carried by the plain key=value user-data.
	userDataMarkerKey   = "EVETEST_USERDATA_MARKER"
	userDataMarkerValue = "userdata-marker-value"

	// Approximate size of the plain key=value user-data blob. Large enough
	// that an oversized payload would show up as a deployment failure.
	userDataFillerSize = 90000
)

// TestAppUserData verifies both flavors of application user-data that EVE
// supports for container applications:
//
//   - plain "key=value" lines, which EVE turns into environment variables of
//     the container's init process, and
//   - a "#cloud-config" document, of which EVE applies the write_files
//     section by materializing the files inside the container rootfs.
//
// It also verifies that cloud-init is applied exactly once per user-data
// version: a file written by write_files and then modified from inside the
// application must survive an application restart untouched.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- user-data delivery is not network
//     topology dependent; a single mgmt+apps port with DHCP is enough to run
//     the app and reach it over SSH.
//
// Note on encoding: ApplicationInstanceConfig.UserData must be base64-encoded.
// EVE's fetchCloudInit base64-decodes the payload unconditionally -- both when
// it arrives in plaintext and when it arrives object-encrypted -- and fails app
// activation with "base64 decode failed" otherwise. This is not documented on
// the eve-api userData field, hence encodeUserData below.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - Local NI "local-ni" (10.11.12.0/24, gateway .1) on ethernet0.
//   - Container app "userdata-app" (lfedge/evetest-ubuntu-ctr) with a single
//     VIF on the NI, port-fwd 2222->22 and an allow-all ACL. The app is
//     deployed twice - user-data cannot be modified in place, so phase 2
//     deletes the instance and deploys a new one.
//
// Phases / assertions
// -------------------
//  1. env-userdata-app-running: deploy the app with ~90 KB of plain
//     "key=value" user-data (bulk filler lines plus one marker pair). Assert
//     the app still reaches RUNNING - an oversized or malformed blob must not
//     wedge deployment - and then read
//     /proc/1/environ inside the container and assert both the filler
//     variable and the marker variable are present. /proc/1 is used rather
//     than the SSH session environment because sshd sanitizes the environment
//     it hands to login sessions.
//  2. env-userdata-app-deleted: delete the app and wait for
//     ZSwState_INVALID.
//  3. cloudinit-app-running -> injected-file-written: deploy the app again,
//     this time with a "#cloud-config" user-data whose write_files section
//     writes "before_restart" to /etc/injected_file.txt with mode 0644.
//     Assert the file exists inside the container with that content.
//  4. injected-file-modified -> app-restarted: overwrite the file from inside
//     the app with "after_restart", then restart the app instance
//     (RebootApplication, i.e. the controller's restart counter) and wait for
//     it to come back to RUNNING.
//  5. Assert the file still reads "after_restart": the user-data version did
//     not change, so EVE must not re-apply write_files and must not revert
//     the application's own modification.
//  6. Delete the app and wait for ZSwState_INVALID.
//
// Test params
// -----------
//   - HYPERVISOR. Under Kubevirt the test waits for the cluster node to
//     become ready before deploying the app.
//
// Suite placement
// ---------------
//   - TestApplicationSuite (deploys an app, hence hypervisor-parameterized).
func TestAppUserData(test *testing.T) {
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

	const (
		appName                  = "userdata-app"
		sshTimeout               = 20 * time.Second
		appRestartTimeout        = 5 * time.Minute
		timeoutExcludingDownload = 10 * time.Minute
	)

	appConfig := evetest.ApplicationInstanceConfig{
		DisplayName: appName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		NetworkAdapters:    singleVIFWithSSH(niUUID),
		UserData:           envUserData(),
	}
	appUUID := devConfig.AddApplication(appConfig)
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("env-userdata-config-applied")

	// Phase 1: plain key=value user-data becomes container environment.
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("env-userdata-app-running")

	waitForAppSSH(t, device, appUUID)
	environ, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"tr '\\0' '\\n' < /proc/1/environ", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.Split(environ, "\n")).To(ContainElement("variable=value"))
	t.Expect(strings.Split(environ, "\n")).To(
		ContainElement(userDataMarkerKey + "=" + userDataMarkerValue))

	// Phase 2: user-data cannot be changed in place, so redeploy the app.
	deleteAppAndWait(t, device, devConfig, appUUID)
	evetest.Checkpoint("env-userdata-app-deleted")

	// Phase 3: cloud-config write_files.
	appConfig.UserData = cloudInitUserData("before_restart")
	appUUID = devConfig.AddApplication(appConfig)
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("cloudinit-app-running")

	waitForAppSSH(t, device, appUUID)
	t.Expect(readInjectedFile(t, device, appUUID, sshTimeout)).To(Equal("before_restart"))
	evetest.Checkpoint("injected-file-written")

	// Phase 4: modify the injected file from inside the app, then restart it.
	_, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"echo after_restart > "+injectedFilePath, sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(readInjectedFile(t, device, appUUID, sshTimeout)).To(Equal("after_restart"))
	evetest.Checkpoint("injected-file-modified")

	device.RebootApplication(appUUID, true, appRestartTimeout)
	waitForAppSSH(t, device, appUUID)
	evetest.Checkpoint("app-restarted")

	// Phase 5: the user-data version did not change, so cloud-init must not
	// be re-applied and the app's own modification must survive.
	t.Expect(readInjectedFile(t, device, appUUID, sshTimeout)).To(Equal("after_restart"))

	// Phase 6: clean up.
	deleteAppAndWait(t, device, devConfig, appUUID)
}

// encodeUserData base64-encodes the user-data payload for
// ApplicationInstanceConfig.UserData. EVE requires this: fetchCloudInit in
// domainmgr base64-decodes the payload unconditionally, on both the plaintext
// and the object-encrypted path, and fails app activation with "base64 decode
// failed" otherwise. The eve-api proto comment for userData does not mention
// it, so it is spelled out here.
func encodeUserData(userData string) string {
	return base64.StdEncoding.EncodeToString([]byte(userData))
}

// envUserData builds a ~90 KB blob of plain "key=value" lines. EVE parses
// user-data that is not a cloud-config document as an environment variable
// map for container applications. The bulk is intentionally made of repeated
// identical pairs so that the resulting environment
// stays small while the config payload is large; a unique marker pair is
// appended to prove the whole blob was parsed, not just its beginning.
// The size refers to the decoded payload, before base64 expansion.
func envUserData() string {
	const fillerLine = "variable=value\n"
	marker := userDataMarkerKey + "=" + userDataMarkerValue + "\n"
	var sb strings.Builder
	sb.Grow(userDataFillerSize + len(marker))
	for sb.Len()+len(fillerLine) <= userDataFillerSize {
		sb.WriteString(fillerLine)
	}
	sb.WriteString(marker)
	return encodeUserData(sb.String())
}

// cloudInitUserData builds a cloud-config document instructing EVE to write
// the given content into injectedFilePath inside the container rootfs.
func cloudInitUserData(content string) string {
	return encodeUserData(`#cloud-config
write_files:
 - path: ` + injectedFilePath + `
   owner: root:root
   permissions: '0644'
   content: ` + content + `
`)
}

// readInjectedFile returns the trimmed content of the cloud-init injected
// file as seen from inside the application.
func readInjectedFile(t *WithT, device *evetest.EdgeDevice,
	appUUID uuid.UUID, sshTimeout time.Duration) string {
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"cat "+injectedFilePath, sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	return strings.TrimSpace(output)
}
