// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test expansion of an environment variable which the application user-data
// sets as an entry of runcmd in a cloud-config.

package apps_test

import (
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// Environment variable which an entry of runcmd sets.
	runcmdEnvKey = "EVETEST_EXPANDED"

	// Its value as written in the user-data. It refers to PATH, a variable
	// which the shell of the shim VM always has.
	runcmdEnvUserData = "foo${PATH}bar"
)

// TestAppUserDataRuncmdExpansion verifies that the value of an environment
// variable is expanded when the user-data of a container application sets the
// variable as an entry of runcmd in a "#cloud-config" document.
//
// For cloud-init an entry of runcmd is a line of shell, so ${PATH} in a value
// stands for the search path. The shell of the container's shim VM replaces
// it before it starts the container. That sets this format apart from plain
// "key=value" lines, whose values reach the application as they are written;
// TestAppUserDataEscapedQuotes checks that with the same value.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- user-data delivery is not network
//     topology dependent; a single mgmt+apps port with DHCP is enough to run
//     the app and reach it over SSH.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - Local NI "local-ni" (10.11.12.0/24, gateway .1) on ethernet0.
//   - Container app "runcmd-expansion-app" (lfedge/evetest-ubuntu-ctr) with a
//     single VIF on the NI, port-fwd 2222->22 and an allow-all ACL. It runs
//     inside a shim VM. Its user-data is a "#cloud-config" document whose
//     runcmd section has the single entry
//     EVETEST_EXPANDED=foo${PATH}bar
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied -> app-is-running: deploy the app and wait
//     for RUNNING.
//  2. container-started: commands can be executed inside the container over
//     SSH.
//  3. Read /proc/1/environ inside the container and assert that the variable
//     holds its user-data value with the PATH of the container in the place
//     of ${PATH}. The image sets PATH, so the shell of the shim VM has that
//     value when it comes to the variable of the user-data, and the container
//     starts with the same one. /proc/1 is used rather than the SSH session
//     environment because sshd sanitizes the environment it hands to login
//     sessions.
//  4. Delete the app and wait for ZSwState_INVALID.
//
// Test params
// -----------
//   - HYPERVISOR. Under Kubevirt the test waits for the cluster node to
//     become ready before deploying the app.
//
// Suite placement
// ---------------
//   - TestAppsSuite, right after TestAppUserDataEscapedQuotes, whose device it
//     reuses.
func TestAppUserDataRuncmdExpansion(test *testing.T) {
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
		appName                  = "runcmd-expansion-app"
		sshTimeout               = 20 * time.Second
		timeoutExcludingDownload = 10 * time.Minute
	)

	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
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
		UserData: encodeUserData("#cloud-config\n" +
			"runcmd:\n" +
			"- " + runcmdEnvKey + "=" + runcmdEnvUserData + "\n"),
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	// Phase 1: the domain exists.
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-is-running")

	// Phase 2: the container itself has come up.
	waitForAppSSH(t, device, appUUID)
	evetest.Checkpoint("container-started")

	// Phase 3: the variable holds the search path where the user-data refers
	// to it.
	environ, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"tr '\\0' '\\n' < /proc/1/environ", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	env := make(map[string]string)
	for _, variable := range strings.Split(environ, "\n") {
		if name, value, hasValue := strings.Cut(variable, "="); hasValue {
			env[name] = value
		}
	}
	test.Logf("env is :%+v", env)
	t.Expect(env["PATH"]).ToNot(BeEmpty(),
		"the application has no PATH which %s could hold", runcmdEnvKey)
	t.Expect(env[runcmdEnvKey]).To(
		Equal(strings.ReplaceAll(runcmdEnvUserData, "${PATH}", env["PATH"])),
		"%s is not its user-data value %q with the PATH of the application "+
			"in the place of ${PATH}; an entry of runcmd is a line of shell",
		runcmdEnvKey, runcmdEnvUserData)

	// Phase 4: clean up.
	deleteAppAndWait(t, device, devConfig, appUUID)
}
