// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test delivery of an environment variable whose value is written with
// backslash-escaped double quotes in the application user-data.

package apps_test

import (
	"fmt"
	"regexp"
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
	// Environment variable holding a JSON document.
	escapedQuotesEnvKey = "EVETEST_JSON_DOCUMENT"

	// Its value as written in the user-data: every double quote of the
	// document is preceded by a backslash.
	escapedQuotesEnvUserData = `[ { \"title\":\"Atlas of the World (second edition - 1987)\",\"lent\":true} ]`

	// Its value as the application must find it in its environment.
	escapedQuotesEnvWant = `[ { "title":"Atlas of the World (second edition - 1987)","lent":true} ]`

	// Environment variable whose value has a dollar sign in front of PATH, a
	// variable which the shell of the shim VM always has. The value of a
	// plain "key=value" line is not shell text: the application must find it
	// as it is written here, not with that search path in it.
	dollarSignEnvKey   = "EVETEST_DOLLAR_SIGN"
	dollarSignEnvValue = `foo${PATH}bar`
)

// shimInitFailureRE matches what the console of a container application's
// shim VM shows when its init gives up before starting the container: the
// complaint of init about the environment file, and the kernel panic which
// follows the exit of init whatever made it exit.
var shimInitFailureRE = regexp.MustCompile(
	`Error processing the environment variables file|Kernel panic`)

// TestAppUserDataEscapedQuotes verifies that a container application receives
// an environment variable holding a JSON document when the plain "key=value"
// user-data spells the double quotes of the document as \".
//
// EVE hands the variables to the container in a file which the init of the
// container's shim VM sources as shell code, with every value inside double
// quotes. A literal double quote therefore has to be written as \", which is
// what applications deployed on EVE releases up to 11.9 do. The test is a
// regression test for EVE un-escaping the value once more before it writes
// that file: the quotes of the document then end the shell string, init
// fails on the file and exits, and the shim VM panics at every boot - while
// EVE keeps reporting the application as RUNNING. A document without spaces
// or parentheses in its strings does not even make init fail; it reaches the
// application with the quotes stripped.
//
// The same user-data sets a second variable whose value has a dollar sign in
// front of PATH, a variable which the shell of the shim VM always has. A plain
// "key=value" line gives the value itself and not shell text, so the
// application must find it unchanged: a value such as a password with dollar
// signs must not depend on which variables that shell has.
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
//   - Container app "escaped-quotes-app" (lfedge/evetest-ubuntu-ctr) with a
//     single VIF on the NI, port-fwd 2222->22 and an allow-all ACL. Its
//     user-data is the two lines
//     EVETEST_JSON_DOCUMENT=[ { \"title\":\"Atlas of the World (second edition - 1987)\",\"lent\":true} ]
//     EVETEST_DOLLAR_SIGN=foo${PATH}bar
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied -> app-is-running: deploy the app and wait
//     for RUNNING. This says nothing about the container yet: EVE reports
//     RUNNING once the domain exists.
//  2. container-started: commands can be executed inside the container over
//     SSH. This is where the regression shows. The wait ends at once, quoting
//     the application's console log, when that log reports that the init of
//     the shim VM failed; otherwise it runs into its timeout.
//  3. Read both variables from /proc/1/environ inside the container and
//     assert that the first holds the JSON document with plain double quotes
//     and the second its value as the user-data spells it. /proc/1 is used
//     rather than the SSH session environment because sshd sanitizes the
//     environment it hands to login sessions.
//  4. Delete the app and wait for ZSwState_INVALID.
//
// Test params
// -----------
//   - HYPERVISOR. Under Kubevirt the test waits for the cluster node to
//     become ready before deploying the app.
//
// Suite placement
// ---------------
//   - TestAppsSuite, right after TestAppUserData, whose device it reuses.
func TestAppUserDataEscapedQuotes(test *testing.T) {
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
		appName                  = "escaped-quotes-app"
		sshTimeout               = 20 * time.Second
		containerStartTimeout    = 3 * time.Minute
		containerStartPolling    = 10 * time.Second
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
		UserData: encodeUserData(
			escapedQuotesEnvKey + "=" + escapedQuotesEnvUserData + "\n" +
				dollarSignEnvKey + "=" + dollarSignEnvValue + "\n"),
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	// Phase 1: the domain exists.
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-is-running")

	// Phase 2: the container itself has to come up, which RUNNING does not
	// tell. The console log does, so stop waiting as soon as it shows that
	// the init of the shim VM failed.
	t.Eventually(func(g Gomega) {
		failures := device.GetAppLogs(appUUID, evetest.LogMsgMatch{
			MsgMatchesRegexp: *shimInitFailureRE,
		})
		if len(failures) > 0 {
			lines := make([]string, 0, len(failures))
			for _, failure := range failures {
				lines = append(lines, strings.TrimSpace(failure.Message))
			}
			StopTrying(fmt.Sprintf("app %q is reported as RUNNING, but the "+
				"init of its shim VM failed and the container never started; "+
				"the console says:\n%s", appName, strings.Join(lines, "\n"))).Now()
		}
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"echo hello", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring("hello"))
	}, containerStartTimeout, containerStartPolling).Should(Succeed(),
		"the container of app %q did not start", appName)
	evetest.Checkpoint("container-started")

	// Phase 3: the variables hold what the user-data says.
	value, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"tr '\\0' '\\n' < /proc/1/environ | sed -n 's/^"+escapedQuotesEnvKey+"=//p'",
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSuffix(value, "\n")).To(Equal(escapedQuotesEnvWant),
		"%s did not reach the application as the JSON document that the "+
			"user-data spells with \\\" for every double quote", escapedQuotesEnvKey)

	value, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"tr '\\0' '\\n' < /proc/1/environ | sed -n 's/^"+dollarSignEnvKey+"=//p'",
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSuffix(value, "\n")).To(Equal(dollarSignEnvValue),
		"%s did not reach the application as the user-data spells it; "+
			"nothing in the value of a plain \"key=value\" line is to be "+
			"expanded", dollarSignEnvKey)

	// Phase 4: clean up.
	deleteAppAndWait(t, device, devConfig, appUUID)
}
