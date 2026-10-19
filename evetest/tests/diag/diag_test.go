// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Tests for diag, the on-device diagnostic summary EVE prints for an operator.

package diag_test

import (
	"encoding/json"
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
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// Structural anchors of a complete diag summary. diag prints the sections in a
// fixed order and only reaches the port sections once it has the blink counter,
// the device network status and the port config list, so a dump taken early in
// boot legitimately stops after the application line. The assertions below are
// therefore polled until one dump carries all of them.
//
// A device that reaches the controller takes the short path through the port
// section: diag prints one line per port and skips the per-port DNS, routing
// and ping detail along with the "PASS: All management ports passed test"
// verdict, all of which appear only once connectivity is already broken.
var (
	diagHeaderRE = regexp.MustCompile(
		`(?m)^INFO: updated diag information at \S+ due to \S+$`)
	deviceLineRE = regexp.MustCompile(
		`(?m)^(INFO|WARNING|ERROR): device: online attest: .+ vault: .+ pcr: .+$`)
	appsLineRE = regexp.MustCompile(
		`(?m)^INFO: applications: \d+ starting, \d+ running$`)
	portsLineRE = regexp.MustCompile(
		`(?m)^INFO: Have \d+ total ports\. \d+ ports should be connected to EV controller$`)
	mgmtPortLineRE = regexp.MustCompile(
		`(?m)^INFO: Port \S+: .*link: up use: mgmt .+$`)
)

// TestDiagOutput verifies that diag produces its full diagnostic summary on a
// healthy, onboarded device, and that an application can retrieve it through
// the metadata server.
//
// Why this matters
// ----------------
// diag is EVE's only operator-facing summary of device health: connectivity to
// the controller, attestation and vault state, application status and the
// readiness of cluster storage. None of it is reported through the EVE API, so
// nothing else in the test suites would notice diag going silent, losing a
// section, or filling with errors on an otherwise healthy device.
//
// The output has three sinks, all fed by the same content: /dev/tty1 for a
// physically attached console, /run/diag.out for a shell on the device, and
// GET /eve/v1/diag on the metadata server for applications. This test asserts
// through the metadata endpoint, which is the one documented for consumers and
// exercises msrv's handler along the way.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port with the SDN DNS server
//     and a static entry for the controller. diag reports per-port
//     connectivity, so the port must genuinely reach the controller for the
//     healthy-path assertions to mean anything.
//
// Device configuration
// --------------------
//   - ethernet0 (eth0, mgmt+app): DHCP.
//   - A Local NI ("local-ni") with a container application attached, which is
//     what makes the metadata server reachable at 169.254.169.254 from inside
//     the application. diag itself does not depend on either.
//
// Phases
// ------
//  1. Bring up the port, the Local NI and the application, and wait until the
//     application answers over SSH through the 2222->22 port-forward.
//  2. Fetch GET /eve/v1/diag from inside the application until one response
//     carries a complete summary, and assert on its structure: the update
//     header, the device/attest/vault/pcr line reporting the device online,
//     the application counts, the summary line naming the device onboarded
//     and connected, the port count, the management port up, and the
//     deployed application listed as running.
//  3. Cross-check the storage state diag reports against volumemgr's own
//     VolumeMgrStatus publication: on a non-EVE-k node storage is usable from
//     the start, so the status must say so and diag must not print the
//     cluster-storage warning.
//
// Parameters
// ----------
//   - HYPERVISOR: kvm or xen. Kubevirt is skipped -- it is reserved for the
//     cluster tests, and this test deploys an application.
func TestDiagOutput(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor == evetest.HypervisorKubevirt {
		evetestT.Skipf("HYPERVISOR %s is reserved for the cluster tests",
			hypervisor)
	}

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

	log := evetest.Logger()

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
	device.ApplyConfig(devConfig, true, true)

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: false,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "diag-reader",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				MAC:                 evetest.MACAddress("02:16:3e:00:00:01"),
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
	device.ApplyConfig(devConfig, false, false)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-running")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	timeout := 3 * time.Minute
	polling := 3 * time.Second

	log.Infof("Waiting for the application to become reachable over SSH")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(appUUID.String()))
	}, timeout, polling).Should(Succeed())

	// The status code is appended on its own line so that a non-200 response
	// is distinguishable from an empty body.
	const fetchDiag = `curl -sS -w '\nHTTP_STATUS:%{http_code}\n' ` +
		`http://169.254.169.254/eve/v1/diag`

	log.Infof("Fetching the diag summary from inside the application")
	var summary string
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			fetchDiag, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("HTTP_STATUS:200"))
		summary = strings.SplitN(output, "HTTP_STATUS:", 2)[0]

		t.Expect(summary).To(MatchRegexp(diagHeaderRE.String()),
			"diag must state when it last updated")
		t.Expect(summary).To(MatchRegexp(deviceLineRE.String()),
			"diag must report device, attestation, vault and PCR state")
		t.Expect(summary).To(MatchRegexp(appsLineRE.String()),
			"diag must report the application counts")
		t.Expect(summary).To(ContainSubstring(
			"INFO: Summary: Connected to EV Controller and onboarded"))
		t.Expect(summary).To(MatchRegexp(portsLineRE.String()),
			"diag must report how many ports should reach the controller")
		t.Expect(summary).To(MatchRegexp(mgmtPortLineRE.String()),
			"diag must report the management port as up")
		t.Expect(summary).To(ContainSubstring(fmt.Sprintf(
			"INFO: App diag-reader uuid %s state RUNNING", appUUID)))
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("diag-summary-fetched")

	log.Infof("diag summary:\n%s", summary)
	t.Expect(summary).ToNot(ContainSubstring("WARNING: state "),
		"the device network state must be SUCCESS")
	t.Expect(summary).ToNot(ContainSubstring(
		"ERROR: No management ports passed test"))

	// volumemgr publishes its status once it is past its early startup, hence
	// the poll rather than a single read. Its pubsub state lives in the pillar
	// container, not in the namespace an SSH session lands in.
	var volumeMgrStatus pillartypes.VolumeMgrStatus
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScript(
			`eve exec pillar cat /run/volumemgr/VolumeMgrStatus/volumemgr.json`,
			sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(json.Unmarshal([]byte(output), &volumeMgrStatus)).To(Succeed())
	}, timeout, polling).Should(Succeed())

	t.Expect(volumeMgrStatus.Initialized).To(BeTrue(),
		"storage is usable from the start on a node without cluster storage")
	t.Expect(summary).ToNot(ContainSubstring("cluster storage not ready"))
}
