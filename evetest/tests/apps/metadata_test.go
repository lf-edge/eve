// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the application metadata channel served by EVE at 169.254.169.254.

package apps_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// Base URL of EVE's metadata server as seen from inside an application.
const metadataServerURL = "http://169.254.169.254/eve/v1"

// TestAppInstanceMetadata verifies EVE's application metadata channel: an
// application POSTs a payload to the link-local metadata server
// (169.254.169.254) and EVE must forward it to the controller as a
// ZInfoAppInstMetaData info message tagged with the application UUID and with
// the metadata type matching the endpoint that was used.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the metadata server is served on the
//     local network instance bridge, so a single mgmt+apps port with DHCP is
//     all that is required.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - Local NI "local-ni" (10.11.12.0/24, gateway .1) on ethernet0.
//   - Container app "metadata-app" (lfedge/evetest-ubuntu-ctr) with a single
//     VIF on the NI, port-fwd 2222->22 so the test can drive curl from inside
//     the app, and an allow-all ACL -- the metadata server is subject to ACL
//     filtering like any other destination.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied -> app-is-running -> app-ssh-reachable:
//     the container is up and reachable over the port-forwarded sshd.
//  2. kubeconfig-metadata-published: with the WatchAppMetadata subscription
//     opened first (EVE publishes the info message as soon as it receives the
//     POST), POST {"hello":"world"} to /eve/v1/kubeconfig. Assert that a
//     ZInfoAppInstMetaData arrives for this app with
//     Type=APP_INST_META_DATA_TYPE_KUBE_CONFIG and Data byte-for-byte equal
//     to the posted body.
//  3. custom-status-metadata-published: POST a distinct payload to
//     /eve/v1/app/appCustomStatus and assert the same, this time with
//     Type=APP_INST_META_DATA_TYPE_CUSTOM_STATUS. This proves the reported
//     metadata type follows the endpoint rather than being hardcoded.
//  4. GET /eve/v1/hostname returns the application instance UUID -- a
//     read-only sanity check that the same server also serves the app its own
//     identity.
//  5. Delete the app and wait until the device reports it gone.
//
// The POSTs are wrapped in Eventually: reaching RUNNING (and even being
// SSH-reachable) does not guarantee that zedrouter has already attached the
// metadata HTTP handler to this app's VIF.
//
// Test params
// -----------
//   - HYPERVISOR. Under Kubevirt the test waits for the cluster node to
//     become ready before deploying the app.
//
// Suite placement
// ---------------
//   - TestApplicationSuite (deploys an app, hence hypervisor-parameterized).
func TestAppInstanceMetadata(test *testing.T) {
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
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "metadata-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		NetworkAdapters:    singleVIFWithSSH(niUUID),
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)
	evetest.Checkpoint("app-is-running")

	waitForAppSSH(t, device, appUUID)
	evetest.Checkpoint("app-ssh-reachable")

	const (
		sshTimeout      = 20 * time.Second
		metadataTimeout = 5 * time.Minute
	)

	// Subscribe before publishing anything - EVE reports the metadata to the
	// controller immediately after the POST is accepted.
	metaUpdates, stopMetaWatch := device.WatchAppMetadata(appUUID)

	// Phase 2: kubeconfig endpoint.
	const kubeconfigPayload = `{"hello":"world"}`
	postAppMetadata(t, device, appUUID, "/kubeconfig", kubeconfigPayload,
		metadataTimeout, sshTimeout)
	t.Eventually(metaUpdates, metadataTimeout).Should(Receive(matchers.SatisfyPredicate(
		"Kubeconfig metadata posted by the app is reported to the controller",
		func(meta *eveinfo.ZInfoAppInstMetaData) bool {
			return meta.GetType() ==
				eveinfo.AppInstMetaDataType_APP_INST_META_DATA_TYPE_KUBE_CONFIG &&
				string(meta.GetData()) == kubeconfigPayload
		})))
	evetest.Checkpoint("kubeconfig-metadata-published")

	// Phase 3: appCustomStatus endpoint (different metadata type).
	const customStatusPayload = `{"status":"evetest-custom-status"}`
	postAppMetadata(t, device, appUUID, "/app/appCustomStatus", customStatusPayload,
		metadataTimeout, sshTimeout)
	t.Eventually(metaUpdates, metadataTimeout).Should(Receive(matchers.SatisfyPredicate(
		"Custom status posted by the app is reported to the controller",
		func(meta *eveinfo.ZInfoAppInstMetaData) bool {
			return meta.GetType() ==
				eveinfo.AppInstMetaDataType_APP_INST_META_DATA_TYPE_CUSTOM_STATUS &&
				string(meta.GetData()) == customStatusPayload
		})))
	evetest.Checkpoint("custom-status-metadata-published")

	// Phase 4: the metadata server tells the app its own identity.
	hostname, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS "+metadataServerURL+"/hostname", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSpace(hostname)).To(Equal(appUUID.String()))

	// Phase 5: clean up.
	stopMetaWatch()
	deleteAppAndWait(t, device, devConfig, appUUID)
}

// postAppMetadata POSTs payload to the given metadata server endpoint from
// inside the application, retrying until the server answers with 200.
func postAppMetadata(t *WithT, device *evetest.EdgeDevice, appUUID uuid.UUID,
	endpoint, payload string, timeout, sshTimeout time.Duration) {
	curl := fmt.Sprintf(
		"curl -sS -o /dev/null -w '%%{http_code}' "+
			"-H 'Content-Type: application/json' --request POST -d '%s' %s%s",
		payload, metadataServerURL, endpoint)
	evetest.Logger().Infof("Publishing app metadata via %s", endpoint)
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			curl, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(strings.TrimSpace(output)).To(Equal("200"))
	}, timeout, 5*time.Second).Should(Succeed())
}
