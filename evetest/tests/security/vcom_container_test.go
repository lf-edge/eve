// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// vcomCtrImage is the first evetest-ubuntu-ctr version that ships python3,
// which vcomCheckScript needs.
const vcomCtrImage = ubuntuCtrImage + ":1.3"

// TestVComContainer verifies that a container application, which EVE-kvm runs
// in a shim VM, reaches vcomlink over vsock and gets TPM-backed data back,
// both as root and as an unprivileged user. TestVCom covers VM applications.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP.
//
// Phases
// ------
//  1. Publish vcomCtrImage to evetest's local OCI registry
//     (PushDockerImageToLocalRegistry), so a locally built image
//     (`make build-test-apps`) is used before the tag is on Docker Hub.
//  2. Deploy it as a container app on a Local NI with a 2222->22
//     port-forward and wait for SSH.
//  3. Run vcomCheckScript as root, then as uid/gid 65534 with no
//     supplementary groups. Each run must report HTTP 200 and a non-empty EK.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM; the test skips unless KVM, the only
//     backend that runs container apps in a VM with a vsock device).
func TestVComContainer(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor != evetest.HypervisorKVM {
		evetestT.Skipf("HYPERVISOR is %s: only KVM runs container apps in a "+
			"shim VM with a vsock device", hypervisor)
	}

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithTPM:           true,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	image, err := evetest.PushDockerImageToLocalRegistry(vcomCtrImage)
	t.Expect(err).ToNot(HaveOccurred(),
		"failed to publish %s to evetest's local OCI registry", vcomCtrImage)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := addLocalNI(devConfig)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:        "vcom-test-ctr",
		Activate:           true,
		Image:              image,
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
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
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
	evetest.Checkpoint("app-running")

	t.Eventually(func(gt Gomega) {
		_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"echo ok", appSSHTimeout, 0)
		gt.Expect(err).ToNot(HaveOccurred())
	}, appMarkerReadTimeout, pollingInterval).Should(Succeed())
	evetest.Checkpoint("app-ssh-ready")

	encoded := base64.StdEncoding.EncodeToString([]byte(vcomCheckScript))
	_, stderr, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"echo "+encoded+" | base64 -d > /tmp/vcomcheck.py && chmod 644 /tmp/vcomcheck.py",
		appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "failed to install the check script: %s", stderr)

	for _, run := range []struct{ user, cmd string }{
		{"root", "python3 /tmp/vcomcheck.py"},
		{"uid 65534", "setpriv --reuid 65534 --regid 65534 --clear-groups " +
			"python3 /tmp/vcomcheck.py"},
	} {
		evetest.Logger().Infof("Running the vComLink TPM check as %s...", run.user)
		out, stderr, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			run.cmd, time.Minute, 0)
		t.Expect(err).ToNot(HaveOccurred(),
			"vComLink check as %s failed: %s %s", run.user, out, stderr)
		t.Expect(out).To(ContainSubstring("STATUS=200"),
			"unexpected vComLink response as %s: %s", run.user, out)
		match := vcomEKLenRegexp.FindStringSubmatch(out)
		t.Expect(match).To(HaveLen(2), "no EK_LEN in output as %s: %s", run.user, out)
		ekLen, err := strconv.Atoi(match[1])
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(ekLen).To(BeNumerically(">", 0), "empty EK as %s", run.user)
	}
	evetest.Checkpoint("vcom-tpm-request-verified")
}
