// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"fmt"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "edge-dev"

	// The single management port configured by every test in this package.
	// portLogicalLabel is what the controller calls it and is therefore what
	// EVE echoes back in info and metric messages; portIfName is the name of
	// the underlying Linux interface.
	portLogicalLabel = "ethernet0"
	portIfName       = "eth0"

	// Prefix of the markers written to /dev/kmsg. A per-probe nonce is
	// appended so that no assertion can be satisfied - or broken - by a marker
	// from another probe or from an earlier test run.
	logProbeMarkerPrefix = "evetest-log-probe"

	probeSSHTimeout = 30 * time.Second

	// Generous, because log entries are batched into gzip bundles before they
	// are uploaded.
	logProbeUploadTimeout = 10 * time.Minute
)

// setupTelemetryTestDevice declares the prerequisites shared by every test in
// this package and returns a handle to the device. They are stated in one place
// because the framework compares device requirements field by field to decide
// whether the VM from the previous test can be reused: any divergence between
// two tests in the suite silently costs a full device recreation.
func setupTelemetryTestDevice(hypervisor evetest.Hypervisor,
	useTPM bool) *evetest.EdgeDevice {
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithTPM:           useTPM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	return evetest.GetEdgeDevice(devName)
}

// singleMgmtPortConfig builds the device configuration shared by the tests in
// this package: one DHCP-configured management+apps port. No network instance
// and no application - these tests only need the device to report about itself
// and to reach the controller, so that logs can be uploaded.
func singleMgmtPortConfig() *evetest.EdgeDeviceConfig {
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  portLogicalLabel,
		PhysicalLabel: portIfName,
		InterfaceName: portIfName,
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	return devConfig
}

// newLogProbeMarker returns a marker string unique to a single probe.
func newLogProbeMarker(probeName string) string {
	return fmt.Sprintf("%s-%s-%d",
		logProbeMarkerPrefix, probeName, time.Now().UnixNano())
}

// emitKernelLogProbe writes the given marker to /dev/kmsg, producing exactly
// one identifiable device log entry attributed to the kernel log source.
//
// /dev/kmsg is an ingestion path EVE documents and relies on itself
// (ssh-service.sh writes there with the comment "this is picked up by
// newlogd"), which makes the probe deterministic and independent of the wording
// of any third-party daemon's messages. Matching on a daemon's own output was
// tried first and does not work: SSH sessions are established, so sshd
// definitely handled them, yet no matching entry ever reaches the controller.
func emitKernelLogProbe(t Gomega, device *evetest.EdgeDevice, marker string) {
	_, _, err := device.RunShellScript(
		fmt.Sprintf("echo %q > /dev/kmsg", marker), probeSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Logger().Infof("Emitted kernel log probe %q on the device", marker)
}

// expectKernelLogProbe emits a kernel log probe and waits until it shows up at
// the controller, attributed to the kernel log source. The subscription is
// established before the marker is emitted, because a log watch only delivers
// entries that arrive after it was set up.
//
// Two preconditions: the caller must have configured
// debug.kernel.remote.loglevel to "info" or lower, because the kernel path is
// gated by its own knobs, separate from the debug.default.* ones the framework
// sets.
func expectKernelLogProbe(t Gomega, device *evetest.EdgeDevice, probeName string) {
	marker := newLogProbeMarker(probeName)
	logs, stopLogWatch := device.WatchLogs(evetest.LogMsgMatch{
		MsgHasSubstring: marker,
	})
	defer stopLogWatch()
	emitKernelLogProbe(t, device, marker)

	var logMsg evetest.LogMsg
	t.Eventually(logs, logProbeUploadTimeout).Should(Receive(&logMsg),
		"the kernel log probe was not uploaded to the controller")
	t.Expect(logMsg.Message).To(ContainSubstring(marker))
	t.Expect(logMsg.Source).To(Equal("kernel"))
	t.Expect(logMsg.Severity).ToNot(BeEmpty())
}
