// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"crypto/sha256"
	"fmt"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
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

	// Bringing up k3s takes minutes; same allowance as the other suites that
	// run under kubevirt.
	//
	// Under kubevirt every test has to wait for its node to become ready, and
	// that wait belongs *after* the first ApplyConfig: kube-init blocks the
	// cluster bring-up on the device name, which zedagent publishes only when
	// it parses a configuration received from the controller.
	clusterNodeReadyTimeout = 20 * time.Minute
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

// replaceConfigProperties overwrites the device-wide configuration properties
// of devConfig, so that the same configuration object can be re-applied with
// different properties without rebuilding (and thus renumbering) its networks
// and adapters. SetConfigProperties appends, hence the reset; the framework
// adds its own defaults for whatever the test leaves unset on every apply.
func replaceConfigProperties(devConfig *evetest.EdgeDeviceConfig,
	cfgProps *pillartypes.ConfigItemValueMap) {
	devConfig.ConfigItems = nil
	devConfig.SetConfigProperties(cfgProps)
}

// sha256Hex returns the hex-encoded SHA-256 digest of b.
func sha256Hex(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// installMarkerConfig pushes a freshly rendered marker Vector config (see
// newMarkerConfig) and returns only once the controller has received an
// uploaded log event stamped with its sentinel source, i.e. the config has been
// promoted and is processing uploads. It returns the sentinel and the exact
// config bytes that were pushed.
//
// Note that while a marker config is promoted, the source of *every* uploaded
// device log event is overwritten with the sentinel - including the entries a
// later assertion in the same test may want to match by source.
func installMarkerConfig(t *WithT, device *evetest.EdgeDevice) (
	markerSource string, markerConfig []byte) {
	markerSource, markerConfig = newMarkerConfig(t)
	markedLogs, stopLogWatch := device.WatchLogs(evetest.LogMsgMatch{
		Source: markerSource,
	})
	defer stopLogWatch()
	device.ApplyConfig(vectorConfigItem(markerConfig), true, true)
	evetest.Checkpoint("marker-applied")

	evetest.Logger().Infof(
		"Waiting for the marker Vector config to become active...")
	t.Eventually(markedLogs, vectorLogUploadTimeout).Should(Receive(),
		"the marker Vector config was never promoted: no uploaded log event "+
			"carried its sentinel source")
	evetest.Checkpoint("marker-active")
	return markerSource, markerConfig
}

// clearVectorConfig empties the vector.config item, which makes newlogd restore
// the Vector config built into the EVE image.
//
// Tests do not need to call this to clean up after themselves: the framework's
// ResetDeviceConfig policy nils ConfigItems, so vector.config is cleared between
// tests anyway. It is here for the test whose subject is the clearing itself.
func clearVectorConfig(device *evetest.EdgeDevice) {
	device.ApplyConfig(vectorConfigItem(nil), true, true)
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
// sets; and no Vector config that rewrites `source` may be promoted at the time
// (see installMarkerConfig), or the Source assertion below cannot hold.
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
