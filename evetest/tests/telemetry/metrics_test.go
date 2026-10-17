// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the device metrics (DeviceMetric) that EVE reports to the controller.

package telemetry_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
)

// TestDeviceMetrics verifies the DeviceMetric message EVE publishes to the
// controller: per-port network counters attributed to the right port, plus
// the memory, CPU and controller-connectivity counters that ride along in the
// same message.
//
// Note that NetworkMetric.iName is the *logical label* from the controller
// config, not the Linux interface name; localName carries the latter. The two
// are asserted separately here, since a device model that happens to label its
// port "eth0" would otherwise hide a mix-up between them.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+apps port with DHCP. Traffic to
//     the controller flows over it continuously, so its counters are
//     guaranteed to be non-zero without the test generating any load.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//     The framework default already lowers the metric publishing interval to
//     20s, so no extra tuning is needed.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied.
//  2. network-metrics-reported: wait for a DeviceMetric carrying a
//     NetworkMetric whose iName is the port's logical label "ethernet0", with
//     non-zero TxBytes, RxBytes, TxPkts and RxPkts -- the device is talking to
//     the controller over this port, so counters must be moving -- and
//     carrying non-zero DeviceMemory.MemoryMB and CpuMetric.TotalNs. Those
//     last two come from a different producer (zedagent fills them only once
//     domainmgr has published the host DomainMetric), so they are part of the
//     wait rather than assertions on whichever message first satisfied the
//     network condition. Then assert localName is the interface name eth0.
//  3. Memory metrics in the same message: UsedEveMB is non-zero and does not
//     exceed the reported total device memory.
//  4. CPU metrics: CpuMetric.UpTime is set and in the past.
//  5. Controller connectivity: at least one ZedcloudMetric with Success > 0
//     and a LastSuccess timestamp -- EVE accounts for the API calls it makes,
//     which is the metric the controller uses to judge device liveness.
//
// All assertions are made against a single message captured by the
// Eventually, so the values are mutually consistent rather than sampled from
// different publishing rounds.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite.
func TestDeviceMetrics(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupTelemetryTestDevice(hypervisor, useTPM)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	devConfig := singleMgmtPortConfig()
	metricUpdates, stopMetricWatch := device.WatchDeviceMetrics()
	defer stopMetricWatch()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 2: per-port network counters are reported and moving.
	timeout := 5 * time.Minute
	var metrics *evemetrics.DeviceMetric
	var portMetric *evemetrics.NetworkMetric
	t.Eventually(metricUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device reports non-zero network, memory and CPU counters",
		func(dm *evemetrics.DeviceMetric) bool {
			metrics = dm
			portMetric = nil
			for _, nm := range dm.GetNetwork() {
				if nm.GetIName() == portLogicalLabel {
					portMetric = nm
					break
				}
			}
			if portMetric == nil ||
				portMetric.GetTxBytes() == 0 || portMetric.GetRxBytes() == 0 ||
				portMetric.GetTxPkts() == 0 || portMetric.GetRxPkts() == 0 {
				return false
			}
			// DeviceMemory and CpuMetric.TotalNs come from a different
			// producer than the network counters: zedagent only fills them in
			// once domainmgr has published the host DomainMetric (see
			// handlemetrics.go, the lookupDomainMetric(nilUUID) branch). Wait
			// for a message carrying all of them rather than asserting them
			// on whichever message happened to satisfy the network condition.
			return dm.GetDeviceMemory().GetMemoryMB() > 0 &&
				dm.GetCpuMetric().GetTotalNs() > 0
		})))
	t.Expect(portMetric.GetLocalName()).To(Equal(portIfName))
	evetest.Checkpoint("network-metrics-reported")

	// Phase 3: memory metrics.
	deviceMemory := metrics.GetDeviceMemory()
	t.Expect(deviceMemory.GetUsedEveMB()).To(BeNumerically(">", 0))
	t.Expect(deviceMemory.GetUsedEveMB()).To(
		BeNumerically("<=", deviceMemory.GetMemoryMB()))

	// Phase 4: CPU metrics.
	cpuMetric := metrics.GetCpuMetric()
	t.Expect(cpuMetric.GetUpTime().IsValid()).To(BeTrue())
	t.Expect(cpuMetric.GetUpTime().AsTime()).To(BeTemporally("<", time.Now()))

	// Phase 5: controller connectivity is accounted for.
	var successfulSends uint64
	for _, zm := range metrics.GetZedcloud() {
		if zm.GetSuccess() > 0 {
			successfulSends += zm.GetSuccess()
			t.Expect(zm.GetLastSuccess().IsValid()).To(BeTrue())
		}
	}
	t.Expect(successfulSends).To(BeNumerically(">", 0),
		"EVE must account for the successful API calls it made to the controller")
}
