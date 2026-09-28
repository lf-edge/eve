// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const devName = "edge-dev"

// TestExternalPortScan scans every TCP and UDP port of an EVE device's
// management address from the network side and verifies that nothing is
// exposed beyond SSH, or that whatever is exposed is HTTPS-only and refuses
// anonymous access.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port. nmap runs in the
//     evetest container and reaches the device through the SDN tunnel, the
//     same path the harness uses for SSH.
//
// Device configuration
// --------------------
//   - SystemAdapter on eth0 (DHCP, mgmt+app, NetworkType=V4Only).
//   - On Kubevirt the device forms a single-node K3s cluster with no cluster
//     interface configured.
//
// Test parameters
// ---------------
//   - HYPERVISOR (defaults to KVM).
//
// Phases
// ------
//  1. initial-config-applied: apply the device config.
//  2. k3s-is-ready (Kubevirt only): wait until the node is Ready, so that
//     every K3s listener is up before the scan.
//  3. ports-scanned: SYN scan and UDP scan of all 65535 ports of each IPv4
//     management address. Every open port is logged. The SSH port must be
//     open on each address, which proves the scan reached it.
//  4. Every open UDP port fails the test, since it cannot be HTTPS. Every
//     open TCP port other than SSH must accept only TLS 1.2+ with ciphers
//     ssl-enum-ciphers grades A, refuse plaintext HTTP, and reject a request
//     without credentials with HTTP 401 or by demanding a client
//     certificate.
func TestExternalPortScan(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

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
	evetest.Checkpoint("setup-done")

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
	device := evetest.GetEdgeDevice(devName)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
		evetest.Checkpoint("k3s-is-ready")
	}

	log := evetest.Logger()
	var targets []string
	t.Eventually(func() []string {
		targets = nil
		for _, ip := range device.GetDeviceIPAddress("ethernet0") {
			if ip.To4() != nil {
				targets = append(targets, ip.String())
			}
		}
		return targets
	}, 2*time.Minute, 5*time.Second).ShouldNot(BeEmpty(),
		"device reports no IPv4 address on ethernet0")

	log.Infof("Scanning all TCP and UDP ports of %v", targets)
	start := time.Now()
	ports, err := ScanOpenPorts(targets, 30*time.Minute)
	t.Expect(err).ToNot(HaveOccurred())
	log.Infof("Scan took %v and found %d open port(s)",
		time.Since(start).Round(time.Second), len(ports))
	for _, p := range ports {
		log.Infof("Open port: %v", p)
	}
	evetest.Checkpoint("ports-scanned")

	for _, target := range targets {
		t.Expect(Reached(ports, target)).To(BeTrue(),
			"SSH not seen open on %s; the scan did not reach it", target)
	}
	t.Expect(Violations(ports)).To(BeEmpty())
}
