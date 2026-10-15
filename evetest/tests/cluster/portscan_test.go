// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/tests/portscan"
)

// TestThreeNodesPortScan scans every TCP and UDP port of each node of a
// three-node EVE-k cluster, on both its management and its cluster address,
// and verifies that nothing is exposed beyond SSH, or that whatever is
// exposed is HTTPS-only and refuses anonymous access. The cluster address is
// where EVE's firewall admits the K3s API server, kubelet, etcd and the
// zedkube cluster-status server.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort, as in TestThreeNodesCluster. nmap runs in
//     the evetest container and reaches both networks through the SDN tunnel.
//
// Device configuration
// --------------------
//   - The devices and cluster config of TestThreeNodesCluster, without the
//     application. Running right after it lets evetest reuse its devices.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. initial-config-applied -> nodes-are-ready: cluster.WaitUntilNodesAreReady
//     with a 30-min budget, so that every K3s listener is up before the scan.
//  2. ports-scanned: SYN scan and UDP scan of all 65535 ports of every node's
//     IPv4 management address and its cluster IP (10.244.244.2-4). Every open
//     port is logged. The SSH port must be open on each address, which proves
//     the scan reached it.
//  3. The App-Tracker on each node's loopback interface reports all three
//     nodes, which it can only do by querying the other nodes'
//     authenticated cluster-status servers.
//  4. The open ports are held to the same policy as in
//     tests/portscan.TestExternalPortScan (see portscan.Violations).
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite, right after TestThreeNodesCluster.
func TestThreeNodesPortScan(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	devName := setupThreeNodes(withTPM, filesystem, false)
	evetest.Checkpoint("setup-done")

	cluster := evetest.NewEdgeCluster("test-cluster")
	cluster.ApplyConfig(newThreeNodeClusterConfig(devName), true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(30 * time.Minute)
	evetest.Checkpoint("nodes-are-ready")

	var targets []string
	for i, name := range devName {
		device := evetest.GetEdgeDevice(name)
		var mgmtIPs []string
		t.Eventually(func() []string {
			mgmtIPs = nil
			for _, ip := range device.GetDeviceIPAddress("ethernet0") {
				if ip.To4() != nil {
					mgmtIPs = append(mgmtIPs, ip.String())
				}
			}
			return mgmtIPs
		}, 2*time.Minute, 5*time.Second).ShouldNot(BeEmpty(),
			"%s reports no IPv4 address on ethernet0", name)
		targets = append(targets, mgmtIPs...)
		targets = append(targets, fmt.Sprintf("10.244.244.%d", i+2))
	}

	log := evetest.Logger()
	log.Infof("Scanning all TCP and UDP ports of %v", targets)
	start := time.Now()
	ports, err := portscan.ScanOpenPorts(targets, 60*time.Minute)
	t.Expect(err).ToNot(HaveOccurred())
	log.Infof("Scan took %v and found %d open port(s)",
		time.Since(start).Round(time.Second), len(ports))
	for _, p := range ports {
		log.Infof("Open port: %v", p)
	}
	evetest.Checkpoint("ports-scanned")

	for _, target := range targets {
		t.Expect(portscan.Reached(ports, target)).To(BeTrue(),
			"SSH not seen open on %s; the scan did not reach it", target)
	}

	for _, name := range devName {
		t.Expect(clusterAppTrackerNodes(evetest.GetEdgeDevice(name))).To(
			HaveLen(len(devName)),
			"App-Tracker on %s does not report every node", name)
	}
	evetest.Checkpoint("app-tracker-checked")

	t.Expect(portscan.Violations(ports)).To(BeEmpty())
}

// appTrackerPort is where zedkube serves the App-Tracker on 127.0.0.1.
const appTrackerPort = "12346"

// clusterAppTrackerNodes queries the App-Tracker on device's loopback
// interface for the cluster-wide status of no particular application, and
// returns the hostnames of the nodes that answered with their status.
func clusterAppTrackerNodes(device *evetest.EdgeDevice) ([]string, error) {
	client := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return device.DialViaSSH(network, addr)
			},
		},
	}
	resp, err := client.Get("http://" +
		net.JoinHostPort("127.0.0.1", appTrackerPort) + "/cluster-app/")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("App-Tracker answered with status %d", resp.StatusCode)
	}
	var combined struct {
		Value []struct {
			Hostname    string `json:"hostname"`
			CollectTime string `json:"collectTime"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&combined); err != nil {
		return nil, fmt.Errorf("decode App-Tracker answer: %w", err)
	}
	var nodes []string
	for _, v := range combined.Value {
		// An entry without collectTime reports a node that timed out.
		if v.CollectTime != "" {
			nodes = append(nodes, v.Hostname)
		}
	}
	return nodes, nil
}
