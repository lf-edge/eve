// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
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

// Timeouts for this test. An Eventually stops as soon as its condition holds,
// so a large bound only delays a true failure.
const (
	// pvcGCClusterTimeout bounds three nodes forming a cluster.
	pvcGCClusterTimeout = 30 * time.Minute

	// pvcGCAppReadyTimeout bounds the app reaching RUNNING, excluding download.
	pvcGCAppReadyTimeout = 15 * time.Minute

	// pvcGCPurgeTimeout bounds the purge.
	pvcGCPurgeTimeout = 10 * time.Minute

	// pvcGCReclaimTimeout bounds the old PVC disappearing. A GC pass runs every
	// six seconds here, so this absorbs the Longhorn delete behind it.
	pvcGCReclaimTimeout = 5 * time.Minute

	// pvcGCPollInterval is coarse because each poll runs kubectl on the device.
	pvcGCPollInterval = 10 * time.Second

	// pvcGCSettleWindow holds the survival assertion for many GC passes. That
	// repetition is the subject of this test.
	pvcGCSettleWindow = 90 * time.Second

	// pvcGCSettleInterval is how often the survival assertion re-checks.
	pvcGCSettleInterval = 15 * time.Second

	// pvcGCVdiskGCTime is timer.gc.vdisk's floor. The GC ticker is
	// vdiskGCTime/10, so a pass runs every six seconds.
	pvcGCVdiskGCTime = 60
)

// clusterPVCNames returns every PVC name in the EVE app namespace, as one node
// sees it. A kubectl failure fails the assertion. An empty set would satisfy
// the absence half of this test for the wrong reason.
func clusterPVCNames(g Gomega, dev *evetest.EdgeDevice) map[string]bool {
	list, err := dev.KubectlListItems("pvc")
	g.Expect(err).ToNot(HaveOccurred(),
		"listing PVCs from device %q", dev.Name())
	names := make(map[string]bool, len(list.Items))
	for _, item := range list.Items {
		names[item.Metadata.Name] = true
	}
	return names
}

// nodeVolumeConfigs returns the VolumeConfigs zedagent publishes on one node.
// The designated node gets IsReplicated false. Every other node gets true.
// See cmd/zedagent/handlevolume.go.
func nodeVolumeConfigs(g Gomega, dev *evetest.EdgeDevice) []pillartypes.VolumeConfig {
	configs, err := evetest.ReadAllPublications[pillartypes.VolumeConfig](
		dev, "zedagent", false)
	g.Expect(err).ToNot(HaveOccurred(),
		"reading zedagent's VolumeConfig publications from %q", dev.Name())
	return configs
}

// nodeVolumeStatuses returns the VolumeStatuses volumemgr publishes on one
// node. gcPVCs reaps any PVC that no entry here names. This set is therefore
// the only protection against that node's own GC pass.
func nodeVolumeStatuses(g Gomega, dev *evetest.EdgeDevice) []pillartypes.VolumeStatus {
	statuses, err := evetest.ReadAllPublications[pillartypes.VolumeStatus](
		dev, "volumemgr", false)
	g.Expect(err).ToNot(HaveOccurred(),
		"reading volumemgr's VolumeStatus publications from %q", dev.Name())
	return statuses
}

// TestClusterPVCGCPreservesLiveVolumes checks that volumemgr's PVC garbage
// collection keeps a PVC that a live VolumeConfig still refers to. It must keep
// it on every node, whether that node owns the volume or replicates it.
//
// The test needs a cluster. IsReplicated is true only on a node that does not
// own the volume, so one node shows one case. Three nodes with one app show
// both at once, and each node runs its own GC pass.
//
// One check protects a live PVC: gcPVCs reaps a PVC when no VolumeStatus on
// that node names it. The IsReplicated guard beside it never fires here,
// because a PVC name carries no replication bit. The test therefore asserts
// per node that the VolumeStatus is present.
//
// A purge supplies the positive control. "The PVC is still there" also passes
// when GC never runs. The purge moves the app to a new generation and orphans
// the old PVC. The old PVC disappears, which proves GC runs. The new PVC stays,
// which is the property under test.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- eth0 on a management+app bridge with
//     DHCP, eth1 on a cluster-only bridge for K3s traffic.
//
// Device configuration
// --------------------
//   - Three clusterDeviceRequirements devices (Kubevirt, fresh image,
//     filesystem per FILESYSTEM).
//   - ClusterConfig (REPLICATED_STORAGE) over three nodes, node 1 bootstrap.
//   - timer.gc.vdisk at its 60s floor, so a GC pass runs every six seconds.
//   - One Local NI "local-ni" (10.11.15.0/24) and one app designated to node 1.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. setup-done -> nodes-are-ready: bring up the cluster.
//  2. app-is-running: deploy the app and wait for RUNNING.
//  3. ownership-asserted: node 1 reports IsReplicated false, nodes 2 and 3
//     report true. Without this the test can cover one case only.
//  4. purge-complete: purge the app, which orphans the old generation's PVC.
//  5. old-pvc-reclaimed: the old PVC goes away and the new PVC stays.
//  6. live-pvc-survives: the new PVC stays for many more GC passes on each
//     node, and the app stays RUNNING.
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite (cluster tests are pinned to Kubevirt).
func TestClusterPVCGCPreservesLiveVolumes(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	var requiredDevices [3]evetest.Requirement
	var devName [3]string
	for i := 0; i < 3; i++ {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		requiredDevices[i] = clusterDeviceRequirements(
			devName[i], withTPM, filesystem, false)
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort,
	}
	var requirements []evetest.Requirement
	requirements = append(requirements, requiredDevices[:]...)
	requirements = append(requirements, requiredNetModel)
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	var nodes [3]evetest.ClusterNode
	for i := 0; i < 3; i++ {
		clusterIP := evetest.IPAddressWithPrefix(fmt.Sprintf("10.244.244.%d/24", i+2))
		nodes[i] = evetest.ClusterNode{
			DevName:          devName[i],
			ClusterIP:        clusterIP,
			ClusterInterface: "ethernet1",
			BootstrapNode:    i == 0,
		}
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE,
		nodes[:]...,
	)

	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.VdiskGCTime, pvcGCVdiskGCTime)
	clusterConfig.SetConfigProperties(cfgProps)

	dhcpNet := clusterConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet1",
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			NetworkUUID:   noIPNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		})

	cluster := evetest.NewEdgeCluster("pvc-gc-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(pvcGCClusterTimeout)
	evetest.Checkpoint("nodes-are-ready")

	niUUID := clusterConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.15.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.15.2"),
			End:   evetest.IPAddress("10.11.15.254"),
		},
		Gateway:       evetest.IPAddress("10.11.15.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	appUUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
		ApplicationInstanceConfig: evetest.ApplicationInstanceConfig{
			DisplayName: "pvc-gc-app",
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			CPUs:        1,
			MemoryBytes: 500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
				},
			},
		},
		DesignatedNodeName: devName[0],
		Affinity:           eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
	})
	cluster.ApplyConfig(clusterConfig, true, true)
	log := evetest.Logger()
	log.Infof("Submitted config with application UUID=%v, designated node %q",
		appUUID, devName[0])
	evetest.Checkpoint("app-config-is-submitted")

	cluster.WaitUntilAppIsRunning(appUUID, pvcGCAppReadyTimeout)
	evetest.Checkpoint("app-is-running")

	// Read from the owner. That node built the disk.
	owner := evetest.GetEdgeDevice(devName[0])
	oldPVCName := ""
	t.Eventually(func(g Gomega) {
		statuses := nodeVolumeStatuses(g, owner)
		g.Expect(statuses).To(HaveLen(1),
			"expected exactly one volume on the designated node, found %d",
			len(statuses))
		oldPVCName = statuses[0].GetPVCName()
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())
	log.Infof("Pre-purge PVC is %q", oldPVCName)

	// Assert the ownership split. If it stops holding, this test covers one
	// case only, and says nothing about the other.
	t.Eventually(func(g Gomega) {
		for i, name := range devName {
			dev := evetest.GetEdgeDevice(name)
			configs := nodeVolumeConfigs(g, dev)
			g.Expect(configs).ToNot(BeEmpty(),
				"node %q publishes no VolumeConfig at all", name)
			for _, vc := range configs {
				if i == 0 {
					g.Expect(vc.IsReplicated).To(BeFalse(),
						"the designated node %q must own volume %s, not replicate it",
						name, vc.Key())
				} else {
					g.Expect(vc.IsReplicated).To(BeTrue(),
						"non-designated node %q must see volume %s as replicated",
						name, vc.Key())
				}
			}
		}
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())
	evetest.Checkpoint("ownership-asserted")

	// The purge moves the app to a new generation. Nothing then refers to the
	// old generation's PVC. This is the positive control below.
	cluster.PurgeApplication(appUUID, true, pvcGCPurgeTimeout)
	evetest.Checkpoint("purge-complete")

	cluster.WaitUntilAppIsRunning(appUUID, pvcGCAppReadyTimeout)

	newPVCName := ""
	t.Eventually(func(g Gomega) {
		statuses := nodeVolumeStatuses(g, owner)
		g.Expect(statuses).To(HaveLen(1),
			"expected exactly one volume after the purge, found %d", len(statuses))
		newPVCName = statuses[0].GetPVCName()
		g.Expect(newPVCName).ToNot(Equal(oldPVCName),
			"the purge must have moved the app to a new volume generation")
	}, pvcGCAppReadyTimeout, pvcGCPollInterval).Should(Succeed())
	log.Infof("Post-purge PVC is %q (was %q)", newPVCName, oldPVCName)

	// The old PVC must go away. This proves gcPVCs runs. The new PVC must stay
	// while that happens.
	t.Eventually(func(g Gomega) {
		present := clusterPVCNames(g, owner)
		g.Expect(present).ToNot(HaveKey(oldPVCName),
			"the superseded generation's PVC %q must be reclaimed", oldPVCName)
		g.Expect(present).To(HaveKey(newPVCName),
			"the live generation's PVC %q must not be reclaimed with it", newPVCName)
	}, pvcGCReclaimTimeout, pvcGCPollInterval).Should(Succeed())
	evetest.Checkpoint("old-pvc-reclaimed")

	// The property under test. Each node runs a GC pass every six seconds. Hold
	// for many more passes. Each node must still see the live PVC, and must
	// still publish the VolumeStatus that protects it.
	t.Consistently(func(g Gomega) {
		for _, name := range devName {
			dev := evetest.GetEdgeDevice(name)
			g.Expect(clusterPVCNames(g, dev)).To(HaveKey(newPVCName),
				"node %q no longer sees the live PVC %q - a GC pass reclaimed a "+
					"disk that a live VolumeConfig still refers to", name, newPVCName)

			named := false
			for _, vs := range nodeVolumeStatuses(g, dev) {
				if vs.GetPVCName() == newPVCName {
					named = true
					break
				}
			}
			g.Expect(named).To(BeTrue(),
				"node %q publishes no VolumeStatus naming %q, so nothing there "+
					"protects it from that node's own gcPVCs pass", name, newPVCName)
		}
	}, pvcGCSettleWindow, pvcGCSettleInterval).Should(Succeed())
	evetest.Checkpoint("live-pvc-survives")

	// A reclaimed disk does not always show as an app error at once. This check
	// is therefore weak alone. A failure here means the damage reached the
	// guest. Ask the node that hosts the app.
	host := cluster.FindDeviceHostingApp(appUUID, pvcGCPollInterval)
	appInfo := host.GetAppInfo(appUUID)
	t.Expect(appInfo).ToNot(BeNil(),
		"expected app info from host %q after the settle window", host.Name())
	t.Expect(appInfo.GetAppErr()).To(BeEmpty(),
		"the app must still be healthy after repeated GC passes")
}
