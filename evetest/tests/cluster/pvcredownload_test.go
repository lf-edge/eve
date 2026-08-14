// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"google.golang.org/protobuf/proto"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// pvcRedownloadRebootTimeout bounds waiting for a node to reboot and,
	// for the two surviving nodes, rejoin the cluster. Generous: a full
	// device reboot plus k3s/etcd rejoin is slow.
	pvcRedownloadRebootTimeout = 30 * time.Minute

	pvcRedownloadPollInterval = 15 * time.Second
)

// TestClusterPVCRedownload reproduces a customer-reported field defect: after
// a cluster maintenance event, EVE re-downloads a VM's multi-GB qcow2 source
// image even though the Longhorn PVC that image exists to fill is already
// Bound and CDI-complete, needlessly blocking the app if the datastore is
// slow or unreachable.
//
// Not a DesignatedNodeID change, contrary to this branch's working
// assumption for most of its history: ContentTreeStatus and
// ContentTreeConfig both publish non-persistent, so a plain reboot --
// volumemgr is its own process -- wipes its cache and resets every
// locally-owned content tree to INITIAL, regardless of whether
// DesignatedNodeID ever changed. Neither VM here is ever re-designated.
//
// Reported steps, and how each maps to this test:
//  1. Shutdown all apps -- DeactivateApplication on both VMs.
//  2. Prepare power off Node1 and the tie-breaker -- EdgeDevConfig.Shutdown
//     on those two devices only, not Node2. Real controller mechanism
//     (drains and deactivates every app on the device), redundant with
//     step 1 for vm1, same as it would be in the field.
//  3. Shutdown 3x nodes -- hard PowerOff on all three, unconditionally.
//  4. Shutdown the datastore -- an SDN firewall rule drops traffic to
//     evetest's image server, for every node, left in place for the rest
//     of the test.
//  5. Disable Node2's cluster interface -- AdminUp=false on its
//     cluster-interconnect port, applied together with step 4 (one
//     NetworkModel update; a second UpdateNetworkModel call would replace
//     the whole model, undoing whichever change came first).
//  6. Bring the 3 nodes up -- Node1 and the tie-breaker rejoin; Node2
//     keeps mgmt/app connectivity but never rejoins the cluster.
//  7. Activate the 2 VMs -- VM1 (Node1) is waited on, since it's this
//     test's subject; VM2 (the isolated Node2) is fire-and-forget.
//  8. Verify VM1 comes online on Node1.
//  9. Verify it still attempts to download its content tree despite being
//     online -- asserted as the fixed behavior (REMOTELOADED), not the
//     reported bug, so this passes on the fix and fails on master.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- the same model TestThreeNodesCluster
//     and TestTieBreakerCluster use, cloned once to add the firewall rule
//     and port change above.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirementsForVMApp (top of cluster_test.go): the same
//     three devices as clusterDeviceRequirements, minus its vCPU caps --
//     see that function's doc comment for why a real CDI import needs
//     them absent. edge-dev1 is the bootstrap node and hosts VM1;
//     edge-dev2 hosts VM2 and is the node isolated in step 5; edge-dev3
//     is the tie-breaker.
//
// Test params
// -----------
//   - TPM (bool), FILESYSTEM.
//
// Suite placement
// ---------------
//   - Not in TestNodeClusterSuite yet. This is the first test to combine
//     multi-node power-cycling, network-model changes mid-test, and a VM
//     app in one sequence; it needs a real run before its timing and
//     failure modes are understood well enough to place it.
func TestClusterPVCRedownload(test *testing.T) {
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
		requiredDevices[i] = clusterDeviceRequirementsForVMApp(devName[i], withTPM, filesystem)
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort,
	}
	var requirements []evetest.Requirement
	requirements = append(requirements, requiredDevices[:]...)
	requirements = append(requirements, requiredNetModel)
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	const tieBreakerIdx = 2
	// Fixed layout for this test, always: devName[0] (Node A) and
	// devName[1] (Node B) are plain cluster members; devName[2] (Node C)
	// is always the tie-breaker. Node A hosts vm1 and is the bootstrap
	// node; Node B hosts vm2 and is the node isolated in step 5.
	var nodes [3]evetest.ClusterNode
	for i := 0; i < 3; i++ {
		clusterIP := evetest.IPAddressWithPrefix(fmt.Sprintf("10.244.244.%d/24", i+2))
		nodes[i] = evetest.ClusterNode{
			DevName:          devName[i],
			ClusterIP:        clusterIP,
			ClusterInterface: "ethernet1",
			BootstrapNode:    i == 0,
			TieBreaker:       i == tieBreakerIdx,
		}
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE,
		nodes[:]...,
	)

	dhcpNet := clusterConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel: "ethernet0", PhysicalLabel: "eth0", InterfaceName: "eth0",
		NetworkUUID: dhcpNet, Usage: evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	clusterConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel: "ethernet1", PhysicalLabel: "eth1", InterfaceName: "eth1",
		NetworkUUID: noIPNet, Usage: evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	cluster := evetest.NewEdgeCluster("test-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(30 * time.Minute)
	evetest.Checkpoint("nodes-are-ready")

	// Nodes reporting Ready doesn't mean Longhorn/CDI/the k3s control
	// plane are done with their own first-time bring-up churn; hitting
	// them immediately with a real CDI import competes with that churn.
	time.Sleep(2 * time.Minute)
	evetest.Checkpoint("cluster-settled")

	log := evetest.Logger()
	dev1 := evetest.GetEdgeDevice(devName[0])
	dev2 := evetest.GetEdgeDevice(devName[1])
	dev3 := evetest.GetEdgeDevice(devName[2])

	// Both VMs share one source image; PVCs are per-volume, so that's fine.
	image, ok := vmAppAlpineImages[dev1.GetArch()]
	t.Expect(ok).To(BeTrue(), "no pinned Alpine image for arch %q", dev1.GetArch())
	imagePath := evetest.FetchAndServeImageFile(
		"https://dl-cdn.alpinelinux.org"+image.relativePath,
		"pvc-redownload-alpine.qcow2", image.sha256)
	evetest.Checkpoint("image-fetched")

	vmImage := func() evetest.HTTPStorage {
		return evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_QCOW2,
			ImageSHA256:       image.sha256,
			MaxDownloadBytes:  image.sizeBytes,
			ImageRelativePath: imagePath,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerPort(),
		}
	}

	niUUID := clusterConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ForwardLLDP:   false,
	})

	newVMApp := func(displayName, designatedNode string) evetest.ClusterApplicationInstanceConfig {
		return evetest.ClusterApplicationInstanceConfig{
			ApplicationInstanceConfig: evetest.ApplicationInstanceConfig{
				DisplayName: displayName,
				Activate:    true,
				Image:       vmImage(),
				// Left unset, the target PVC is sized to exactly the
				// image's own virtual size, leaving no room for CDI's
				// scratch-space qcow2->raw conversion.
				DiskBytes:          1 * evetest.GiB,
				VirtualizationMode: eveconfig.VmMode_HVM,
				CPUs:               1,
				MemoryBytes:        512 * evetest.MiB,
				NetworkAdapters: []evetest.AppNetworkAdapter{
					evetest.VirtualNetworkAdapter{
						LogicalLabel:        displayName + "-vif0",
						NetworkInstanceUUID: niUUID,
					},
				},
			},
			DesignatedNodeName: designatedNode,
			Affinity:           eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
		}
	}
	// Precondition the bug depends on: both PVCs Bound and CDI-complete.
	// Deployed one at a time, not in one ApplyConfig, so a failure here
	// names exactly which app failed rather than leaving two concurrent
	// CDI imports to disentangle.
	vm1UUID := clusterConfig.AddApplication(newVMApp("vm1", devName[0]))
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Waiting for vm1 to reach RUNNING for the first time")
	dev1.WaitUntilAppIsRunning(vm1UUID, pvcRedownloadRebootTimeout)
	evetest.Checkpoint("vm1-initially-running")

	vm2UUID := clusterConfig.AddApplication(newVMApp("vm2", devName[1]))
	cluster.ApplyConfig(clusterConfig, true, true)
	log.Infof("Waiting for vm2 to reach RUNNING for the first time")
	dev2.WaitUntilAppIsRunning(vm2UUID, pvcRedownloadRebootTimeout)
	evetest.Checkpoint("vms-initially-running")

	// Step 1: shut down both apps from the controller.
	dev1.DeactivateApplication(vm1UUID, true, pvcRedownloadRebootTimeout)
	dev2.DeactivateApplication(vm2UUID, true, pvcRedownloadRebootTimeout)
	evetest.Checkpoint("apps-deactivated")

	// Step 2: prepare Node A and the tie-breaker (Node C) for power off.
	// EdgeDevConfig.Shutdown drains and deactivates every app instance on
	// each -- redundant with step 1 above for vm1, but that redundancy is
	// the real controller behavior being modeled. Node B is deliberately
	// excluded: it gets no shutdown-prepare of its own, only the hard
	// power loss below.
	dev1.PrepareShutdown()
	dev3.PrepareShutdown()
	evetest.Checkpoint("shutdown-prepared")
	time.Sleep(2 * time.Minute)
	evetest.Checkpoint("drains-begun")

	// Step 3: hard power loss on all three nodes, regardless of which
	// ones were prepared above.
	clusterDevices := []*evetest.EdgeDevice{dev1, dev2, dev3}
	evetest.RunParallel(3, func(i int) {
		clusterDevices[i].PowerOff()
	})
	evetest.Checkpoint("nodes-powered-off")

	// Steps 4+5, as one model update -- a second UpdateNetworkModel call
	// would replace the whole model, undoing whichever change came first.
	//
	// Step 4: drop traffic to the image server from every node (SrcSubnet
	// 0.0.0.0/0). Everything else -- mgmt, cluster interconnect -- keeps
	// working, since the SDN's firewall is default-allow and only this
	// one destination is matched.
	//
	// Step 5: bring down only Node B's cluster-interconnect port
	// (dev2-eth1). Node A and Node C keep their own cluster ports up and
	// reform the cluster between themselves; Node B's isolation is what
	// keeps it out.
	restrictedModel := proto.Clone(netmodels.SeparateClusterPort).(*api.NetworkModel)
	restrictedModel.Firewall = &api.Firewall{
		Rules: []*api.FwRule{
			{
				SrcSubnet: "0.0.0.0/0",
				DstSubnet: evetest.GetImageServerIPv4().String() + "/32",
				Action:    api.FwAction_FW_DROP,
			},
		},
	}
	for _, p := range restrictedModel.Ports {
		if p.LogicalLabel == "dev2-eth1" {
			p.AdminUp = false
		}
	}
	evetest.UpdateNetworkModel(restrictedModel)
	evetest.Checkpoint("datastore-severed-node2-isolated")

	// Step 6. waitUntilOnline=false per PowerOn's own caveat about
	// LastRebootTime not reliably republishing after a hard power-off;
	// recovery is confirmed below via cluster membership instead.
	evetest.RunParallel(3, func(i int) {
		clusterDevices[i].PowerOn(false)
	})
	evetest.Checkpoint("nodes-powered-on")

	// cluster.WaitUntilNodesAreReady is not usable here: it waits for
	// every originally-configured node, and Node2 never rejoins.
	log.Infof("Waiting for %s and %s to reform the cluster without %s",
		devName[0], devName[tieBreakerIdx], devName[1])
	t.Eventually(func() (int, error) {
		out, err := runKubectl(dev1, `get nodes`+
			` -o jsonpath="{range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{'\n'}{end}"`)
		if err != nil {
			return 0, err
		}
		ready := 0
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.TrimSpace(line) == "True" {
				ready++
			}
		}
		return ready, nil
	}, pvcRedownloadRebootTimeout, pvcRedownloadPollInterval).Should(Equal(2),
		"expected exactly the two surviving nodes to report Ready; "+
			"Node2's cluster interconnect is down and it cannot rejoin")
	evetest.Checkpoint("cluster-reformed")

	// Steps 7+8. VM2's outcome on the departed Node2 is a different
	// question than the one this test asks, hence fire-and-forget.
	dev2.ActivateApplication(vm2UUID, false, 0)
	log.Infof("Waiting for vm1 to come back online on %s", devName[0])
	dev1.ActivateApplication(vm1UUID, true, pvcRedownloadRebootTimeout)
	evetest.Checkpoint("vm1-reactivated")

	hostDevice := cluster.FindDeviceHostingApp(vm1UUID, 2*time.Minute)
	t.Expect(hostDevice).NotTo(BeNil(), "no cluster device reports hosting vm1")
	t.Expect(hostDevice.GetConfig().GetDeviceName()).To(Equal(devName[0]),
		"vm1 landed on a node other than its DesignatedNodeName")
	evetest.Checkpoint("vm1-online")

	// Step 9. The datastore has been unreachable since step 4, so vm1
	// getting this far already rules out a real download; this asserts it
	// explicitly, on the fixed-behavior side (REMOTELOADED).
	var contentTrees []types.ContentTreeStatus
	t.Eventually(func() error {
		var err error
		contentTrees, err = evetest.ReadAllPublications[types.ContentTreeStatus](
			dev1, "volumemgr", false)
		return err
	}, 2*time.Minute, pvcRedownloadPollInterval).Should(Succeed())

	// vm1 and vm2 share one source image, so matching on ContentSha256
	// alone is ambiguous: dev1 also carries a synced-but-not-local
	// ContentTreeStatus for vm2, parked at LOADED by an unrelated
	// !IsLocal shortcut that never touches the download pipeline. IsLocal
	// is what actually picks out vm1's own tree on this device.
	var vm1Tree *types.ContentTreeStatus
	for i := range contentTrees {
		if contentTrees[i].ContentSha256 == image.sha256 && contentTrees[i].IsLocal {
			vm1Tree = &contentTrees[i]
			break
		}
	}
	t.Expect(vm1Tree).NotTo(BeNil(),
		"no local ContentTreeStatus on %s matches vm1's image SHA256 %s", devName[0], image.sha256)
	t.Expect(vm1Tree.State).To(Equal(types.REMOTELOADED),
		"vm1's content tree is in state %v, not REMOTELOADED -- "+
			"it was re-downloaded despite the PVC already being complete", vm1Tree.State)

	downloaderConfigs, err := evetest.ReadAllPublications[types.DownloaderConfig](
		dev1, "volumemgr", false)
	t.Expect(err).NotTo(HaveOccurred())
	for _, dc := range downloaderConfigs {
		t.Expect(dc.ImageSha256).NotTo(Equal(image.sha256),
			"volumemgr published a DownloaderConfig for vm1's image despite its PVC being complete")
	}
	evetest.Checkpoint("no-redownload-verified")
}
