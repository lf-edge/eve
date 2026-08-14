// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

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
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestVMAppPurgeDuringFailover exercises a purge issued after the app's
// designated node has failed over: the app's designated node is powered
// off, KubeVirt reschedules the replica onto a different node, and a purge
// is then issued while the designated node is still down. The purge must
// not wait on the dead node: gating the teardown on the app's designated
// node, or on where a replica currently happens to be scheduled, would
// deadlock exactly this case, because neither signal is both durable and
// liveness-aware on its own.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- six ports (two per device): eth0
//     ports share a management+app SDN bridge with DHCP and controller
//     reachability; eth1 ports share a separate cluster-only bridge used
//     for inter-node K3s traffic.
//
// Device configuration
// --------------------
//   - Three purgeDeviceRequirements (purge_helpers_test.go) devices, called
//     with HypervisorKubevirt - same fresh-image/vcpu-cap setup as the other
//     Kubevirt tests in this suite, following tests/cluster/cluster_test.go's
//     TestThreeNodesCluster topology.
//   - ClusterConfig (REPLICATED_STORAGE) with three ClusterNode entries on
//     10.244.244.0/24; node 1 is the bootstrap node.
//   - One Local NI "local-ni" (10.11.14.0/24) and one shim-VM app
//     (vmShimApplication) with DesignatedNodeName=devName[0] (node 1) and
//     Affinity=PREFERRED.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//   - HYPERVISOR is read from the suite only to skip on anything but kubevirt;
//     the three devices are always required as Kubevirt nodes, since a VMIRS
//     and a replicated-storage cluster exist nowhere else.
//
// Phases
// ------
//  1. setup-done -> nodes-are-ready: bring up the three-node cluster.
//  2. app-is-deployed: deploy the app; assert it is in fact running on its
//     preferred (DNID) node, node 1, while node 1 is healthy.
//  3. dnid-node-powered-off: EdgeDevice.PowerOff() on node 1.
//  4. failed-over: EdgeCluster.FindDeviceHostingApp with node 1 excluded waits
//     for KubeVirt to reschedule the replica onto node 2 or node 3. The
//     exclusion matters: without it the powered-off node's own stale cluster
//     info still names it as the host and would be returned immediately.
//  5. purge-complete: EdgeCluster.PurgeApplication(waitUntilPurged=true) -
//     this bumps the purge counter on every device (including the
//     powered-off node 1 - EdgeDevice.ApplyConfig's push does not require
//     device reachability) but waits only on the node actually hosting the
//     app; there is no exclusive gate on the delete itself.
//  6. End-state assertion: exactly one VMIRS, named for the NEW generation,
//     observed from the node that now hosts the app. Unlike the other two
//     tests in this suite, this one makes no volume or guest-level assertion
//     (VolumeStatus is a per-node ephemeral publication and its
//     clustered/replicated-storage semantics across a node failover have
//     not been established for this suite; the app's forwarded SSH port on
//     the new host has not been either).
//  7. dnid-node-powered-on: power node 1 back on so cluster teardown does
//     not have to reason about an already-off device.
//
// Suite placement
// ---------------
//   - TestAppsSuite, last: it is the only subtest needing three devices, so it
//     is also the most expensive to set up.
func TestVMAppPurgeDuringFailover(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	if hypervisor := evetest.GetHypervisorParameterValue(); hypervisor != evetest.HypervisorKubevirt {
		evetestT.Skipf("HYPERVISOR is %s: this test needs a replicated-storage "+
			"cluster and asserts on VMIRS objects, which only exist on kubevirt",
			hypervisor)
	}
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	var requiredDevices [3]evetest.Requirement
	var devName [3]string
	for i := 0; i < 3; i++ {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		requiredDevices[i] = purgeDeviceRequirements(devName[i], withTPM, filesystem,
			evetest.HypervisorKubevirt)
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

	cluster := evetest.NewEdgeCluster("purge-failover-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(clusterFormationTimeout)
	evetest.Checkpoint("nodes-are-ready")

	niUUID := clusterConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.14.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.14.2"),
			End:   evetest.IPAddress("10.11.14.254"),
		},
		Gateway:       evetest.IPAddress("10.11.14.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	const appDisplayName = "purge-app"
	appUUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
		ApplicationInstanceConfig: vmShimApplication(appDisplayName, niUUID),
		DesignatedNodeName:        devName[0],
		Affinity:                  eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
	})
	cluster.ApplyConfig(clusterConfig, true, true)
	log := evetest.Logger()
	log.Infof("Submitted config with application UUID=%v, DNID node=%q", appUUID, devName[0])
	evetest.Checkpoint("app-config-is-submitted")

	cluster.WaitUntilAppIsRunning(appUUID, appReadyTimeout)
	evetest.Checkpoint("app-is-deployed")

	initialHost := cluster.FindDeviceHostingApp(appUUID, time.Minute)
	t.Expect(initialHost.Name()).To(Equal(devName[0]),
		"app should have been scheduled onto its preferred (DNID) node while it is healthy")

	dnidDevice := evetest.GetEdgeDevice(devName[0])
	baselineCounter, _ := purgeCounter(dnidDevice, appUUID)

	log.Infof("Powering off DNID node %q to force a failover", devName[0])
	dnidDevice.PowerOff()
	evetest.Checkpoint("dnid-node-powered-off")

	failoverHost := cluster.FindDeviceHostingApp(appUUID, failoverTimeout, devName[0])
	log.Infof("App failed over to device %q", failoverHost.Name())
	evetest.Checkpoint("failed-over")

	cluster.PurgeApplication(appUUID, true, purgeCompleteTimeout)
	evetest.Checkpoint("purge-complete")

	wantCounter := baselineCounter + 1
	t.Eventually(func(g Gomega) {
		assertExactlyOneVMIRSAtGeneration(g, failoverHost, appUUID, appDisplayName, wantCounter)
	}, purgeEndStateTimeout, assertPollInterval).Should(Succeed())

	log.Infof("Powering DNID node %q back on", devName[0])
	dnidDevice.PowerOn(true)
	evetest.Checkpoint("dnid-node-powered-on")
}
