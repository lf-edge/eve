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
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func clusterDeviceRequirements(
	devName string, withTPM bool, filesystem evetest.Filesystem) evetest.RequireEdgeDevice {
	return evetest.RequireEdgeDevice{
		Name:           devName,
		WithTPM:        withTPM,
		WithHypervisor: evetest.HypervisorKubevirt,
		// We want to test cluster creation.
		DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
		// Filesystem is configurable via the FILESYSTEM parameter and defaults
		// to ext4. EVE-k formation is fsync-heavy (k3s/etcd WAL, Longhorn/CDI/
		// KubeVirt image extraction); ZFS's synchronous ZIL commit adds enough
		// fsync latency to crash-loop the in-process apiserver during the
		// single->multi-node etcd transition, whereas ext4 stays healthy. Kept
		// configurable because a lot of EVE-k behaves differently per filesystem.
		WithFilesystem: filesystem,
		WithGrubOptions: []string{
			// Application performance is not a primary concern; instead, we focus
			// on minimizing device onboarding time and accelerating cluster formation.
			"set_global hv_dom0_cpu_settings \"dom0_max_vcpus=4\"",
			"set_global hv_eve_cpu_settings \"eve_max_vcpus=3\"",
			"set_global hv_ctrd_cpu_settings \"ctrd_max_vcpus=3\"",
		},
	}
}

// TestSingleNodeCluster verifies that an EVE-K device boots, forms a
// healthy single-node K3s cluster, accepts an application deployment, and
// that the deployed container is reachable both from outside (via port
// forwarding) and outbound (curl to an SDN HTTP endpoint).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, SDN DNS,
//     http-server.test endpoint, controller reachable.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirements (top of this file): WithHypervisor=Kubevirt,
//     DeviceReusePolicy=CreateFromScratchWithLiveImage (we want to test
//     fresh cluster formation), default ext4 (changeable via the FILESYSTEM
//     parameter), plus grub options that cap dom0/eve/ctrd vcpus so
//     cluster formation is fast.
//   - SystemAdapter on eth0 (DHCP, mgmt+app, NetworkType=V4Only).
//   - One Local NI "local-ni" (10.11.12.0/24, EnableFlowlog=true) and one
//     container app with default-allow + port-fwd 2222->22.
//
// Test parameters
// ---------------
//   - TPM (bool) via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. setup-done -> initial-config-applied: apply the bare device config
//     (no app yet) and start watching ClusterInfo.
//  2. k3s-is-ready: ZInfoKubeCluster eventually reports a single node
//     whose NodeReady condition is true AND
//     Storage.Health=SERVICE_STATUS_HEALTHY. Then assert ClusterId is
//     non-empty, the node is RoleServer + Schedulable, and that no
//     EveApps / EveVmApps / PodNameSpaces have been created yet
//     (clean-slate cluster, no workload).
//  3. app-config-is-submitted: add the local NI + the container app to the
//     config and re-apply.
//  4. app-is-deployed: WaitUntilAppIsRunning (the helper tracks
//     download/install state and uses excluding-download timeouts; 10
//     min budget).
//  5. Smoke tests via RunShellScriptInsideApp (port-fwd 2222->22):
//     - `hostname` returns the app UUID (proves port-forwarding works
//     end-to-end through the kubevirt VMI shim).
//     - `curl -sS http://http-server.test/helloworld` returns
//     "Hello world!" (proves outbound app traffic via the NI).
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite (cluster tests are pinned to Kubevirt;
//     non-cluster tests must NOT use Kubevirt).
func TestSingleNodeCluster(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	// Get parameter values set for this test execution.
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := clusterDeviceRequirements(devName, withTPM, filesystem)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	device := evetest.GetEdgeDevice(devName)
	clusterUpdates, stopClusterWatch := device.WatchClusterInfo()
	defer stopClusterWatch()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	timeout := 20 * time.Minute
	var clusterInfo *eveinfo.ZInfoKubeCluster
	const nodeReadyCond = eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY
	t.Eventually(clusterUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"K3s is ready",
		func(info *eveinfo.ZInfoKubeCluster) bool {
			clusterInfo = info
			if len(info.Nodes) != 1 {
				return false
			}
			if clusterInfo.Storage.Health != eveinfo.ServiceStatus_SERVICE_STATUS_HEALTHY {
				return false
			}
			for _, cond := range info.Nodes[0].GetConditions() {
				if cond.GetType() == nodeReadyCond {
					return cond.GetSet()
				}
			}
			return false
		})))
	t.Expect(clusterInfo.ClusterId).NotTo(BeEmpty())
	t.Expect(clusterInfo.Nodes[0].RoleServer).To(BeTrue())
	t.Expect(clusterInfo.Nodes[0].Schedulable).To(BeTrue())
	t.Expect(clusterInfo.EveApps).To(BeEmpty())
	t.Expect(clusterInfo.EveVmApps).To(BeEmpty())
	t.Expect(clusterInfo.PodNameSpaces).To(BeEmpty())
	evetest.Checkpoint("k3s-is-ready")

	// Deploy a container application.
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
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
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "container-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		CPUs:        1,
		MemoryBytes: 500 * evetest.MiB,
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
	log := evetest.Logger()
	log.Infof("Submitted config with container application UUID=%v", appUUID)
	evetest.Checkpoint("app-config-is-submitted")

	timeoutExcludingDownload := 10 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-is-deployed")

	// Test port forwarding.
	// RunShellScriptInsideApp will try to use the 2222->22 port forwarding rule.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	timeout = 3 * time.Minute
	polling := 3 * time.Second
	sshTimeout := 20 * time.Second
	log.Infof("Testing port forwarding")
	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(appUUID.String()))
	}, timeout, polling).Should(Succeed())

	// Test application connectivity initiated from inside the application.
	log.Infof("Testing application connectivity")
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello world!"))
}

// TestThreeNodesCluster verifies that three EVE-K devices, each with a
// dedicated cluster-side port, form a healthy K3s cluster (replicated
// storage), and that an application deployed with affinity preference for
// node 1 lands on node 1 and is reachable.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- six ports (two per device, labeled
//     dev{1,2,3}-eth{0,1}). eth0 ports of all devices share a single
//     management+app SDN bridge with DHCP and controller reachability.
//     eth1 ports of all devices share a separate cluster-only bridge
//     (10.244.244.0/24, no Internet) used for inter-node K3s traffic.
//
// Device configuration
// --------------------
//   - Three RequireEdgeDevice entries built via clusterDeviceRequirements
//     (same params as TestSingleNodeCluster: Kubevirt, fresh image,
//     ext4 by default / configurable via FILESYSTEM, 8 GB RAM, 4 vCPUs,
//     vcpu-cap grub options).
//   - ClusterConfig (evetest.NewEdgeClusterConfig) with three
//     ClusterNode entries: each device gets a distinct ClusterIP from
//     10.244.244.0/24 (.2, .3, .4) on ClusterInterface="ethernet1".
//     Node 1 is BootstrapNode=true (cluster founder).
//   - Per-device SystemAdapter set (applied to all three nodes
//     identically): SystemAdapter on eth0 with DHCP (mgmt+app),
//     SystemAdapter on eth1 with NoIPNetworkConfig and Usage=Shared --
//     the cluster network is L3 only on top of the Kubevirt/K3s stack.
//   - cluster.ApplyConfig pushes the config to all three devices in
//     parallel.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. initial-config-applied -> nodes-are-ready: cluster.WaitUntilNodesAreReady
//     with a 30-min budget. K3s must form across the three nodes via the
//     dedicated cluster network.
//  2. app-config-is-submitted: add a Local NI + a container app
//     (milan4zededa/evetest-ubuntu-ctr:1.0) as a
//     ClusterApplicationInstanceConfig with
//     DesignatedNodeName=devName[0] and Affinity=PREFERRED -- the
//     scheduler should prefer node 1 but is allowed to pick a different
//     node if node 1 is unsuitable.
//  3. app-is-deployed: cluster.WaitUntilAppIsRunning (10 min budget
//     excluding image download).
//  4. Smoke tests via cluster.RunShellScriptInsideApp (port-fwd 2222->22):
//     - `hostname` returns the app UUID.
//     - `curl -sS http://http-server.test/helloworld` returns
//     "Hello world!".
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite. Like TestSingleNodeCluster this runs only on
//     Kubevirt.
func TestThreeNodesCluster(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	// Get parameter values set for this test execution.
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	// Set up the test harness and specify the test prerequisites.
	var requiredDevices [3]evetest.Requirement
	var devName [3]string
	for i := 0; i < 3; i++ {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		requiredDevices[i] = clusterDeviceRequirements(devName[i], withTPM, filesystem)
	}

	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort,
	}
	var requirements []evetest.Requirement
	requirements = append(requirements, requiredDevices[:]...)
	requirements = append(requirements, requiredNetModel)
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	// Build the cluster configuration.
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

	// Configure network adapters and networks (applied to all devices).
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

	// Apply the initial configuration to each device in parallel.
	cluster := evetest.NewEdgeCluster("test-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(30 * time.Minute)
	evetest.Checkpoint("nodes-are-ready")

	// Deploy an application into the cluster, preferring the first node for hosting it.
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
	appUUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
		ApplicationInstanceConfig: evetest.ApplicationInstanceConfig{
			DisplayName: "container-app",
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "milan4zededa/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			CPUs:        1,
			MemoryBytes: 500 * evetest.MiB,
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
		},
		DesignatedNodeName: devName[0],
		Affinity:           eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
	})
	cluster.ApplyConfig(clusterConfig, true, true)
	log := evetest.Logger()
	log.Infof("Submitted config with container application UUID=%v", appUUID)
	evetest.Checkpoint("app-config-is-submitted")

	timeoutExcludingDownload := 10 * time.Minute
	cluster.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-is-deployed")

	// Test port forwarding.
	// RunShellScriptInsideApp will try to use the 2222->22 port forwarding rule.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	timeout := 3 * time.Minute
	polling := 3 * time.Second
	sshTimeout := 20 * time.Second
	log.Infof("Testing port forwarding")
	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		output, _, err := cluster.RunShellScriptInsideApp(appUUID, appAuth,
			"hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(appUUID.String()))
	}, timeout, polling).Should(Succeed())

	// Test application connectivity initiated from inside the application.
	log.Infof("Testing application connectivity")
	output, _, err := cluster.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello world!"))
}
