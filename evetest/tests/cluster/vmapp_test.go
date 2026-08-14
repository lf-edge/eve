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
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// vmAppAlpineImage describes the pinned Alpine Linux cloud-init qcow2 image
// used to boot the VM app in this test. Kept as its own copy rather than a
// shared reference to tests/apps/vnc_test.go's identical map -- the same
// duplication already exists between that file and
// tests/security/vcom_test.go.
type vmAppAlpineImage struct {
	relativePath string
	sha256       string
	sizeBytes    uint64
}

// Alpine 3.24.1 cloud images, pinned by release version (not a rolling
// "latest" alias) so the SHA256 below stays valid indefinitely. See
// https://alpinelinux.org/cloud/ for the full image list.
var vmAppAlpineImages = map[string]vmAppAlpineImage{
	"amd64": {
		relativePath: "/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2",
		sha256:       "6e2e6fe0572b6632527f268d3659e8fccebda4e1ee470fafe2c4d7b85b6a4df6",
		sizeBytes:    183697408,
	},
	"arm64": {
		relativePath: "/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-aarch64-uefi-cloudinit-r0.qcow2",
		sha256:       "3059a6280977c2122982632e0317c5ddbd39069d46ca1e60480de283091f720f",
		sizeBytes:    239271936,
	},
}

// TestClusterVMApp verifies that a qcow2 VM app -- not a container -- boots
// on an EVE-K cluster node and reaches RUNNING. Every existing cluster test
// uses a container, which under Kubevirt runs in a shim VM but never boots
// a real guest disk; this is the first cluster-suite coverage of that path.
//
// No failover, DNID re-designation, or node isolation here -- just proving
// the VM app primitive works in a cluster at all.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- the same model TestThreeNodesCluster
//     uses. It grants EVE no outbound Internet reachability, hence
//     evetest.FetchAndServeImageFile rather than the public Alpine CDN
//     tests/apps/vnc_test.go points a device at directly.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirementsForVMApp (top of cluster_test.go): the same
//     three devices as clusterDeviceRequirements, minus its vCPU caps --
//     see that function's doc comment for why a real CDI import needs
//     them absent. edge-dev1 is the bootstrap node and hosts the app.
//
// Test params
// -----------
//   - TPM (bool), FILESYSTEM.
//
// Suite placement
// ---------------
//   - Not in TestNodeClusterSuite yet: this is the first VM app ever
//     deployed in the cluster suite, and the boot timing/failure modes
//     (image fetch, CDI import, VMI creation) need a real run to pin down
//     before it belongs alongside the suite's other tests.
func TestClusterVMApp(test *testing.T) {
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

	device := evetest.GetEdgeDevice(devName[0])
	image, ok := vmAppAlpineImages[device.GetArch()]
	t.Expect(ok).To(BeTrue(), "no pinned Alpine image for arch %q", device.GetArch())
	imagePath := evetest.FetchAndServeImageFile(
		"https://dl-cdn.alpinelinux.org"+image.relativePath,
		"vmapp-alpine.qcow2", image.sha256)
	evetest.Checkpoint("image-fetched")

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
			DisplayName: "cluster-vm-app",
			Activate:    true,
			Image: evetest.HTTPStorage{
				ImageFormat:       eveconfig.Format_QCOW2,
				ImageSHA256:       image.sha256,
				MaxDownloadBytes:  image.sizeBytes,
				ImageRelativePath: imagePath,
				ServerAddress:     evetest.GetImageServerIPv4().String(),
				ServerPort:        evetest.GetImageServerPort(),
			},
			// Left unset, the target PVC is sized to exactly the image's
			// own virtual size, leaving no room for CDI's scratch-space
			// qcow2->raw conversion. Comfortably above that virtual size.
			DiskBytes:          1 * evetest.GiB,
			VirtualizationMode: eveconfig.VmMode_HVM,
			CPUs:               1,
			MemoryBytes:        512 * evetest.MiB,
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
	evetest.Checkpoint("vm-app-submitted")

	log.Infof("Waiting for VM app %v to reach RUNNING", appUUID)
	cluster.WaitUntilAppIsRunning(appUUID, 30*time.Minute)
	evetest.Checkpoint("vm-app-running")

	hostDevice := cluster.FindDeviceHostingApp(appUUID, 2*time.Minute)
	t.Expect(hostDevice).NotTo(BeNil(), "no cluster device reports hosting the VM app")
	t.Expect(hostDevice.GetConfig().GetDeviceName()).To(Equal(devName[0]),
		"the VM app landed on a node other than its DesignatedNodeName")
	evetest.Checkpoint("vm-app-placement-verified")
}
