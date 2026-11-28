// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestKubeComponentsUpgradeCluster forms a three-node EVE-k cluster on the
// most recent EVE release, runs an app with a data volume, and upgrades the
// nodes one at a time to the build under test. The first node to boot the
// new build runs the cluster-wide component upgrade pass while the other
// two still run the initial build. The nodes upgraded after it must find
// every component already at its target and leave it there. After every
// node's upgrade each kube component the pass covers (Multus, KubeVirt, CDI,
// Longhorn) must run the version the new build targets, with every Longhorn
// volume on the target engine image, and at the end the data written before
// the upgrade must still be there.
//
// kube-init runs the pass only when its build carries a higher kube version
// than the node has applied, and each node records its own. The test logs
// every node's applied kube version before and after its upgrade. See
// TestKubeComponentsUpgradeSingleNode for what that tells about a run.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort, as in TestThreeNodesUpgrade.
//
// Device configuration
// --------------------
//   - The devices and cluster config of TestThreeNodesUpgrade, installed
//     from scratch with the initial EVE version.
//   - The container app of TestThreeNodesUpgrade (port-fwd 2222->22),
//     preferring node 1, plus a blank, clear-text data volume with the same
//     designated node, written to as a raw disk. Clear-text keeps vault
//     readiness out of a test about the kube components.
//
// Test parameters
// ---------------
//   - INITIAL_EVE_VERSION: EVE-k version the cluster forms on (default
//     initialEVEVersionForKubeUpgrade).
//   - INITIAL_EVE_REPO: repository INITIAL_EVE_VERSION is pulled from
//     (default lfedge/eve).
//   - EVE_VERSION: version to upgrade to, via evetest.EVEVersionParameter()
//     (default: the HEAD of the checked-out EVE repo).
//   - TPM (bool) via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. nodes-are-ready: the cluster forms on the initial version (30-min
//     budget) and every node records its applied kube version.
//  2. app-deployed: the app runs and a marker is written to its data volume.
//  3. node-<name>-upgraded, once per node, bootstrap node last: UpgradeEVE
//     waits up to kubeUpgradeTimeout for the node's new partition to be
//     marked active, then a fresh cluster report must show all three nodes
//     Ready.
//  4. node-<name>-kube-components-converged, once per node: read through
//     the node just upgraded, every component runs its target version and
//     every Longhorn volume the target engine image, with no failed
//     component update and the node's applied kube version not lowered.
//  5. app-verified-post-upgrade: the app answers and the marker is intact.
//
// Suite placement
// ---------------
//   - TestUpgradeSuite.
func TestKubeComponentsUpgradeCluster(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
		evetest.TestParameterDefinition{
			Key:          initialEVEVersionParamKey,
			DefaultValue: initialEVEVersionForKubeUpgrade,
			Description: evetest.TestParameterDescription{
				Summary: "EVE-k version the cluster forms on before the upgrade",
				Default: initialEVEVersionForKubeUpgrade,
			},
		},
		evetest.TestParameterDefinition{
			// Hardcoded, not constants.DefaultEVERepo: list-tests can't
			// resolve cross-package constants.
			Key:          initialEVERepoParamKey,
			DefaultValue: "lfedge/eve",
			Description: evetest.TestParameterDescription{
				Summary: "Container image repository for the initial EVE version",
				Default: "lfedge/eve",
			},
		},
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()
	initialVersion := evetest.GetTestParameter[string](initialEVEVersionParamKey)
	if initialVersion == "" {
		evetestT.Fatalf("%s%s is required for TestKubeComponentsUpgradeCluster",
			constants.EnvPrefix, initialEVEVersionParamKey)
	}
	initialRepo := evetest.GetTestParameter[string](initialEVERepoParamKey)
	targetVersion := evetest.GetEVEVersionParameterValue()

	log := evetest.Logger()
	log.Infof("Forming the cluster on %s:%s and upgrading it to %q",
		initialRepo, initialVersion, targetVersion)

	var devName [3]string
	var requirements []evetest.Requirement
	for i := range devName {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		requirements = append(requirements, evetest.RequireEdgeDevice{
			Name:              devName[i],
			WithTPM:           withTPM,
			WithHypervisor:    evetest.HypervisorKubevirt,
			WithFilesystem:    filesystem,
			WithEVEVersion:    initialVersion,
			WithEVERepo:       initialRepo,
			DeviceReusePolicy: evetest.CreateFromScratchWithInstaller,
		})
	}
	requirements = append(requirements, evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort(devName[:]...),
	})
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	clusterConfig := newThreeNodeClusterConfig(devName)
	cluster := evetest.NewEdgeCluster("test-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(30 * time.Minute)
	var appliedBefore [3]int
	for i := range devName {
		appliedBefore[i] = expectAppliedKubeVersion(t,
			evetest.GetEdgeDevice(devName[i]), 10*time.Minute)
		log.Infof("Applied kube version on %s (%s): %d",
			devName[i], initialVersion, appliedBefore[i])
	}
	evetest.Checkpoint("nodes-are-ready")

	niUUID := clusterConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	dataVolUUID := clusterConfig.AddBlankVolume(evetest.ClusterBlankVolumeConfig{
		DisplayName:        "kube-upgrade-data",
		SizeBytes:          dataVolumeSize,
		ClearText:          true,
		DesignatedNodeName: devName[0],
	})
	appUUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
		ApplicationInstanceConfig: evetest.ApplicationInstanceConfig{
			DisplayName: "kube-upgrade-app",
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			CPUs:        1,
			MemoryBytes: 500 * evetest.MiB,
			Mounts: []evetest.MountConfig{
				{VolumeUUID: dataVolUUID, MountDir: dataMountDir},
			},
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
					PortFwdRules: []evetest.PortFwdRule{
						{
							Protocol:     evetest.NetworkProtocolTCP,
							EdgeNodePort: appSSHFwdPort,
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
	cluster.WaitUntilAppIsRunning(appUUID, 10*time.Minute)

	appAuth := evetest.UsernamePasswordAuth{Username: appSSHUser, Password: appSSHPassword}
	writeDataMarker(t, cluster, appUUID, appAuth)
	evetest.Checkpoint("app-deployed")

	// The bootstrap node goes last, so the first node to run the new build,
	// and with it the component upgrade pass, is one that joined through it.
	for i := len(devName) - 1; i >= 0; i-- {
		device := evetest.GetEdgeDevice(devName[i])
		log.Infof("Upgrading %s to %q", devName[i], targetVersion)
		device.UpgradeEVE(targetVersion, evetest.HypervisorKubevirt,
			evetest.BaseOSDatastoreHTTP, true, false, kubeUpgradeTimeout)
		cluster.WaitForFreshNodesReady(30 * time.Minute)
		evetest.Checkpoint(fmt.Sprintf("node-%s-upgraded", devName[i]))

		expectKubeComponentsConverged(t, device, appliedBefore[i],
			kubeConvergeTimeout)
		evetest.Checkpoint(fmt.Sprintf("node-%s-kube-components-converged",
			devName[i]))
	}

	// Budget above pillar's 600 s timer.boot.retry, which a VMIRS create
	// refused while kubevirt's webhook is still starting has to wait out.
	expectDataMarker(t, cluster, appUUID, appAuth, 15*time.Minute)
	evetest.Checkpoint("app-verified-post-upgrade")
}
