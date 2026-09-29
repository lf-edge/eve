// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	initialEVEVersionParamKey = "INITIAL_EVE_VERSION"
	initialEVERepoParamKey    = "INITIAL_EVE_REPO"
)

// TestThreeNodesUpgrade forms a three-node EVE-k cluster on a released EVE
// version, deploys a container application, and upgrades the nodes one at a
// time to the EVE version under test. After each node's upgrade every node
// must be Ready again before the next one starts, so the cluster runs mixed
// versions for most of the test. At the end the application must still be
// reachable.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort, as in TestThreeNodesCluster.
//
// Device configuration
// --------------------
//   - The devices and cluster config of TestThreeNodesCluster, installed
//     from scratch with the initial EVE version.
//   - The container app of TestThreeNodesCluster (port-fwd 2222->22),
//     preferring node 1.
//
// Test parameters
// ---------------
//   - INITIAL_EVE_VERSION: EVE-k version the cluster forms on (default
//     17.0.0-lts).
//   - INITIAL_EVE_REPO: repository INITIAL_EVE_VERSION is pulled from
//     (default lfedge/eve).
//   - EVE_VERSION: version to upgrade to, via evetest.EVEVersionParameter()
//     (default: the HEAD of the checked-out EVE repo, so a run on master
//     upgrades to master). With EVETEST_EVE_LIVE_IMAGE set the target is the
//     local build instead, as in TestEVEUpgrade.
//   - TPM (bool) via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. initial-config-applied -> nodes-are-ready: the cluster forms on the
//     initial version (30-min budget).
//  2. app-is-deployed: the container app runs and answers `hostname` over
//     its port forward.
//  3. node-<name>-upgraded, once per node, bootstrap node last: UpgradeEVE
//     waits for the node to run the target version, then a fresh cluster
//     report must show all three nodes Ready with healthy storage.
//  4. app-verified-post-upgrade: the app answers `hostname` again.
//
// Suite placement
// ---------------
//   - Standalone: its devices run a different EVE version than
//     TestNodeClusterSuite's and cannot be reused.
func TestThreeNodesUpgrade(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
		evetest.TestParameterDefinition{
			Key:          initialEVEVersionParamKey,
			DefaultValue: "17.0.0-lts",
			Description: evetest.TestParameterDescription{
				Summary: "EVE-k version the cluster forms on before the upgrade",
				Default: "17.0.0-lts",
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
		evetestT.Fatalf("%s%s is required for TestThreeNodesUpgrade",
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
		req := clusterDeviceRequirements(devName[i], withTPM, filesystem, false)
		req.WithEVEVersion = initialVersion
		req.WithEVERepo = initialRepo
		req.DeviceReusePolicy = evetest.CreateFromScratchWithInstaller
		requirements = append(requirements, req)
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
	appUUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
		ApplicationInstanceConfig: evetest.ApplicationInstanceConfig{
			DisplayName: "upgrade-app",
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
	cluster.WaitUntilAppIsRunning(appUUID, 10*time.Minute)

	appAuth := evetest.UsernamePasswordAuth{Username: "root", Password: "testpassword"}
	expectAppAnswers := func(timeout time.Duration) {
		t.Eventually(func(t Gomega) {
			out, _, err := cluster.RunShellScriptInsideApp(appUUID, appAuth,
				"hostname", 20*time.Second, 0)
			t.Expect(err).ToNot(HaveOccurred())
			t.Expect(out).To(ContainSubstring(appUUID.String()))
		}, timeout, 5*time.Second).Should(Succeed())
	}
	expectAppAnswers(3 * time.Minute)
	evetest.Checkpoint("app-is-deployed")

	// The bootstrap node goes last, so the nodes that joined through it
	// restart on the new version while it still runs the old one.
	for i := len(devName) - 1; i >= 0; i-- {
		device := evetest.GetEdgeDevice(devName[i])
		log.Infof("Upgrading %s to %q", devName[i], targetVersion)
		device.UpgradeEVE(targetVersion, evetest.HypervisorKubevirt,
			evetest.BaseOSDatastoreHTTP, true, false)
		waitForFreshNodesReady(t, devName, 30*time.Minute)
		evetest.Checkpoint(fmt.Sprintf("node-%s-upgraded", devName[i]))
	}

	// Budget above pillar's 600 s timer.boot.retry, which a VMIRS create
	// refused while kubevirt's webhook is still starting has to wait out.
	expectAppAnswers(15 * time.Minute)
	evetest.Checkpoint("app-verified-post-upgrade")
}

// waitForFreshNodesReady waits until some node publishes cluster info in
// which every node in devName is Ready and storage is healthy. Unlike
// EdgeCluster.WaitUntilNodesAreReady it ignores the info already cached,
// which after a node reboot can predate the reboot and still show it Ready.
func waitForFreshNodesReady(t *WithT, devName [3]string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ready := make(chan string, len(devName))
	for _, name := range devName {
		device := evetest.GetEdgeDevice(name)
		updates, stop := device.WatchClusterInfo()
		defer stop()
		go func() {
			for {
				select {
				case info, ok := <-updates:
					if !ok {
						return
					}
					if allClusterNodesReady(info, devName[:]) {
						ready <- name
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	select {
	case name := <-ready:
		evetest.Logger().Infof("All cluster nodes reported Ready by %s", name)
	case <-ctx.Done():
		t.Expect(ctx.Err()).ToNot(HaveOccurred(),
			"no node reported all of %v Ready with healthy storage", devName)
	}
}

// allClusterNodesReady reports whether info shows healthy storage and every
// node in names Ready.
func allClusterNodesReady(info *eveinfo.ZInfoKubeCluster, names []string) bool {
	if info.GetStorage().GetHealth() != eveinfo.ServiceStatus_SERVICE_STATUS_HEALTHY {
		return false
	}
	const readyCond = eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY
	for _, name := range names {
		nodeReady := false
		for _, node := range info.GetNodes() {
			if node.GetName() != name {
				continue
			}
			for _, cond := range node.GetConditions() {
				if cond.GetType() == readyCond {
					nodeReady = cond.GetSet()
				}
			}
		}
		if !nodeReady {
			return false
		}
	}
	return true
}
