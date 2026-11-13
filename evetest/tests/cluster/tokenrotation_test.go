// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
)

const (
	// tokenRotationFormTimeout bounds three nodes forming the cluster.
	tokenRotationFormTimeout = 30 * time.Minute

	// tokenRotationRecoverTimeout bounds a rebooted or powered-on node
	// rejoining: a full EVE boot plus the k3s start that follows.
	tokenRotationRecoverTimeout = 20 * time.Minute

	// tokenRotationReportTimeout bounds a config change reaching the cluster
	// info the controller receives, or Kubernetes marking a powered-off node
	// NotReady.
	tokenRotationReportTimeout = 5 * time.Minute

	// tokenRotationRollTimeout bounds the bootstrap node rotating the token
	// and then each of the three servers restarting k3s in turn.
	tokenRotationRollTimeout = 30 * time.Minute
)

// TestClusterTokenRotation verifies that a cluster keeps working when the
// controller replaces it with a new one over the same nodes, that is a new
// ClusterID and a new join token, without the nodes leaving cluster mode.
//
// k3s encrypts its bootstrap data with the cluster token. kube-init writes
// the controller's token into the k3s config on every start, so unless the
// running cluster is rotated to the new token, the next k3s start on any node
// cannot decrypt its own datastore and Kubernetes stays down.
//
// Rotation follows https://docs.k3s.io/cli/token: `k3s token rotate` on one
// server, then every server restarted with the new token. kube-init does
// both, restarting one server at a time.
//
// kube-init has two paths for this, and the test forces each one:
//   - running rotation: the bootstrap node's health worker rotates the
//     running cluster and the servers then restart in turn. Asserted from
//     the token k3s records on each node, which a member rewrites only when
//     its k3s restarts, since a node on the old token looks the same through
//     the EVE API.
//   - startup recovery: a node whose k3s starts before the rotation falls
//     back to the token its datastore was encrypted with. Forced by
//     restarting a member while the bootstrap node, the only node that
//     rotates, is powered off: that member's Kubernetes API can then only
//     come back through the fallback.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- same as TestThreeNodesCluster, so the
//     suite can reuse the three VMs.
//
// Device configuration
// --------------------
//   - setupThreeNodes / newThreeNodeClusterConfig (cluster_test.go): three
//     Kubevirt devices, REPLICATED_STORAGE, node 1 the bootstrap node.
//   - The replacement is EdgeClusterConfig.ReplaceClusterIdentity: same
//     nodes, cluster IPs and roles, new ClusterID and token.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. cluster-formed: all three nodes Ready under the first identity.
//  2. identity-rotated-online: a new identity is applied to all three
//     running nodes; every node's k3s must end up on the new token, and all
//     nodes Ready.
//  3. bootstrap-rebooted: the bootstrap node reboots and must rejoin.
//  4. identity-replaced-offline: the bootstrap node is powered off and a
//     third identity is applied to the two survivors.
//  5. member-recovered-before-rotation: edge-dev2 reboots while the
//     bootstrap node is still off. Its k3s must reject the new token, and
//     kube-init must fall back to the stored one and bring k3s up.
//  6. bootstrap-restored: the bootstrap node is powered on, all nodes must
//     be Ready, and every node's k3s must end up on the third token.
//
// Suite placement
// ---------------
//   - TestNodeClusterResilienceSuite, with the other three-node tests that
//     reboot or power off nodes.
func TestClusterTokenRotation(test *testing.T) {
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
	log := evetest.Logger()

	bootstrapName, memberName, otherMemberName := devName[0], devName[1], devName[2]
	bootstrap := evetest.GetEdgeDevice(bootstrapName)
	member := evetest.GetEdgeDevice(memberName)
	otherMember := evetest.GetEdgeDevice(otherMemberName)
	clusterConfig := newThreeNodeClusterConfig(devName)
	cluster := evetest.NewEdgeCluster("test-cluster")

	// Phase 1.
	cluster.ApplyConfig(clusterConfig, true, true)
	cluster.WaitUntilNodesAreReady(tokenRotationFormTimeout)
	evetest.Checkpoint("cluster-formed")

	// Polled rather than watched: EVE re-sends cluster info only when the
	// cluster's state changes, so the report carrying the new ID may already
	// have arrived. Called only after a reboot, which changes that state.
	reportsIdentity := func(desc string) {
		want := clusterConfig.ClusterID.String()
		t.Eventually(func() clusterReports {
			return latestClusterReports(devName[:])
		}, tokenRotationReportTimeout, 10*time.Second).Should(
			matchers.SatisfyPredicate(desc+": a node reports cluster "+want,
				anyReport(func(info *eveinfo.ZInfoKubeCluster) bool {
					return info.GetClusterId() == want
				})))
	}
	// rolledOut waits for every node's k3s to run on the current token, for
	// the last restart to finish, then for every node to be Ready again. k3s
	// rewrites the token file as it starts, and a node's Ready status can
	// outlast a short restart, so only the released lease shows the last
	// restart is done.
	rolledOut := func(desc string) {
		token := clusterConfig.Token
		for _, name := range devName {
			dev := evetest.GetEdgeDevice(name)
			t.Eventually(func() (bool, error) {
				return k3sRunsToken(dev, token)
			}, tokenRotationRollTimeout, 15*time.Second).Should(BeTrue(),
				"%s: k3s on %q never restarted on the new token", desc, name)
		}
		t.Eventually(func() (bool, error) {
			return k3sRestartLeaseHeld(bootstrap)
		}, tokenRotationRecoverTimeout, 15*time.Second).Should(BeFalse(),
			"%s: a k3s restart never released its lease", desc)
		for _, name := range devName {
			t.Eventually(func() (bool, error) {
				return k3sNodeReady(bootstrap, name)
			}, tokenRotationRecoverTimeout, 15*time.Second).Should(BeTrue(),
				"%s: %q not Ready after the restarts", desc, name)
		}
	}

	// Phase 2.
	clusterConfig.ReplaceClusterIdentity()
	log.Infof("Replacing the cluster identity with %s on all running nodes",
		clusterConfig.ClusterID)
	cluster.ApplyConfig(clusterConfig, true, true)
	rolledOut("after replacing the identity online")
	evetest.Checkpoint("identity-rotated-online")

	// Phase 3.
	log.Infof("Rebooting %q; it must rejoin the cluster", bootstrapName)
	bootstrap.RequestReboot(true, true)
	cluster.WaitForFreshNodesReady(tokenRotationRecoverTimeout)
	reportsIdentity("after rebooting the bootstrap node")
	evetest.Checkpoint("bootstrap-rebooted")

	// Phase 4. Wait until Kubernetes marks the bootstrap node NotReady, so
	// the fresh Ready report awaited in phase 6 postdates the outage. Asked
	// of a survivor's apiserver: only the stats leader sends cluster info,
	// and the powered-off node may hold that lease for up to 300s.
	bootstrap.PowerOff()
	t.Eventually(func() (bool, error) {
		return k3sNodeReady(otherMember, bootstrapName)
	}, tokenRotationReportTimeout, 10*time.Second).Should(BeFalse(),
		"a survivor never saw %q NotReady", bootstrapName)
	clusterConfig.ReplaceClusterIdentity()
	log.Infof("Replacing the cluster identity with %s while %q is off",
		clusterConfig.ClusterID, bootstrapName)
	cluster.ApplyConfig(clusterConfig, true, true, bootstrapName)
	evetest.Checkpoint("identity-replaced-offline")

	// Phase 5. etcd regains quorum once edge-dev2 rejoins edge-dev3. Asked
	// of edge-dev2's own apiserver, which answers only once its k3s is up:
	// the cluster report cannot show this, as no NotReady is recorded while
	// edge-dev3 alone has no quorum, and the last report shows it Ready.
	log.Infof("Rebooting %q while %q is off; k3s must reject the new token "+
		"and kube-init fall back to the stored one", memberName, bootstrapName)
	member.RequestReboot(true, true)
	t.Eventually(func() (bool, error) {
		return k3sNodeReady(member, memberName)
	}, tokenRotationRecoverTimeout, 15*time.Second).Should(BeTrue(),
		"k3s on %q never came up on the stored token", memberName)
	evetest.Checkpoint("member-recovered-before-rotation")

	// Phase 6. waitUntilOnline=false per PowerOn's doc comment; the rejoin
	// below is the recovery signal.
	bootstrap.PowerOn(false)
	cluster.WaitForFreshNodesReady(tokenRotationRecoverTimeout)
	reportsIdentity("after powering the bootstrap node back on")
	rolledOut("after powering the bootstrap node back on")
	evetest.Checkpoint("bootstrap-restored")
}
