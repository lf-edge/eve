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

	// tokenRotationReportTimeout bounds a config change, or a node going
	// NotReady, reaching the cluster info the controller receives.
	tokenRotationReportTimeout = 5 * time.Minute

	// tokenRotationRotateTimeout bounds the bootstrap node's health worker
	// noticing a new token and k3s finishing the rotation.
	tokenRotationRotateTimeout = 5 * time.Minute
)

// TestClusterTokenRotation verifies that a cluster keeps working when the
// controller replaces it with a new one over the same nodes, that is a new
// ClusterID and a new join token, without the nodes leaving cluster mode.
//
// k3s encrypts its bootstrap data with the cluster token. kube-init writes
// the controller's token into the k3s config on every start, so unless the
// running cluster is rotated to the new token, the next k3s start on any node
// cannot decrypt its own datastore and Kubernetes stays down. kube-init has
// two paths for this, and the test forces each one:
//   - running rotation: the bootstrap node's health worker rotates the
//     running cluster. Asserted from the token k3s records on that node,
//     since a node that came back on the old token looks the same through
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
//     running nodes; the bootstrap node's k3s must switch to the new token
//     without a restart.
//  3. bootstrap-rebooted: the bootstrap node reboots and must rejoin.
//  4. member-rebooted: edge-dev2 reboots and must rejoin. It has only the
//     new token, so this passes only if the cluster itself was rotated.
//  5. identity-replaced-offline: the bootstrap node is powered off and a
//     third identity is applied to the two survivors.
//  6. member-recovered-before-rotation: edge-dev2 reboots while the
//     bootstrap node is still off. Its k3s must reject the new token, and
//     kube-init must fall back to the stored one and bring k3s up.
//  7. bootstrap-restored: the bootstrap node is powered on, all nodes must
//     be Ready, and the bootstrap node must rotate to the third token.
//  8. members-rejoined-after-rotation: edge-dev3, which never fell back,
//     and edge-dev2, which did, each reboot and must rejoin on the third
//     token.
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
	survivors := devName[1:]
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
	bootstrapRotated := func(desc string) {
		token := clusterConfig.Token
		t.Eventually(func() (bool, error) {
			return k3sRunsToken(bootstrap, token)
		}, tokenRotationRotateTimeout, 10*time.Second).Should(BeTrue(),
			desc+": k3s on the bootstrap node never rotated to the new token")
	}
	rebootAndRejoin := func(name string) {
		log.Infof("Rebooting %q; it must rejoin the cluster", name)
		evetest.GetEdgeDevice(name).RequestReboot(true, true)
		cluster.WaitForFreshNodesReady(tokenRotationRecoverTimeout)
	}

	// Phase 2.
	clusterConfig.ReplaceClusterIdentity()
	log.Infof("Replacing the cluster identity with %s on all running nodes",
		clusterConfig.ClusterID)
	cluster.ApplyConfig(clusterConfig, true, true)
	bootstrapRotated("after replacing the identity online")
	evetest.Checkpoint("identity-rotated-online")

	// Phase 3.
	rebootAndRejoin(bootstrapName)
	evetest.Checkpoint("bootstrap-rebooted")

	// Phase 4.
	rebootAndRejoin(memberName)
	reportsIdentity("after rebooting the members")
	evetest.Checkpoint("member-rebooted")

	// Phase 5. Wait for the outage to show, so later Ready reports are known
	// to come from after it. The watch opens before the power-off, and the
	// node going NotReady is a state change, so the report is always sent.
	survivorUpdates, stopSurvivorWatch := watchClusterInfo(survivors)
	defer stopSurvivorWatch()
	bootstrap.PowerOff()
	t.Eventually(survivorUpdates, tokenRotationReportTimeout).Should(Receive(
		matchers.SatisfyPredicate(
			"a survivor reports the powered-off bootstrap node NotReady",
			func(info *eveinfo.ZInfoKubeCluster) bool {
				return len(info.GetNodes()) > 0 && !nodeReady(info, bootstrapName)
			})))
	stopSurvivorWatch()
	clusterConfig.ReplaceClusterIdentity()
	log.Infof("Replacing the cluster identity with %s while %q is off",
		clusterConfig.ClusterID, bootstrapName)
	cluster.ApplyConfig(clusterConfig, true, true, bootstrapName)
	evetest.Checkpoint("identity-replaced-offline")

	// Phase 6. etcd regains quorum once edge-dev2 rejoins edge-dev3. Asked
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

	// Phase 7. waitUntilOnline=false per PowerOn's doc comment; the rejoin
	// below is the recovery signal.
	bootstrap.PowerOn(false)
	cluster.WaitForFreshNodesReady(tokenRotationRecoverTimeout)
	reportsIdentity("after powering the bootstrap node back on")
	bootstrapRotated("after powering the bootstrap node back on")
	evetest.Checkpoint("bootstrap-restored")

	// Phase 8.
	rebootAndRejoin(otherMemberName)
	rebootAndRejoin(memberName)
	evetest.Checkpoint("members-rejoined-after-rotation")
}
