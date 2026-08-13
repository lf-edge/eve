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

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// tieBreakerApplyTimeout bounds how long the kube-init FSM may take to
	// finish the tie-breaker phase. The phase drains the node and asks
	// Longhorn to evict its replicas, so it is generous.
	tieBreakerApplyTimeout = 20 * time.Minute

	// tieBreakerSettleTimeout bounds the individual state checks made once
	// the phase reports completion. They are already true by then, so this
	// only absorbs the latency of reading them back.
	tieBreakerSettleTimeout = 2 * time.Minute

	tieBreakerPollInterval = 15 * time.Second

	// tieBreakerWarnTimeout bounds the checks that only warn. They are quick
	// because the values either hold straight after the phase or never do.
	tieBreakerWarnTimeout = 60 * time.Second

	// tieBreakerKubectlTimeout bounds a single kubectl invocation.
	tieBreakerKubectlTimeout = 2 * time.Minute

	// tieBreakerNodeLabel and its values mirror pkg/kube/kube-init/
	// tiebreaker: the tie-breaker is labelled "true", every other node
	// "false", and workloads select on "false" to stay off it.
	tieBreakerNodeLabel = "tie-breaker-node"
	tieBreakerLabelSet  = "true"
	tieBreakerLabelUnst = "false"

	// tieBreakerStatusLabel is stamped on every node once the phase
	// succeeds, so it is the gate the assertions below wait on.
	tieBreakerStatusLabel = "tie-breaker-config-applied=1"

	// Replica count the phase leaves the KubeVirt and Longhorn control
	// planes at: one per non-tie-breaker node.
	tieBreakerReplicas = "2"
)

// runKubectl goes through "eve exec kube" because kubectl exists only in the
// kube container, not in the host shell.
func runKubectl(device *evetest.EdgeDevice, args string) (string, error) {
	stdout, stderr, err := device.RunShellScript(
		"eve exec kube kubectl "+args, tieBreakerKubectlTimeout, 0)
	if err != nil {
		return "", fmt.Errorf("kubectl %s: %w (stderr: %s)",
			args, err, strings.TrimSpace(stderr))
	}
	return strings.TrimSpace(stdout), nil
}

func expectKubectl(t *WithT, device *evetest.EdgeDevice,
	what, args, want string, timeout time.Duration) {
	t.Eventually(func() (string, error) {
		return runKubectl(device, args)
	}, timeout, tieBreakerPollInterval).Should(Equal(want), what)
}

// warnKubectl polls for a state that pkg/kube applies once at cluster
// creation and never reconciles. It warns instead of failing, because the
// owning controller sets these values back. The warning records what the
// state was, which shows whether the value held at first and drifted, or
// never applied.
func warnKubectl(device *evetest.EdgeDevice, what, args, want string) {
	log := evetest.Logger()
	deadline := time.Now().Add(tieBreakerWarnTimeout)
	var last string
	for {
		out, err := runKubectl(device, args)
		switch {
		case err != nil:
			last = err.Error()
		case out == want:
			return
		default:
			last = out
		}
		if time.Now().After(deadline) {
			log.Warnf("tie-breaker: %s: got %q, want %q", what, last, want)
			return
		}
		time.Sleep(tieBreakerPollInterval)
	}
}

// expectKubectlNoField polls until no whitespace-separated field of the query
// output equals unwanted. An empty result passes, so callers must make sure
// the query has something to return.
func expectKubectlNoField(t *WithT, device *evetest.EdgeDevice,
	what, args, unwanted string, timeout time.Duration) {
	t.Eventually(func() error {
		out, err := runKubectl(device, args)
		if err != nil {
			return err
		}
		for _, f := range strings.Fields(out) {
			if f == unwanted {
				return fmt.Errorf("%s: found %q in %q", what, unwanted, out)
			}
		}
		return nil
	}, timeout, tieBreakerPollInterval).Should(Succeed())
}

// expectKubectlFields takes a wantCount of -1 as "any non-zero number of
// fields", for sets whose size is an implementation detail.
func expectKubectlFields(t *WithT, device *evetest.EdgeDevice,
	what, args string, wantCount int, wantEach string, timeout time.Duration) {
	t.Eventually(func() error {
		out, err := runKubectl(device, args)
		if err != nil {
			return err
		}
		fields := strings.Fields(out)
		if len(fields) == 0 {
			return fmt.Errorf("%s: query returned nothing", what)
		}
		if wantCount >= 0 && len(fields) != wantCount {
			return fmt.Errorf("%s: got %d fields (%q), want %d",
				what, len(fields), out, wantCount)
		}
		for _, f := range fields {
			if f != wantEach {
				return fmt.Errorf("%s: got %q in %q, want every field to be %q",
					what, f, out, wantEach)
			}
		}
		return nil
	}, timeout, tieBreakerPollInterval).Should(Succeed())
}

// TestTieBreakerCluster verifies the tie-breaker node of a three-node EVE-K
// cluster: the node that holds a quorum vote only, runs no workloads and
// carries no Longhorn replicas.
//
// The designation travels from the EVE API through zedagent's
// EdgeNodeClusterConfig into pkg/kube, which labels, cordons and drains the
// node and configures KubeVirt, CDI and Longhorn to keep off it. This test
// covers that chain, ending with an app deployment that proves no VMI or
// Longhorn replica lands on the tie-breaker.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- the same model TestThreeNodesCluster
//     uses: eth0 for mgmt and apps, eth1 for the cluster interconnect.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirements (top of cluster_test.go), three devices.
//     edge-dev3 is the tie-breaker; edge-dev1 is the bootstrap node.
//
// Test params
// -----------
//   - TPM (bool), FILESYSTEM.
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite, after TestThreeNodesCluster, so a plain
//     three-node failure shows in the simpler test first.
func TestTieBreakerCluster(test *testing.T) {
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

	// Build the cluster configuration. The last node is the tie-breaker.
	const tieBreakerIdx = 2
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

	log := evetest.Logger()

	// Every node must learn which node is the tie-breaker, because each one
	// decides locally whether the role applies to itself.
	var tieBreakerNodeID string
	for i := 0; i < 3; i++ {
		device := evetest.GetEdgeDevice(devName[i])
		var clusterCfg types.EdgeNodeClusterConfig
		t.Eventually(func() error {
			cfgs, err := evetest.ReadAllPublications[types.EdgeNodeClusterConfig](
				device, "zedagent", false)
			if err != nil {
				return err
			}
			if len(cfgs) != 1 {
				return fmt.Errorf("%s publishes %d EdgeNodeClusterConfig, want 1",
					devName[i], len(cfgs))
			}
			clusterCfg = cfgs[0]
			return nil
		}, 5*time.Minute, tieBreakerPollInterval).Should(Succeed())

		nodeID := clusterCfg.TieBreakerNodeID.UUID.String()
		t.Expect(clusterCfg.TieBreakerNodeID.UUID).NotTo(Equal(evetest.NilUUID),
			"%s was given no tie-breaker designation", devName[i])
		if tieBreakerNodeID == "" {
			tieBreakerNodeID = nodeID
		}
		t.Expect(nodeID).To(Equal(tieBreakerNodeID),
			"%s disagrees about which node is the tie-breaker", devName[i])
		log.Infof("%s reports tie-breaker node UUID=%s", devName[i], nodeID)
	}
	evetest.Checkpoint("tie-breaker-designation-agreed")

	// Query Kubernetes through a node that stays schedulable, so the
	// tie-breaker's own cordon and drain cannot interfere.
	device := evetest.GetEdgeDevice(devName[0])

	// The phase stamps the status label on every node only after all of its
	// steps and the drain succeed, so this is the gate for everything below.
	expectKubectlFields(t, device, "tie-breaker phase completed on every node",
		"get nodes -l "+tieBreakerStatusLabel+
			` -o jsonpath="{.items[*].metadata.labels['tie-breaker-config-applied']}"`,
		3, "1", tieBreakerApplyTimeout)
	evetest.Checkpoint("tie-breaker-phase-applied")

	// node-uuid is the key the phase itself maps the configured UUID through,
	// so the test and the code agree on which node is which.
	var tieName string
	t.Eventually(func() (string, error) {
		out, err := runKubectl(device, "get nodes -l node-uuid="+tieBreakerNodeID+
			` -o jsonpath="{.items[*].metadata.name}"`)
		if err != nil {
			return "", err
		}
		tieName = out
		return out, nil
	}, tieBreakerSettleTimeout, tieBreakerPollInterval).ShouldNot(BeEmpty(),
		"no Kubernetes node carries node-uuid="+tieBreakerNodeID)
	t.Expect(strings.Fields(tieName)).To(HaveLen(1),
		"expected exactly one node with node-uuid=%s, got %q",
		tieBreakerNodeID, tieName)
	log.Infof("tie-breaker node UUID=%s is Kubernetes node %q",
		tieBreakerNodeID, tieName)

	// Node labels and cordon: the tie-breaker is labelled true and
	// cordoned, the other two are labelled false and left schedulable.
	// Matching the whole node list against the one designated name proves
	// both that the label is on the right node and that no other node
	// carries it.
	expectKubectl(t, device, "exactly one node is the tie-breaker",
		"get nodes -l "+tieBreakerNodeLabel+"="+tieBreakerLabelSet+
			` -o jsonpath="{.items[*].metadata.name}"`,
		tieName, tieBreakerSettleTimeout)
	expectKubectl(t, device, "tie-breaker node is cordoned",
		fmt.Sprintf(`get node %s -o jsonpath="{.spec.unschedulable}"`, tieName),
		"true", tieBreakerSettleTimeout)
	expectKubectlFields(t, device, "the other two nodes are labelled as workers",
		"get nodes -l "+tieBreakerNodeLabel+"="+tieBreakerLabelUnst+
			` -o jsonpath="{.items[*].metadata.labels['`+tieBreakerNodeLabel+`']}"`,
		2, tieBreakerLabelUnst, tieBreakerSettleTimeout)
	// Matched on the absence of "true" rather than an exact value, because
	// spec.unschedulable is omitempty: an uncordoned node may report false
	// or omit the field altogether.
	expectKubectlNoField(t, device, "the other two nodes stay schedulable",
		"get nodes -l "+tieBreakerNodeLabel+"="+tieBreakerLabelUnst+
			` -o jsonpath="{.items[*].spec.unschedulable}"`,
		"true", tieBreakerSettleTimeout)
	evetest.Checkpoint("tie-breaker-node-state-verified")

	// KubeVirt: control plane scaled to one replica per worker.
	expectKubectl(t, device, "virt-operator is scaled to the worker count",
		`get deploy virt-operator -n kubevirt -o jsonpath="{.spec.replicas}"`,
		tieBreakerReplicas, tieBreakerSettleTimeout)
	warnKubectl(device, "KubeVirt CR infra replicas",
		`get kubevirt kubevirt -n kubevirt -o jsonpath="{.spec.infra.replicas}"`,
		tieBreakerReplicas)
	warnKubectl(device, "virt-handler node selector",
		`get ds virt-handler -n kubevirt`+
			` -o jsonpath="{.spec.template.spec.nodeSelector['`+
			tieBreakerNodeLabel+`']}"`,
		tieBreakerLabelUnst)

	// CDI: every Deployment in the namespace kept off the tie-breaker.
	expectKubectlFields(t, device, "cdi Deployments avoid the tie-breaker",
		`get deploy -n cdi -o jsonpath="{.items[*].spec.template.spec.nodeSelector['`+
			tieBreakerNodeLabel+`']}"`,
		-1, tieBreakerLabelUnst, tieBreakerSettleTimeout)
	evetest.Checkpoint("tie-breaker-workload-exclusion-verified")

	// longhorn-manager owns the node spec that longhornNodeSetSched writes
	// and sets it back. Replica placement below is the invariant that holds.
	warnKubectl(device, "longhorn node scheduling on the tie-breaker",
		fmt.Sprintf(`get nodes.longhorn.io %s -n longhorn-system`+
			` -o jsonpath="{.spec.allowScheduling}"`, tieName), "false")
	warnKubectl(device, "longhorn eviction of the tie-breaker",
		fmt.Sprintf(`get nodes.longhorn.io %s -n longhorn-system`+
			` -o jsonpath="{.spec.evictionRequested}"`, tieName), "true")
	warnKubectl(device, "longhorn disk scheduling on the tie-breaker",
		fmt.Sprintf(`get nodes.longhorn.io %s -n longhorn-system`+
			` -o jsonpath="{.spec.disks.*.allowScheduling}"`, tieName), "false")

	// Longhorn CSI sidecars scaled to the worker count.
	for _, deploy := range []string{
		"csi-attacher", "csi-provisioner", "csi-resizer", "csi-snapshotter",
	} {
		expectKubectl(t, device, "longhorn "+deploy+" is scaled to the worker count",
			fmt.Sprintf(`get deploy %s -n longhorn-system`+
				` -o jsonpath="{.spec.replicas}"`, deploy),
			tieBreakerReplicas, tieBreakerSettleTimeout)
	}

	// Only longhorn-manager is asserted. longhorn-csi-plugin stands for the
	// DaemonSets that longhorn-manager creates after the phase runs, so the
	// phase never patches them.
	expectKubectl(t, device, "the longhorn-manager DaemonSet avoids the tie-breaker",
		`get ds longhorn-manager -n longhorn-system`+
			` -o jsonpath="{.spec.template.spec.nodeSelector['`+
			tieBreakerNodeLabel+`']}"`,
		tieBreakerLabelUnst, tieBreakerSettleTimeout)
	warnKubectl(device, "longhorn-csi-plugin node selector",
		`get ds longhorn-csi-plugin -n longhorn-system`+
			` -o jsonpath="{.spec.template.spec.nodeSelector['`+
			tieBreakerNodeLabel+`']}"`,
		tieBreakerLabelUnst)
	evetest.Checkpoint("tie-breaker-longhorn-verified")

	// The drain leaves only DaemonSet-owned pods behind, which the phase
	// deliberately keeps (as `kubectl drain --ignore-daemonsets` does).
	expectKubectlFields(t, device, "only DaemonSet pods remain on the tie-breaker",
		fmt.Sprintf("get pods -A --field-selector spec.nodeName=%s"+
			` -o jsonpath="{.items[*].metadata.ownerReferences[*].kind}"`, tieName),
		-1, "DaemonSet", tieBreakerSettleTimeout)
	evetest.Checkpoint("tie-breaker-drained")

	// Deploy an app so the placement assertions below have something to
	// observe. Without a workload they would pass on an empty cluster.
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
			DisplayName: "tie-breaker-app",
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
	cluster.WaitUntilAppIsRunning(appUUID, 20*time.Minute)
	evetest.Checkpoint("app-is-running")

	// The tie-breaker exists to hold a quorum vote only, so neither the
	// app's VMI nor any Longhorn replica may land on it.
	expectKubectlNoField(t, device, "no VMI runs on the tie-breaker",
		`get vmi -A -o jsonpath="{.items[*].status.nodeName}"`,
		tieName, tieBreakerSettleTimeout)
	expectKubectlNoField(t, device, "no Longhorn replica sits on the tie-breaker",
		`get replicas.longhorn.io -n longhorn-system`+
			` -o jsonpath="{.items[*].spec.nodeID}"`,
		tieName, tieBreakerSettleTimeout)

	// A tie-breaker lowers the replica count of the storage class EVE picks
	// for new volumes, because only the two workers can hold replicas.
	expectKubectlFields(t, device, "app volumes use the two-replica storage class",
		`get pvc -n eve-kube-app -o jsonpath="{.items[*].spec.storageClassName}"`,
		-1, "lh-sc-rep2", tieBreakerSettleTimeout)
	evetest.Checkpoint("tie-breaker-placement-verified")
}
