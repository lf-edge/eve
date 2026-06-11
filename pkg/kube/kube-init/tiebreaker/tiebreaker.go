// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package tiebreaker configures the third "tie-breaker" node in a
// three-node EVE-K cluster. The tie-breaker hosts no workloads —
// its only purpose is to give etcd a quorum third vote so single-
// node loss doesn't strand the cluster.
//
// The configuration touches several layers:
//   - Kubernetes nodes: label the tie-breaker, cordon it, set the
//     opposite label on the two worker nodes.
//   - KubeVirt: scale virt-operator + KubeVirt CR to 2 replicas;
//     patch every kubevirt-namespace DaemonSet with a nodeSelector
//     keeping pods off the tie-breaker.
//   - CDI: same nodeSelector patch on every cdi-namespace
//     Deployment.
//   - Longhorn: disable scheduling on the tie-breaker's Longhorn
//     node + its disks; scale CSI sidecars to 2 replicas; patch
//     longhorn-system DaemonSets with the nodeSelector.
//   - Drain the tie-breaker so any pre-existing workloads move
//     before the labels take effect.
//
// ConfigApply is the entry the FSM calls; everything else is the
// implementation detail of a single phase.
package tiebreaker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/encconfig"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

const (
	tieBreakerNodeLabel  = "tie-breaker-node"
	tieBreakerLabelSet   = "true"
	tieBreakerLabelUnset = "false"

	// tieBreakerStatusLabel is applied to every node once the
	// tie-breaker configuration phase succeeds. Used by StatusGet to
	// detect "already done".
	tieBreakerStatusLabel = "tie-breaker-config-applied=1"

	// clusterNodeCount is the size of an EVE-K HA cluster. Three
	// nodes: two workers and one tie-breaker.
	clusterNodeCount = 3
)

// ConfigIsSet reports whether the EdgeNodeClusterConfig
// subscription has delivered a payload with a non-empty
// TieBreakerNodeID. No delivery yet OR a zero UUID both collapse
// to false — the caller is expected to skip tie-breaker work in
// that case.
func ConfigIsSet() bool {
	return encconfig.TieBreakerUUID() != ""
}

// ConfigGetNodeUUID returns the tie-breaker's device UUID from
// the cached EdgeNodeClusterConfig.
func ConfigGetNodeUUID() (string, error) {
	id := encconfig.TieBreakerUUID()
	if id == "" {
		return "", fmt.Errorf(
			"TieBreakerNodeID is not set in EdgeNodeClusterConfig subscription")
	}
	return id, nil
}

// StatusIsSelf reports whether the tie-breaker UUID is the local
// node's UUID. Caller passes both so the function doesn't need to
// thread a context for hostname lookup.
func StatusIsSelf(tieUUID, selfUUID string) bool {
	return tieUUID == selfUUID
}

// StatusSet stamps every node with the tie-breaker-config-applied=1
// label. ConfigApply calls this only after the rest of the phase
// succeeds, so the label is a true "we got to the end" marker.
func StatusSet(ctx context.Context) error {
	log.Printf("tiebreaker: setting status label on all nodes")
	_, err := kubectl("label", "nodes", "--all",
		tieBreakerStatusLabel, "--overwrite")
	return err
}

// StatusGet reports whether the status label has been applied to
// every node in the cluster (exactly clusterNodeCount nodes).
func StatusGet(ctx context.Context) bool {
	out, err := kubectl("get", "nodes",
		"-l", tieBreakerStatusLabel,
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return false
	}
	return len(strings.Fields(strings.TrimSpace(out))) == clusterNodeCount
}

// NodeCountIsCluster reports whether the cluster currently has the
// expected three nodes. Used to gate ConfigApply: until all three
// have joined we can't pick a tie-breaker.
func NodeCountIsCluster(ctx context.Context) bool {
	out, err := kubectl("get", "nodes",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return false
	}
	return len(strings.Fields(strings.TrimSpace(out))) == clusterNodeCount
}

// nodeNameFromUUID maps a device UUID onto its Kubernetes node name
// via the node-uuid=<uuid> label that k3s readiness applies.
func nodeNameFromUUID(ctx context.Context, uuid string) (string, error) {
	out, err := kubectl("get", "nodes",
		"-l", "node-uuid="+uuid,
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return "", fmt.Errorf("get node name for uuid %s: %w", uuid, err)
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("no node found with uuid %s", uuid)
	}
	return name, nil
}

// nodesConfigApply labels the tie-breaker with tie-breaker-node=true
// and cordons it; every other node gets tie-breaker-node=false and
// an uncordon (defensive — they may already be ready).
func nodesConfigApply(ctx context.Context, tieUUID string) error {
	tieName, err := nodeNameFromUUID(ctx, tieUUID)
	if err != nil {
		return err
	}
	out, err := kubectl("get", "nodes",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	for _, nodeName := range strings.Fields(strings.TrimSpace(out)) {
		if nodeName == tieName {
			log.Printf("tiebreaker: labeling %s as tie-breaker", nodeName)
			if _, err := kubectl("label", "node", nodeName,
				tieBreakerNodeLabel+"="+tieBreakerLabelSet,
				"--overwrite"); err != nil {
				return fmt.Errorf("label tie-breaker node %s: %w", nodeName, err)
			}
			if _, err := kubectl("cordon", nodeName); err != nil {
				return fmt.Errorf("cordon tie-breaker node %s: %w", nodeName, err)
			}
			continue
		}
		log.Printf("tiebreaker: labeling %s as worker", nodeName)
		if _, err := kubectl("label", "node", nodeName,
			tieBreakerNodeLabel+"="+tieBreakerLabelUnset,
			"--overwrite"); err != nil {
			return fmt.Errorf("label node %s: %w", nodeName, err)
		}
		if _, err := kubectl("uncordon", nodeName); err != nil {
			return fmt.Errorf("uncordon node %s: %w", nodeName, err)
		}
	}
	return nil
}

// kubevirtConfig sets the KubeVirt control-plane replica count
// (virt-operator Deployment + KubeVirt CR's .spec.infra.replicas).
func kubevirtConfig(ctx context.Context, replicas int) error {
	r := fmt.Sprintf("%d", replicas)
	log.Printf("tiebreaker: scaling kubevirt to %s replicas", r)
	if _, err := kubectl("scale", "deployment", "virt-operator",
		"-n", "kubevirt", "--replicas="+r); err != nil {
		return fmt.Errorf("scale virt-operator: %w", err)
	}
	patch := fmt.Sprintf(`{"spec":{"infra":{"replicas":%d}}}`, replicas)
	if _, err := kubectl("patch", "kubevirt", "kubevirt",
		"-n", "kubevirt", "--type=merge", "-p="+patch); err != nil {
		return fmt.Errorf("patch kubevirt CR replicas: %w", err)
	}
	return nil
}

// kubevirtTieBreakerConfigApply patches every DaemonSet in the
// kubevirt namespace with a nodeSelector that keeps pods off the
// tie-breaker (tie-breaker-node=false).
func kubevirtTieBreakerConfigApply(ctx context.Context) error {
	log.Printf("tiebreaker: patching kubevirt daemonsets with nodeSelector")
	out, err := kubectl("get", "daemonsets", "-n", "kubevirt",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return fmt.Errorf("list kubevirt daemonsets: %w", err)
	}
	patch := nodeSelectorPatch(tieBreakerNodeLabel, tieBreakerLabelUnset)
	for _, ds := range strings.Fields(strings.TrimSpace(out)) {
		if _, err := kubectl("patch", "daemonset", ds,
			"-n", "kubevirt", "--type=merge", "-p="+patch); err != nil {
			return fmt.Errorf("patch kubevirt daemonset %s: %w", ds, err)
		}
	}
	return nil
}

// cdiConfig patches every Deployment in the cdi namespace with the
// tie-breaker nodeSelector.
func cdiConfig(ctx context.Context) error {
	log.Printf("tiebreaker: patching cdi deployments with nodeSelector")
	out, err := kubectl("get", "deployments", "-n", "cdi",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return fmt.Errorf("list cdi deployments: %w", err)
	}
	patch := nodeSelectorPatch(tieBreakerNodeLabel, tieBreakerLabelUnset)
	for _, deploy := range strings.Fields(strings.TrimSpace(out)) {
		if _, err := kubectl("patch", "deployment", deploy,
			"-n", "cdi", "--type=merge", "-p="+patch); err != nil {
			return fmt.Errorf("patch cdi deployment %s: %w", deploy, err)
		}
	}
	return nil
}

// nodeSelectorPatch returns the merge-patch JSON that sets
// .spec.template.spec.nodeSelector[label]=value.
func nodeSelectorPatch(label, value string) string {
	return fmt.Sprintf(
		`{"spec":{"template":{"spec":{"nodeSelector":{"%s":"%s"}}}}}`,
		label, value)
}

// longhornNodeDisks captures just the disk names from a Longhorn
// node's spec, which is enough to enumerate disks for patching.
type longhornNodeDisks struct {
	Spec struct {
		Disks map[string]json.RawMessage `json:"disks"`
	} `json:"spec"`
}

// longhornNodeSetSched flips allowScheduling + evictionRequested on
// the named Longhorn node AND every one of its disks. enabled=false
// is how we tell Longhorn to evict replicas off the tie-breaker.
func longhornNodeSetSched(ctx context.Context, nodeName string, enabled bool) error {
	log.Printf("tiebreaker: longhorn node %s scheduling=%v", nodeName, enabled)
	sched := enabled
	evict := !enabled

	nodeJSON, err := kubectl("get", "nodes.longhorn.io", nodeName,
		"-n", "longhorn-system", "-o", "json")
	if err != nil {
		return fmt.Errorf("get longhorn node %s: %w", nodeName, err)
	}
	var lhNode longhornNodeDisks
	if err := json.Unmarshal([]byte(nodeJSON), &lhNode); err != nil {
		return fmt.Errorf("parse longhorn node %s: %w", nodeName, err)
	}

	if err := longhornJSONPatch(nodeName, "/spec/allowScheduling", sched); err != nil {
		return err
	}
	if err := longhornJSONPatch(nodeName, "/spec/evictionRequested", evict); err != nil {
		return err
	}
	for diskName := range lhNode.Spec.Disks {
		if err := longhornJSONPatch(nodeName,
			fmt.Sprintf("/spec/disks/%s/allowScheduling", diskName),
			sched); err != nil {
			return fmt.Errorf("disk %s: %w", diskName, err)
		}
		if err := longhornJSONPatch(nodeName,
			fmt.Sprintf("/spec/disks/%s/evictionRequested", diskName),
			evict); err != nil {
			return fmt.Errorf("disk %s: %w", diskName, err)
		}
	}
	return nil
}

// longhornJSONPatch applies a single-op JSON Patch to the named
// Longhorn node.
func longhornJSONPatch(nodeName, path string, value bool) error {
	patch := fmt.Sprintf(`[{"op":"replace","path":"%s","value":%v}]`, path, value)
	if _, err := kubectl("patch", "nodes.longhorn.io", nodeName,
		"-n", "longhorn-system", "--type=json", "-p="+patch); err != nil {
		return fmt.Errorf("patch longhorn node %s %s: %w", nodeName, path, err)
	}
	return nil
}

// longhornRescale scales the Longhorn CSI sidecar Deployments to
// `replicas` and patches every longhorn-system DaemonSet with the
// tie-breaker nodeSelector. DaemonSet patches retry 5x because
// longhorn-manager occasionally races us during initial install.
func longhornRescale(ctx context.Context, replicas int) error {
	r := fmt.Sprintf("%d", replicas)
	log.Printf("tiebreaker: rescaling longhorn components to %s replicas", r)

	for _, deploy := range []string{
		"csi-attacher", "csi-provisioner", "csi-resizer", "csi-snapshotter",
	} {
		if _, err := kubectl("scale", "deployment", deploy,
			"-n", "longhorn-system", "--replicas="+r); err != nil {
			return fmt.Errorf("scale longhorn deployment %s: %w", deploy, err)
		}
	}

	out, err := kubectl("get", "daemonsets", "-n", "longhorn-system",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return fmt.Errorf("list longhorn daemonsets: %w", err)
	}
	patch := nodeSelectorPatch(tieBreakerNodeLabel, tieBreakerLabelUnset)
	for _, ds := range strings.Fields(strings.TrimSpace(out)) {
		var patchErr error
		for i := 0; i < 5; i++ {
			if _, patchErr = kubectl("patch", "daemonset", ds,
				"-n", "longhorn-system", "--type=merge",
				"-p="+patch); patchErr == nil {
				break
			}
			log.Printf("tiebreaker: retry %d/5 patching longhorn daemonset %s: %v",
				i+1, ds, patchErr)
		}
		if patchErr != nil {
			return fmt.Errorf("patch longhorn daemonset %s after 5 retries: %w",
				ds, patchErr)
		}
	}
	return nil
}

// ConfigApply is the entry point. Returns nil and logs the reason
// when a precondition is unmet (config not set, labels not yet
// applied, fewer than 3 nodes, not the tie-breaker, already done).
// Returns an error only when an actual configuration step fails.
func ConfigApply(ctx context.Context, selfUUID string) error {
	if !ConfigIsSet() {
		log.Printf("tiebreaker: config not set, skipping")
		return nil
	}

	labeled, err := state.IsMarked(state.NodeLabelsInitialized)
	if err != nil {
		return fmt.Errorf("check %s marker: %w",
			state.NodeLabelsInitialized, err)
	}
	if !labeled {
		log.Printf("tiebreaker: node labels not yet initialized, skipping")
		return nil
	}

	if !NodeCountIsCluster(ctx) {
		log.Printf("tiebreaker: cluster does not have %d nodes yet, skipping",
			clusterNodeCount)
		return nil
	}

	tieUUID, err := ConfigGetNodeUUID()
	if err != nil {
		return fmt.Errorf("get tie-breaker node UUID: %w", err)
	}

	if !StatusIsSelf(tieUUID, selfUUID) {
		log.Printf("tiebreaker: this node (%s) is not the tie-breaker (%s), skipping",
			selfUUID, tieUUID)
		return nil
	}

	if StatusGet(ctx) {
		log.Printf("tiebreaker: config already applied, skipping")
		return nil
	}

	log.Printf("tiebreaker: applying configuration")

	tieName, err := nodeNameFromUUID(ctx, tieUUID)
	if err != nil {
		return fmt.Errorf("resolve tie-breaker node name: %w", err)
	}

	for _, step := range []struct {
		name string
		fn   func() error
	}{
		{"nodesConfigApply", func() error { return nodesConfigApply(ctx, tieUUID) }},
		{"kubevirtConfig", func() error { return kubevirtConfig(ctx, 2) }},
		{"kubevirtTieBreakerConfigApply", func() error { return kubevirtTieBreakerConfigApply(ctx) }},
		{"cdiConfig", func() error { return cdiConfig(ctx) }},
		{"longhornNodeSetSched", func() error { return longhornNodeSetSched(ctx, tieName, false) }},
		{"longhornRescale", func() error { return longhornRescale(ctx, 2) }},
	} {
		if err := step.fn(); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
	}

	log.Printf("tiebreaker: draining %s", tieName)
	if _, err := kubectl("drain", tieName,
		"--ignore-daemonsets", "--delete-emptydir-data", "--force"); err != nil {
		return fmt.Errorf("drain tie-breaker node %s: %w", tieName, err)
	}

	if err := StatusSet(ctx); err != nil {
		return fmt.Errorf("set tie-breaker status: %w", err)
	}
	log.Printf("tiebreaker: configuration applied successfully")
	return nil
}

// kubectl logs the invocation and forwards to kubectlx.Run.
// Local wrapper because every tie-breaker action is a kubectl call
// that we want surfaced in the daemon log for postmortem inspection.
func kubectl(args ...string) (string, error) {
	log.Printf("kubectl %s", strings.Join(args, " "))
	return kubectlx.Run(args...)
}
