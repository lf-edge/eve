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
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/encconfig"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
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
//
// client-go has no "label --all" bulk operation; we List then Patch
// each node with a merge patch. A per-node error is fatal (the
// caller retries the whole phase).
func StatusSet(ctx context.Context) error {
	log.Printf("tiebreaker: setting status label on all nodes")
	nodes := kubeclient.Default().Clientset.CoreV1().Nodes()
	list, err := nodes.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	patch, err := kubectlx.BuildMergeLabelPatch(
		map[string]string{"tie-breaker-config-applied": "1"}, nil)
	if err != nil {
		return fmt.Errorf("build tie-breaker status patch: %w", err)
	}
	for _, n := range list.Items {
		if _, err := nodes.Patch(ctx, n.Name,
			types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("label node %s: %w", n.Name, err)
		}
	}
	return nil
}

// StatusGet reports whether the status label has been applied to
// every node in the cluster (exactly clusterNodeCount nodes).
func StatusGet(ctx context.Context) bool {
	list, err := kubeclient.Default().Clientset.CoreV1().Nodes().
		List(ctx, metav1.ListOptions{LabelSelector: "tie-breaker-config-applied=1"})
	if err != nil {
		return false
	}
	return len(list.Items) == clusterNodeCount
}

// NodeCountIsCluster reports whether the cluster currently has the
// expected three nodes. Used to gate ConfigApply: until all three
// have joined we can't pick a tie-breaker.
func NodeCountIsCluster(ctx context.Context) bool {
	list, err := kubeclient.Default().Clientset.CoreV1().Nodes().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return false
	}
	return len(list.Items) == clusterNodeCount
}

// nodeNameFromUUID maps a device UUID onto its Kubernetes node name
// via the node-uuid=<uuid> label that k3s readiness applies.
func nodeNameFromUUID(ctx context.Context, uuid string) (string, error) {
	list, err := kubeclient.Default().Clientset.CoreV1().Nodes().
		List(ctx, metav1.ListOptions{LabelSelector: "node-uuid=" + uuid})
	if err != nil {
		return "", fmt.Errorf("get node name for uuid %s: %w", uuid, err)
	}
	if len(list.Items) == 0 {
		return "", fmt.Errorf("no node found with uuid %s", uuid)
	}
	return list.Items[0].Name, nil
}

// nodesConfigApply labels the tie-breaker with tie-breaker-node=true
// and cordons it; every other node gets tie-breaker-node=false and
// an uncordon (defensive — they may already be ready).
func nodesConfigApply(ctx context.Context, tieUUID string) error {
	tieName, err := nodeNameFromUUID(ctx, tieUUID)
	if err != nil {
		return err
	}
	nodes := kubeclient.Default().Clientset.CoreV1().Nodes()
	list, err := nodes.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	for _, n := range list.Items {
		labelValue := tieBreakerLabelUnset
		wantCordon := false
		if n.Name == tieName {
			log.Printf("tiebreaker: labeling %s as tie-breaker", n.Name)
			labelValue = tieBreakerLabelSet
			wantCordon = true
		} else {
			log.Printf("tiebreaker: labeling %s as worker", n.Name)
		}
		labelPatch, err := kubectlx.BuildMergeLabelPatch(
			map[string]string{tieBreakerNodeLabel: labelValue}, nil)
		if err != nil {
			return fmt.Errorf("build tie-breaker label patch for %s: %w", n.Name, err)
		}
		if _, err := nodes.Patch(ctx, n.Name,
			types.MergePatchType, labelPatch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("label node %s: %w", n.Name, err)
		}
		if err := setCordoned(ctx, nodes, n.Name, wantCordon); err != nil {
			return err
		}
	}
	return nil
}

// setCordoned flips spec.unschedulable on the named node.
// Idempotent: patching to the same value is a no-op at the API server.
func setCordoned(ctx context.Context, nodes corev1client.NodeInterface, name string, cordon bool) error {
	patch := fmt.Sprintf(`{"spec":{"unschedulable":%v}}`, cordon)
	if _, err := nodes.Patch(ctx, name,
		types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		verb := "cordon"
		if !cordon {
			verb = "uncordon"
		}
		return fmt.Errorf("%s node %s: %w", verb, name, err)
	}
	return nil
}

// kubevirtConfig sets the KubeVirt control-plane replica count
// (virt-operator Deployment + KubeVirt CR's .spec.infra.replicas).
func kubevirtConfig(ctx context.Context, replicas int) error {
	log.Printf("tiebreaker: scaling kubevirt to %d replicas", replicas)
	kc := kubeclient.Default()
	deployPatch := fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas)
	if _, err := kc.Clientset.AppsV1().Deployments(kubectlx.KubeVirtNamespace).
		Patch(ctx, "virt-operator", types.MergePatchType,
			[]byte(deployPatch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("scale virt-operator: %w", err)
	}
	crPatch := fmt.Sprintf(`{"spec":{"infra":{"replicas":%d}}}`, replicas)
	if _, err := kc.Dynamic.Resource(kubectlx.KubeVirtGVR).Namespace(kubectlx.KubeVirtNamespace).
		Patch(ctx, "kubevirt", types.MergePatchType, []byte(crPatch),
			metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch kubevirt CR replicas: %w", err)
	}
	return nil
}

// kubevirtTieBreakerConfigApply patches every DaemonSet in the
// kubevirt namespace with a nodeSelector that keeps pods off the
// tie-breaker (tie-breaker-node=false).
func kubevirtTieBreakerConfigApply(ctx context.Context) error {
	log.Printf("tiebreaker: patching kubevirt daemonsets with nodeSelector")
	return patchDaemonSetsInNamespace(ctx, kubectlx.KubeVirtNamespace, 1)
}

// cdiConfig patches every Deployment in the cdi namespace with the
// tie-breaker nodeSelector.
func cdiConfig(ctx context.Context) error {
	log.Printf("tiebreaker: patching cdi deployments with nodeSelector")
	kc := kubeclient.Default()
	deps, err := kc.Clientset.AppsV1().Deployments(kubectlx.CDINamespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list cdi deployments: %w", err)
	}
	patch := nodeSelectorPatch(tieBreakerNodeLabel, tieBreakerLabelUnset)
	for _, d := range deps.Items {
		if _, err := kc.Clientset.AppsV1().Deployments(kubectlx.CDINamespace).
			Patch(ctx, d.Name, types.MergePatchType, []byte(patch),
				metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("patch cdi deployment %s: %w", d.Name, err)
		}
	}
	return nil
}

// patchDaemonSetsInNamespace applies the tie-breaker nodeSelector
// merge-patch to every DaemonSet in the given namespace, retrying
// each patch up to maxRetries times. The retry count matters for
// longhorn-system where longhorn-manager occasionally races us
// during initial install; kubevirt namespace usage passes 1.
func patchDaemonSetsInNamespace(ctx context.Context, ns string, maxRetries int) error {
	if maxRetries < 1 {
		maxRetries = 1
	}
	kc := kubeclient.Default()
	dsClient := kc.Clientset.AppsV1().DaemonSets(ns)
	list, err := dsClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list daemonsets in %s: %w", ns, err)
	}
	patch := nodeSelectorPatch(tieBreakerNodeLabel, tieBreakerLabelUnset)
	for _, ds := range list.Items {
		var lastErr error
		for i := 0; i < maxRetries; i++ {
			_, lastErr = dsClient.Patch(ctx, ds.Name,
				types.MergePatchType, []byte(patch), metav1.PatchOptions{})
			if lastErr == nil {
				break
			}
			if i < maxRetries-1 {
				log.Printf("tiebreaker: retry %d/%d patching %s daemonset %s: %v",
					i+1, maxRetries, ns, ds.Name, lastErr)
			}
		}
		if lastErr != nil {
			return fmt.Errorf("patch %s daemonset %s after %d retries: %w",
				ns, ds.Name, maxRetries, lastErr)
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

	obj, err := kubeclient.Default().Dynamic.Resource(kubectlx.LonghornNodesGVR).
		Namespace(kubectlx.LonghornNamespace).Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get longhorn node %s: %w", nodeName, err)
	}
	raw, err := json.Marshal(obj.Object)
	if err != nil {
		return fmt.Errorf("marshal longhorn node %s: %w", nodeName, err)
	}
	var lhNode longhornNodeDisks
	if err := json.Unmarshal(raw, &lhNode); err != nil {
		return fmt.Errorf("parse longhorn node %s: %w", nodeName, err)
	}

	if err := longhornJSONPatch(ctx, nodeName, "/spec/allowScheduling", sched); err != nil {
		return err
	}
	if err := longhornJSONPatch(ctx, nodeName, "/spec/evictionRequested", evict); err != nil {
		return err
	}
	for diskName := range lhNode.Spec.Disks {
		if err := longhornJSONPatch(ctx, nodeName,
			fmt.Sprintf("/spec/disks/%s/allowScheduling", diskName),
			sched); err != nil {
			return fmt.Errorf("disk %s: %w", diskName, err)
		}
		if err := longhornJSONPatch(ctx, nodeName,
			fmt.Sprintf("/spec/disks/%s/evictionRequested", diskName),
			evict); err != nil {
			return fmt.Errorf("disk %s: %w", diskName, err)
		}
	}
	return nil
}

// longhornJSONPatch applies a single-op JSON Patch to the named
// Longhorn node CR.
func longhornJSONPatch(ctx context.Context, nodeName, path string, value bool) error {
	patch := fmt.Sprintf(`[{"op":"replace","path":"%s","value":%v}]`, path, value)
	if _, err := kubeclient.Default().Dynamic.Resource(kubectlx.LonghornNodesGVR).
		Namespace(kubectlx.LonghornNamespace).Patch(ctx, nodeName,
		types.JSONPatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch longhorn node %s %s: %w", nodeName, path, err)
	}
	return nil
}

// longhornRescale scales the Longhorn CSI sidecar Deployments to
// `replicas` and patches every longhorn-system DaemonSet with the
// tie-breaker nodeSelector. DaemonSet patches retry 5x because
// longhorn-manager occasionally races us during initial install.
func longhornRescale(ctx context.Context, replicas int) error {
	log.Printf("tiebreaker: rescaling longhorn components to %d replicas", replicas)
	kc := kubeclient.Default()

	deployPatch := fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas)
	for _, deploy := range []string{
		"csi-attacher", "csi-provisioner", "csi-resizer", "csi-snapshotter",
	} {
		if _, err := kc.Clientset.AppsV1().Deployments(kubectlx.LonghornNamespace).
			Patch(ctx, deploy, types.MergePatchType,
				[]byte(deployPatch), metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("scale longhorn deployment %s: %w", deploy, err)
		}
	}

	return patchDaemonSetsInNamespace(ctx, kubectlx.LonghornNamespace, 5)
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
	if err := drainNode(ctx, tieName); err != nil {
		return fmt.Errorf("drain tie-breaker node %s: %w", tieName, err)
	}

	if err := StatusSet(ctx); err != nil {
		return fmt.Errorf("set tie-breaker status: %w", err)
	}
	log.Printf("tiebreaker: configuration applied successfully")
	return nil
}

// drainNode is the client-go equivalent of `kubectl drain <node>
// --ignore-daemonsets --delete-emptydir-data --force`. It:
//   - lists every pod scheduled on the node,
//   - skips DaemonSet-owned pods (they're re-created immediately
//     anyway; kubectl's --ignore-daemonsets does the same),
//   - issues an Eviction (respecting PodDisruptionBudgets) for every
//     other pod,
//   - waits until each evicted pod has actually disappeared from
//     the node.
//
// `--delete-emptydir-data` is implicit here: the Eviction API
// terminates pods regardless of emptyDir volumes, and any local
// data goes with them — same effective behaviour as the kubectl
// flag. `--force` semantics are also inherent: we evict every
// unmanaged pod without prompting.
func drainNode(ctx context.Context, nodeName string) error {
	kc := kubeclient.Default()
	nodes := kc.Clientset.CoreV1().Nodes()

	// Ensure the node is cordoned before draining, matching kubectl
	// drain's own precondition (kubectl cordons first if needed).
	if err := setCordoned(ctx, nodes, nodeName, true); err != nil {
		return err
	}

	pods, err := kc.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return fmt.Errorf("list pods on node %s: %w", nodeName, err)
	}

	toEvict := make([]corev1.Pod, 0, len(pods.Items))
	for _, p := range pods.Items {
		if isDaemonSetPod(&p) {
			continue
		}
		toEvict = append(toEvict, p)
	}

	for i := range toEvict {
		p := &toEvict[i]
		eviction := &policyv1.Eviction{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.Name, Namespace: p.Namespace,
			},
		}
		if err := kc.Clientset.PolicyV1().
			Evictions(p.Namespace).Evict(ctx, eviction); err != nil {
			// NotFound = pod already gone (fine); TooManyRequests
			// means a PDB blocks eviction — retry once after a
			// short wait since drain is supposed to be forceful.
			if apierrors.IsNotFound(err) {
				continue
			}
			if apierrors.IsTooManyRequests(err) {
				time.Sleep(2 * time.Second)
				if err := kubectlx.IgnoreNotFound(
					kc.Clientset.PolicyV1().Evictions(p.Namespace).
						Evict(ctx, eviction)); err != nil {
					return fmt.Errorf("evict %s/%s: %w", p.Namespace, p.Name, err)
				}
				continue
			}
			return fmt.Errorf("evict %s/%s: %w", p.Namespace, p.Name, err)
		}
	}

	return waitForPodsGone(ctx, nodeName, toEvict)
}

// isDaemonSetPod matches kubectl drain's --ignore-daemonsets rule:
// any pod owned by a DaemonSet is skipped.
func isDaemonSetPod(p *corev1.Pod) bool {
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

// waitForPodsGone blocks until every pod in `evicted` has left the
// node — either deleted or rescheduled elsewhere. Polls at 2s
// intervals; caller's ctx bounds the overall wait.
func waitForPodsGone(ctx context.Context, nodeName string, evicted []corev1.Pod) error {
	if len(evicted) == 0 {
		return nil
	}
	kc := kubeclient.Default()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		remaining := 0
		for i := range evicted {
			p := &evicted[i]
			cur, err := kc.Clientset.CoreV1().Pods(p.Namespace).
				Get(ctx, p.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				continue
			}
			if err == nil && cur.Spec.NodeName != nodeName {
				continue
			}
			remaining++
		}
		if remaining == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("drain %s: %d pods still on node after 5m",
				nodeName, remaining)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
