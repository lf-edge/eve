// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// errKubeconfigRotated reports that the kubeconfig was rewritten after
// the client was built. The client embeds the CA it was constructed
// with, so once the file changes it can never succeed again — every call
// fails the TLS handshake against a healthy apiserver. Waiting it out is
// therefore pointless; the caller must rebuild and resume.
var errKubeconfigRotated = errors.New("kubeconfig rotated under the client")

// kubeconfigRebuilds caps how many times a single wait will rebuild.
// A join rotates once, when the node adopts the cluster CA. A budget
// bounds the pathological case where something rewrites the file
// continuously, so the wait fails with a diagnosis instead of spinning.
const kubeconfigRebuilds = 3

// Readiness-wait cadences. Vars so tests can shrink them.
var (
	kubeconfigPollInterval = 5 * time.Second
	nodeReadyPollInterval  = 5 * time.Second
	podReadyPollInterval   = 10 * time.Second
)

// WaitReady blocks until k3s is fully operational: kubeconfig
// appeared + copied, the local node reports Ready, the node-uuid
// label is applied, and every pod in kube-system is Ready.
//
// The supplied timeout bounds the whole sequence (a fresh
// context.WithTimeout is derived from ctx and consumed inside).
//
// Step 4 (label node) is non-fatal — a label-application failure
// only matters for cross-node addressing in HA clusters and the FSM
// can retry later.
func WaitReady(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := WaitKubeconfig(ctx); err != nil {
		return fmt.Errorf("wait kubeconfig: %w", err)
	}

	// Build a client-go clientset now that the kubeconfig exists.
	// Dial errors against the not-yet-serving API surface as
	// per-Get failures below and drive the poll loops — no shell-out.
	// This client is local to WaitReady; the daemon-scoped
	// kubeclient.Default() is initialised separately by main.
	kc, err := kubeclient.New(state.K3sKubeconfig)
	if err != nil {
		return fmt.Errorf("build kubeclient: %w", err)
	}

	logAPITarget(kc, state.K3sKubeconfig)
	kubeconfigAt := kubeconfigMtime(state.K3sKubeconfig)

	info, ok := edgenodeinfo.Get()
	if !ok {
		return fmt.Errorf("EdgeNodeInfo not yet published; subscription has not delivered")
	}
	if info.DeviceName == "" {
		return fmt.Errorf("EdgeNodeInfo.DeviceName is empty (corrupted payload)")
	}
	uuid := info.DeviceID.String()
	if uuid == "" {
		return fmt.Errorf("EdgeNodeInfo.DeviceID is empty (corrupted payload)")
	}
	nodeName := state.ToK8sName(info.DeviceName)

	for rebuilds := 0; ; rebuilds++ {
		err := waitNodeReady(ctx, kc, kc.Clientset, nodeName,
			state.K3sKubeconfig, kubeconfigAt)
		if err == nil {
			break
		}
		if !errors.Is(err, errKubeconfigRotated) {
			return fmt.Errorf("wait node ready: %w", err)
		}
		if rebuilds >= kubeconfigRebuilds {
			return fmt.Errorf("wait node ready: kubeconfig rotated %d times: %w",
				rebuilds+1, err)
		}
		kc, kubeconfigAt, err = rebuildClient()
		if err != nil {
			return fmt.Errorf("wait node ready: %w", err)
		}
	}

	if err := labelNodeUUID(ctx, kc.Clientset, nodeName, uuid); err != nil {
		log.Printf("warning: failed to label node %s with uuid: %v", nodeName, err)
	}

	if err := waitSystemPodsReady(ctx, kc, kc.Clientset, nodeName); err != nil {
		return fmt.Errorf("wait system pods ready: %w", err)
	}
	log.Printf("k3s is fully ready")
	return nil
}

// WaitKubeconfig polls state.K3sKubeconfig until it appears, then
// copies it to KubeconfigCopy. The poll honours ctx — the caller is
// expected to bound the wait via context.WithTimeout.
func WaitKubeconfig(ctx context.Context) error {
	log.Printf("waiting for kubeconfig at %s", state.K3sKubeconfig)

	ticker := time.NewTicker(kubeconfigPollInterval)
	defer ticker.Stop()
	for {
		present, err := fileExists(state.K3sKubeconfig)
		if err != nil {
			return fmt.Errorf("stat %s: %w", state.K3sKubeconfig, err)
		}
		if present {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s: %w",
				state.K3sKubeconfig, ctx.Err())
		case <-ticker.C:
		}
	}

	if err := copyKubeconfig(); err != nil {
		return fmt.Errorf("copy kubeconfig: %w", err)
	}
	log.Printf("kubeconfig ready and copied to %s", KubeconfigCopy)
	return nil
}

// rebuildClient constructs a fresh client from the kubeconfig now on
// disk and republishes the copy pillar reads.
//
// Refreshing KubeconfigCopy is the point of doing this here rather than
// leaving it to the periodic mirror: it is what pillar's zedkube opens
// (kubeapi.EVEkubeConfigFile), so until it carries the new CA, node
// drain and delete fail the same TLS handshake we just recovered from.
func rebuildClient() (*kubeclient.Client, string, error) {
	kc, err := kubeclient.New(state.K3sKubeconfig)
	if err != nil {
		return nil, "", fmt.Errorf("rebuild kubeclient: %w", err)
	}
	if err := copyKubeconfig(); err != nil {
		// Non-fatal for our own progress; pillar's copy is refreshed
		// again by the periodic mirror.
		log.Printf("warning: refresh %s after rotation: %v", KubeconfigCopy, err)
	}
	logAPITarget(kc, state.K3sKubeconfig)
	return kc, kubeconfigMtime(state.K3sKubeconfig), nil
}

// fileExists is the cousin of os.Stat that distinguishes
// "definitely absent" (false, nil) from "we cannot tell" (false,
// err) — silently treating EACCES/EIO as "absent" hides the
// underlying breakage from the FSM.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// copyKubeconfig atomically copies state.K3sKubeconfig to
// KubeconfigCopy, ensuring the destination directory exists.
func copyKubeconfig() error {
	if err := os.MkdirAll(KubeconfigCopyDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", KubeconfigCopyDir, err)
	}
	data, err := os.ReadFile(state.K3sKubeconfig)
	if err != nil {
		return fmt.Errorf("read %s: %w", state.K3sKubeconfig, err)
	}
	if err := state.AtomicWriteFile(KubeconfigCopy, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", KubeconfigCopy, err)
	}
	return nil
}

// waitNodeReady polls the API server until the named node reports
// Ready=True. API-server dial errors and NotFound (node hasn't
// registered yet) drive the poll — anything else surfaces.
func waitNodeReady(
	ctx context.Context, kc *kubeclient.Client, cs kubernetes.Interface,
	nodeName, kubeconfigPath, kubeconfigAt string,
) error {
	log.Printf("waiting for node %s to be Ready", nodeName)

	ticker := time.NewTicker(nodeReadyPollInterval)
	defer ticker.Stop()
	var attempt int
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for node %s to be Ready: %w",
				nodeName, ctx.Err())
		case <-ticker.C:
		}
		n, err := getNodeBounded(ctx, cs, nodeName)
		if err != nil {
			// API not up yet, or node not registered — keep polling,
			// but say so every so often. This loop can run for the
			// whole readiness budget, and a silent one is
			// indistinguishable from a hung one: five minutes of no
			// output here is what made a stalled join take an hour to
			// diagnose on 2026-08-02.
			// A rewrite means this client can never succeed: it holds
			// the CA it was built with, and the file on disk now
			// describes a different one. Bail out to be rebuilt rather
			// than spend the rest of the budget failing the same
			// handshake.
			if now := kubeconfigMtime(kubeconfigPath); now != "" &&
				now != kubeconfigAt {
				log.Printf("node %s not readable and %s was rewritten "+
					"(%s → %s): this client trusts a retired CA, rebuilding",
					nodeName, kubeconfigPath, kubeconfigAt, now)
				return errKubeconfigRotated
			}
			attempt++
			// Probe on the first failure and then periodically: the
			// call's own error says "deadline exceeded" for every
			// distinct cause, so the layer breakdown is what actually
			// identifies it.
			if attempt == 1 || attempt%6 == 0 {
				log.Printf("node %s not readable (attempt %d): %v | %s",
					nodeName, attempt, errShort(err),
					probeAPI(ctx, kc, kubeconfigPath, kubeconfigAt))
			}
			continue
		}
		if kubectlx.IsNodeReady(n) {
			log.Printf("node %s is Ready", nodeName)
			return nil
		}
		// Readable but not Ready. Say WHY, periodically. Logging the
		// condition's reason/message together with the object's
		// resourceVersion is what separates the two very different
		// situations that look identical from outside:
		//
		//   - resourceVersion advancing, reason=KubeletNotReady — a
		//     genuine node condition (CNI down, runtime unhealthy);
		//     kubelet is posting status and we are simply waiting.
		//   - resourceVersion frozen — we are reading a stale object.
		//     Seen 2026-08-05: after a join, edge-dev1 reported dev2
		//     Ready while dev2's own API said not-Ready for five
		//     minutes, and the join watchdog rebooted it.
		//
		// The distinction decides whether the bug is in the node or in
		// which datastore the local apiserver is answering from, and it
		// cost an hour of log archaeology for want of these two fields.
		attempt++
		logEveryNPolls(attempt,
			fmt.Sprintf("node %s readable but not Ready [%s]", nodeName,
				describeNodeReady(n)), nil)
	}
}

// describeNodeReady renders the Ready condition plus the identity of the
// object it came from, for the diagnostic above.
func describeNodeReady(n *corev1.Node) string {
	rv := n.ResourceVersion
	for _, c := range n.Status.Conditions {
		if c.Type != corev1.NodeReady {
			continue
		}
		return fmt.Sprintf("Ready=%s reason=%q msg=%q lastTransition=%s resourceVersion=%s",
			c.Status, c.Reason, c.Message, c.LastTransitionTime.Format(time.RFC3339), rv)
	}
	return fmt.Sprintf("no Ready condition at all; conditions=%d resourceVersion=%s",
		len(n.Status.Conditions), rv)
}

// labelNodeUUID applies the `node-uuid=<uuid>` label to nodeName,
// overwriting any prior value. Uses a JSON merge patch so partial
// label maps on the object are preserved.
func labelNodeUUID(ctx context.Context, cs kubernetes.Interface, nodeName, uuid string) error {
	patch, err := kubectlx.BuildMergeLabelPatch(
		map[string]string{"node-uuid": uuid}, nil)
	if err != nil {
		return fmt.Errorf("build node-uuid label patch: %w", err)
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, nodeName,
		types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("label node %s: not found (registration race?): %w",
				nodeName, err)
		}
		return fmt.Errorf("label node %s: %w", nodeName, err)
	}
	log.Printf("labelled node %s with node-uuid=%s", nodeName, uuid)
	return nil
}

// waitSystemPodsReady blocks until every pod in kube-system reports
// Ready or has finished (Completed/Succeeded). Progress is logged
// every time the ready/total count changes, including the list of
// pods we are still waiting on.
// OnProgress, when set, is called whenever WaitReady observes forward
// movement — currently a change in the ready/total system-pod counts.
// Wired by main.go to the join watchdog so a node that is converging
// slowly but genuinely is not mistaken for a wedged one. A package var
// because k3s cannot import monitor without a cycle.
var OnProgress func(stage string)

func noteProgress(stage string) {
	if OnProgress != nil {
		OnProgress(stage)
	}
}

func waitSystemPodsReady(
	ctx context.Context, kc *kubeclient.Client, cs kubernetes.Interface,
	nodeName string,
) error {
	log.Printf("waiting for this node's system pods to be Ready")
	ticker := time.NewTicker(podReadyPollInterval)
	defer ticker.Stop()

	var lastReady, lastTotal int
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for system pods: %w", ctx.Err())
		case <-ticker.C:
		}
		ready, total, notReady := countSystemPods(ctx, cs, nodeName)
		if total == 0 {
			continue
		}
		if ready != lastReady || total != lastTotal {
			if len(notReady) > 0 {
				log.Printf("system pods: [%d/%d] ready, waiting on: %s",
					ready, total, strings.Join(notReady, ", "))
			}
			lastReady, lastTotal = ready, total
			// Counts moved, so the node is converging. Tell the join
			// watchdog: sitting in WAIT_K3S_READY while pods come up
			// is the normal path after a join and routinely outlasts
			// the stall limit, but it is not a stall.
			noteProgress(fmt.Sprintf("system pods %d/%d ready", ready, total))
		}
		if ready == total {
			log.Printf("all system pods are Ready [%d/%d]", ready, total)
			return nil
		}
	}
}

// countSystemPods counts the kube-system pods scheduled to nodeName and
// classifies each by readiness. Transient API errors collapse to
// (0, 0, nil) — the caller keeps polling.
//
// Scoped to this node on purpose. "Is my node ready to proceed" is a
// node-local question, and the pod list is cluster-wide: on a
// single-node cluster the two are the same set, which is why counting
// everything went unnoticed. In a cluster it means one node's
// readiness depends on pods belonging to other nodes, including a node
// that is deliberately being removed — whose DaemonSet pods stay
// Pending forever. Observed 2026-08-02: while edge-dev3 was converting
// back to single-node, edge-dev2 sat at 9/11 waiting on
// kube-multus-ds and svclb-traefik pods bound to edge-dev3, never
// reached RUNNING, never cleared its join marker, and was rebooted by
// the join watchdog every five minutes — correctly, because its join
// genuinely never completed.
//
// Pods with no nodeName yet (unscheduled) are skipped rather than
// counted as not-ready: they are not this node's business until the
// scheduler places them.
func countSystemPods(
	ctx context.Context, cs kubernetes.Interface, nodeName string,
) (int, int, []string) {
	// The field selector does the filtering server-side; countPodsOnNode
	// repeats it locally so the scoping holds even if a selector is
	// dropped somewhere in between, and so the rule is testable without
	// an API server.
	callCtx, cancel := context.WithTimeout(ctx, apiCallBudget)
	defer cancel()
	pods, err := cs.CoreV1().Pods("kube-system").List(callCtx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil || pods == nil || len(pods.Items) == 0 {
		return 0, 0, nil
	}
	return countPodsOnNode(pods.Items, nodeName)
}

// countPodsOnNode classifies pods bound to nodeName. Pods on other
// nodes, and pods the scheduler has not placed yet, are not this
// node's business and are skipped entirely rather than counted
// not-ready.
func countPodsOnNode(pods []corev1.Pod, nodeName string) (int, int, []string) {
	var ready, total int
	var notReady []string
	for i := range pods {
		p := &pods[i]
		if p.Spec.NodeName != nodeName {
			continue
		}
		total++
		if p.Status.Phase == corev1.PodSucceeded {
			ready++
			continue
		}
		if p.Status.Phase != corev1.PodRunning {
			notReady = append(notReady, p.Name+"("+string(p.Status.Phase)+")")
			continue
		}
		if podContainersReady(p) {
			ready++
		} else {
			notReady = append(notReady, p.Name+"("+string(p.Status.Phase)+")")
		}
	}
	return ready, total, notReady
}

// podContainersReady returns true if every container has Ready=True.
// Matches `kubectl get pods` READY column semantics.
func podContainersReady(p *corev1.Pod) bool {
	if len(p.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, cs := range p.Status.ContainerStatuses {
		if !cs.Ready {
			return false
		}
	}
	return true
}

// logEveryNPolls keeps a long poll loop audible without flooding the
// log: one line on the first failure, then one a minute at the default
// 5s cadence.
func logEveryNPolls(attempt int, what string, err error) {
	const every = 12
	if attempt != 1 && attempt%every != 0 {
		return
	}
	if err != nil {
		log.Printf("%s (attempt %d): %v", what, attempt, err)
		return
	}
	log.Printf("%s (attempt %d)", what, attempt)
}

// apiCallBudget bounds a single API call inside a poll loop.
//
// client-go applies no client-side deadline of its own and we
// deliberately do not set rest.Config.Timeout — that would also cut the
// informers' long-lived watches. So without a per-call context a Get
// against an apiserver that accepts the connection and then never
// answers blocks for the whole enclosing budget, and the loop around it
// polls exactly once.
//
// That is what happened on 2026-08-05: edge-dev2's readiness wait made a
// single Get after its cluster join, that call hung, and five minutes
// passed with no output and no retry — which read as "the node is not
// Ready" when the truth was "we never got an answer". edge-dev1
// considered the same node Ready throughout.
const apiCallBudget = 10 * time.Second

// getNodeBounded fetches a node under apiCallBudget so a hung apiserver
// costs one iteration rather than the entire readiness budget. A
// deadline here surfaces as an ordinary error and drives the poll loop's
// retry and logging.
func getNodeBounded(
	ctx context.Context, cs kubernetes.Interface, nodeName string,
) (*corev1.Node, error) {
	callCtx, cancel := context.WithTimeout(ctx, apiCallBudget)
	defer cancel()
	return cs.CoreV1().Nodes().Get(callCtx, nodeName, metav1.GetOptions{})
}
