// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestFileExistsClassification separates "definitely absent" from "cannot tell" (EACCES).
func TestFileExistsClassification(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	absent := filepath.Join(dir, "absent")
	if err := os.WriteFile(present, []byte("x"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ok, err := fileExists(present)
	if err != nil || !ok {
		t.Errorf("present: ok=%v err=%v", ok, err)
	}
	ok, err = fileExists(absent)
	if err != nil || ok {
		t.Errorf("absent: ok=%v err=%v", ok, err)
	}

	// EACCES path: unreadable parent must surface as error, not "absent".
	if os.Geteuid() == 0 {
		return
	}
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0000); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0700) })
	ok, err = fileExists(filepath.Join(blocked, "target"))
	if err == nil {
		t.Errorf("unreadable parent should surface error; got (%v, nil)", ok)
	}
}

// TestCopyKubeconfig verifies the destination-side semantics of
// copyKubeconfig: on a missing source it fails without leaving a
// partial destination; on success it produces a 0600-mode copy.
func TestCopyKubeconfig(t *testing.T) {
	dir := t.TempDir()
	dstDir := filepath.Join(dir, "dst")
	dstFile := filepath.Join(dstDir, "k3s.yaml")

	origDir, origFile := KubeconfigCopyDir, KubeconfigCopy
	KubeconfigCopyDir = dstDir
	KubeconfigCopy = dstFile
	t.Cleanup(func() {
		KubeconfigCopyDir, KubeconfigCopy = origDir, origFile
	})

	// state.K3sKubeconfig is a const path (/etc/rancher/k3s/k3s.yaml)
	// that most CI hosts don't have. When it's absent, copyKubeconfig
	// must fail cleanly with no partial dst leak.
	if _, err := os.Stat(state.K3sKubeconfig); errors.Is(err, os.ErrNotExist) {
		err := copyKubeconfig()
		if err == nil {
			t.Fatal("copyKubeconfig should fail when source is absent")
		}
		if _, err := os.Stat(dstFile); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("dst should not exist after failed copy; stat err=%v", err)
		}
		return
	}
	// If state.K3sKubeconfig happens to exist (CI machine with k3s),
	// verify the destination has correct permissions.
	if err := copyKubeconfig(); err != nil {
		t.Fatalf("copyKubeconfig: %v", err)
	}
	info, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("dst perm = %o, want 0600", info.Mode().Perm())
	}
}

// TestWaitKubeconfigTimeoutsCleanly verifies WaitKubeconfig
// respects ctx timeout when the kubeconfig never appears.
func TestWaitKubeconfigTimeoutsCleanly(t *testing.T) {
	orig := kubeconfigPollInterval
	kubeconfigPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { kubeconfigPollInterval = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := WaitKubeconfig(ctx)
	if err == nil {
		t.Skip("state.K3sKubeconfig exists on this host; cannot test the timeout path")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded in chain, got %v", err)
	}
}

// pod builds a kube-system pod fixture bound to a node.
func pod(name, node string, phase corev1.PodPhase, containersReady bool) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system"},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: phase},
	}
	if phase == corev1.PodRunning {
		st := corev1.ConditionFalse
		if containersReady {
			st = corev1.ConditionTrue
		}
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Ready: containersReady}}
		p.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.ContainersReady, Status: st,
		}}
	}
	return p
}

// TestCountPodsOnNodeIgnoresOtherNodes is the bug that cost a day.
//
// Node readiness is a node-local question, but the pod list is
// cluster-wide. Counting every kube-system pod means one node's
// readiness depends on pods belonging to other nodes — including a
// node deliberately being removed, whose DaemonSet pods stay Pending
// forever. edge-dev2 sat at 9/11 on kube-multus-ds and svclb-traefik
// pods bound to edge-dev3 while edge-dev3 was converting away, never
// reached RUNNING, and was rebooted every five minutes as a result.
func TestCountPodsOnNodeIgnoresOtherNodes(t *testing.T) {
	pods := []corev1.Pod{
		pod("coredns", "edge-dev2", corev1.PodRunning, true),
		pod("metrics-server", "edge-dev2", corev1.PodRunning, true),
		// The departing node's DaemonSet pods. Pending forever, and
		// none of edge-dev2's concern.
		pod("kube-multus-ds-5msrh", "edge-dev3", corev1.PodPending, false),
		pod("svclb-traefik-kc2n7", "edge-dev3", corev1.PodPending, false),
		// Not scheduled anywhere yet.
		pod("helm-install-traefik", "", corev1.PodPending, false),
	}

	ready, total, notReady := countPodsOnNode(pods, "edge-dev2")

	if total != 2 {
		t.Errorf("total = %d, want 2 — only this node's pods count", total)
	}
	if ready != 2 {
		t.Errorf("ready = %d, want 2", ready)
	}
	if len(notReady) != 0 {
		t.Errorf("notReady = %v, want empty — those pods belong to other nodes", notReady)
	}
	if ready != total {
		t.Error("this node would never report ready, which is the whole bug")
	}
}

// TestCountPodsOnNodeClassifies covers the local classification: a
// Running pod whose containers are not Ready is not ready, and a
// Succeeded pod (a completed install Job) is.
func TestCountPodsOnNodeClassifies(t *testing.T) {
	pods := []corev1.Pod{
		pod("done-job", "n1", corev1.PodSucceeded, false),
		pod("healthy", "n1", corev1.PodRunning, true),
		pod("starting", "n1", corev1.PodRunning, false),
		pod("pending", "n1", corev1.PodPending, false),
	}

	ready, total, notReady := countPodsOnNode(pods, "n1")

	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if ready != 2 {
		t.Errorf("ready = %d, want 2 (Succeeded + Running/ContainersReady)", ready)
	}
	if len(notReady) != 2 {
		t.Errorf("notReady = %v, want 2 entries", notReady)
	}
}

// TestDescribeNodeReady pins the diagnostic that decides whether a
// not-Ready node is a real node condition or a stale read. Both fields
// matter: the reason names the cause, and the resourceVersion is what
// reveals a frozen object when the reason looks innocuous.
func TestDescribeNodeReady(t *testing.T) {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-dev2", ResourceVersion: "4711"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{
				Type:    corev1.NodeReady,
				Status:  corev1.ConditionFalse,
				Reason:  "KubeletNotReady",
				Message: "container runtime network not ready",
			}},
		},
	}
	got := describeNodeReady(n)
	for _, want := range []string{
		"Ready=False", `reason="KubeletNotReady"`,
		"container runtime network not ready", "resourceVersion=4711",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("describeNodeReady missing %q\n  got: %s", want, got)
		}
	}

	// A node carrying no conditions at all is its own signal — a freshly
	// registered object that kubelet has not posted status for yet.
	bare := &corev1.Node{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1"}}
	if got := describeNodeReady(bare); !strings.Contains(got, "no Ready condition") ||
		!strings.Contains(got, "resourceVersion=1") {
		t.Errorf("bare node description unhelpful: %s", got)
	}
}

// TestGetNodeBoundedStopsWaitingOnAHungAPI is the bug in one test. A
// poll loop whose single call can block for the whole enclosing budget
// is not a poll loop: it polls once, logs nothing, and the silence reads
// as "not Ready" when the truth is "no answer". client-go sets no
// client-side deadline and rest.Config.Timeout is deliberately unset
// (it would also cut the informers' watches), so the bound has to come
// from a per-call context.
func TestGetNodeBoundedStopsWaitingOnAHungAPI(t *testing.T) {
	// A server that accepts the request and never replies, which is how
	// the real apiserver behaved after a cluster join.
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hung.Close()

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: hung.URL})
	if err != nil {
		t.Fatalf("build clientset: %v", err)
	}

	// The enclosing budget stands in for the readiness timeout: far
	// longer than one call should ever take.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	if _, err := getNodeBounded(ctx, cs, "edge-dev2"); err == nil {
		t.Fatal("expected an error from a hung apiserver")
	}
	elapsed := time.Since(start)

	if elapsed > apiCallBudget+5*time.Second {
		t.Errorf("getNodeBounded took %v; it must give up near apiCallBudget (%v) "+
			"rather than consume the enclosing budget", elapsed, apiCallBudget)
	}
	if ctx.Err() != nil {
		t.Error("the enclosing context was consumed; the per-call bound did not hold")
	}
}

// TestFailedReadyzChecks pins the parse that names what the apiserver is
// waiting on. This is the line that will distinguish "etcd not joined"
// from "informers not synced" from "apiserver fine, something else is
// wrong" — the distinction three reruns failed to establish.
func TestFailedReadyzChecks(t *testing.T) {
	body := strings.Join([]string{
		"[+]ping ok",
		"[+]log ok",
		"[-]etcd failed: reason withheld",
		"[+]informer-sync ok",
		"[-]poststarthook/start-kube-apiserver-admission-initializer failed: not finished",
		"readyz check failed",
	}, "\n")

	got := failedReadyzChecks(body)
	if len(got) != 2 {
		t.Fatalf("failedReadyzChecks returned %d entries, want 2: %v", len(got), got)
	}
	if !strings.Contains(got[0], "etcd") {
		t.Errorf("first failing check = %q, want it to name etcd", got[0])
	}
	if !strings.Contains(got[1], "poststarthook") {
		t.Errorf("second failing check = %q, want the poststarthook", got[1])
	}

	// An all-ok body must report nothing failing, so the probe line reads
	// "apiserver is fine" rather than inventing a culprit.
	if got := failedReadyzChecks("[+]ping ok\n[+]etcd ok\nreadyz check passed"); len(got) != 0 {
		t.Errorf("healthy body reported failures: %v", got)
	}
}

// TestKubeconfigChangedDetectsARewrite covers the stale-client case: a
// join replaces the kubeconfig with one carrying the cluster CA, and a
// client built before that fails every call at the TLS handshake, which
// surfaces only as a timeout.
func TestKubeconfigChangedDetectsARewrite(t *testing.T) {
	f := filepath.Join(t.TempDir(), "k3s.yaml")
	if err := os.WriteFile(f, []byte("before"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	builtAt := kubeconfigMtime(f)
	if builtAt == "" {
		t.Fatal("kubeconfigMtime returned empty for an existing file")
	}
	if got := kubeconfigChanged(f, builtAt); !strings.Contains(got, "unchanged") {
		t.Errorf("unmodified file reported as changed: %s", got)
	}

	// Rewrite with a distinctly later timestamp, as a join does.
	later := time.Now().Add(2 * time.Minute)
	if err := os.Chtimes(f, later, later); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	got := kubeconfigChanged(f, builtAt)
	if !strings.Contains(got, "KUBECONFIG-REWRITTEN") {
		t.Errorf("rewritten file not flagged: %s", got)
	}
}

// newFailingAPI returns a server that errors on every request, standing
// in for an apiserver our client cannot talk to.
func newFailingAPI(t *testing.T) kubernetes.Interface {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("build clientset: %v", err)
	}
	return cs
}

// TestWaitNodeReadyBailsOutWhenKubeconfigRotates covers the recovery
// half of the stale-client fix.
//
// A client embeds the CA it was built with, so once the kubeconfig is
// rewritten it can never succeed — it will fail the TLS handshake
// against a healthy apiserver until the readiness budget runs out. That
// is what cost edge-dev2 5m13s and a watchdog reboot. The wait must
// give up promptly and report errKubeconfigRotated so the caller
// rebuilds, rather than polling a client that is provably dead.
func TestWaitNodeReadyBailsOutWhenKubeconfigRotates(t *testing.T) {
	origInterval := nodeReadyPollInterval
	nodeReadyPollInterval = 10 * time.Millisecond
	defer func() { nodeReadyPollInterval = origInterval }()

	kubeconfig := filepath.Join(t.TempDir(), "k3s.yaml")
	if err := os.WriteFile(kubeconfig, []byte("pre-join"), 0600); err != nil {
		t.Fatalf("seed kubeconfig: %v", err)
	}
	builtAt := kubeconfigMtime(kubeconfig)

	// k3s rewrites it moments after the client was built, exactly as it
	// does when the node adopts the cluster CA.
	later := time.Now().Add(2 * time.Minute)
	if err := os.Chtimes(kubeconfig, later, later); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// A budget far larger than the bail-out should need, so consuming it
	// is itself the failure being guarded against.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	err := waitNodeReady(ctx, nil, newFailingAPI(t), "edge-dev2",
		kubeconfig, builtAt)
	if !errors.Is(err, errKubeconfigRotated) {
		t.Fatalf("expected errKubeconfigRotated, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to notice the rotation; it must bail out on the "+
			"first failed call, not burn the budget", elapsed)
	}
	if ctx.Err() != nil {
		t.Error("the enclosing budget was consumed instead of bailing out")
	}
}

// TestWaitNodeReadyKeepsPollingWhenKubeconfigIsStable is the other half:
// an unchanged kubeconfig must NOT trigger the rebuild path. A node that
// is merely slow to register looks the same from a failing Get, and
// rebuilding on that would turn a normal wait into a rebuild loop that
// exhausts the budget.
func TestWaitNodeReadyKeepsPollingWhenKubeconfigIsStable(t *testing.T) {
	origInterval := nodeReadyPollInterval
	nodeReadyPollInterval = 10 * time.Millisecond
	defer func() { nodeReadyPollInterval = origInterval }()

	kubeconfig := filepath.Join(t.TempDir(), "k3s.yaml")
	if err := os.WriteFile(kubeconfig, []byte("stable"), 0600); err != nil {
		t.Fatalf("seed kubeconfig: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := waitNodeReady(ctx, nil, newFailingAPI(t), "edge-dev2",
		kubeconfig, kubeconfigMtime(kubeconfig))
	if errors.Is(err, errKubeconfigRotated) {
		t.Fatal("reported a rotation for an unchanged kubeconfig")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the wait to run to its deadline, got %v", err)
	}
}
