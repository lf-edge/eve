// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

const (
	testNvidiaManifest = "apiVersion: apps/v1\nkind: DaemonSet\n# nvidia\n"
	testNvidiaCDISpec  = "cdiVersion: 0.5.0\nkind: nvidia.com/gpu\ndevices: []\n"
)

// fakeNodeLabels stands in for this node's labels on the API server.
type fakeNodeLabels struct {
	labels         map[string]string
	gets, patches  int
	getErr, setErr error
}

type nvidiaFixture struct {
	platform string // fake /opt/vendor/nvidia/eve-platform
	module   string // fake /sys/module/nvidia
	etcCDI   string // fake /etc/cdi
	runCDI   string // fake /run/cdi
	dst      string // k3s auto-deploy dir
	node     *fakeNodeLabels
}

// redirectNvidiaGPU points the reconcile at a temp tree: the manifest
// pkg/kube ships, empty CDI dirs, an empty auto-deploy dir, and no
// eve-platform file or nvidia module until a test adds them. The node's
// labels live in memory.
func redirectNvidiaGPU(t *testing.T) nvidiaFixture {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "k3s-manifests")
	f := nvidiaFixture{
		platform: filepath.Join(root, "vendor", "eve-platform"),
		module:   filepath.Join(root, "sys-module", "nvidia"),
		etcCDI:   filepath.Join(root, "etc-cdi"),
		runCDI:   filepath.Join(root, "run-cdi"),
		dst:      filepath.Join(root, "manifests-dst"),
		node:     &fakeNodeLabels{labels: map[string]string{}},
	}
	for _, dir := range []string{src, f.etcCDI, f.runCDI, f.dst, filepath.Dir(f.platform), filepath.Dir(f.module)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	writeFile(t, filepath.Join(src, nvidiaPluginManifestName), testNvidiaManifest)

	oldSrc, oldPlatform, oldModule, oldCDI := nvidiaManifestsSrc, NvidiaPlatformFile, NvidiaModuleDir, NvidiaCDISpecDirs
	oldGet, oldSet, oldCleared := nvidiaGetNodeLabel, nvidiaSetNodeLabel, nvidiaLabelCleared
	nvidiaManifestsSrc, NvidiaPlatformFile, NvidiaModuleDir = src, f.platform, f.module
	NvidiaCDISpecDirs = []string{f.etcCDI, f.runCDI}
	n := f.node
	nvidiaGetNodeLabel = func(context.Context) (string, bool, error) {
		n.gets++
		if n.getErr != nil {
			return "", false, n.getErr
		}
		v, ok := n.labels[NvidiaGPUNodeLabel]
		return v, ok, nil
	}
	nvidiaSetNodeLabel = func(_ context.Context, on bool) error {
		n.patches++
		if n.setErr != nil {
			return n.setErr
		}
		if on {
			n.labels[NvidiaGPUNodeLabel] = "true"
		} else {
			delete(n.labels, NvidiaGPUNodeLabel)
		}
		return nil
	}
	nvidiaLabelCleared = false
	t.Cleanup(func() {
		nvidiaManifestsSrc, NvidiaPlatformFile, NvidiaModuleDir, NvidiaCDISpecDirs = oldSrc, oldPlatform, oldModule, oldCDI
		nvidiaGetNodeLabel, nvidiaSetNodeLabel, nvidiaLabelCleared = oldGet, oldSet, oldCleared
	})
	return f
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// setPlatform stands in for pkg/nvidia's eve-platform file.
func (f nvidiaFixture) setPlatform(t *testing.T, platform string) {
	t.Helper()
	writeFile(t, f.platform, platform+"\n")
}

// loadModule stands in for nvidia.ko being loaded.
func (f nvidiaFixture) loadModule(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(f.module, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", f.module, err)
	}
}

// usable makes this node an NVIDIA GPU node for the platform: module loaded
// and the CDI spec in place, static for Jetson, generated for ai-generic.
func (f nvidiaFixture) usable(t *testing.T, platform string) {
	t.Helper()
	f.setPlatform(t, platform)
	f.loadModule(t)
	if platform == "ai-generic" {
		writeFile(t, filepath.Join(f.runCDI, "nvidia.yaml"), testNvidiaCDISpec)
	} else {
		writeFile(t, filepath.Join(f.etcCDI, "jetson-orin.yaml"), testNvidiaCDISpec)
	}
}

func (f nvidiaFixture) labelled() bool {
	return f.node.labels[NvidiaGPUNodeLabel] == "true"
}

func (f nvidiaFixture) staged(t *testing.T) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dst, nvidiaPluginManifestName))
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read staged manifest: %v", err)
	}
	return string(data), true
}

func (f nvidiaFixture) reconcile(t *testing.T) error {
	t.Helper()
	return reconcileNvidiaGPU(context.Background(), f.dst)
}

// Every NVIDIA platform stages the same manifest and labels a usable node.
func TestReconcileNvidiaGPU_EveryPlatformStagesManifestAndLabels(t *testing.T) {
	for _, p := range []string{"nvidia-jp5", "nvidia-jp6", "nvidia-jp7", "nvidia-gb", "ai-generic"} {
		t.Run(p, func(t *testing.T) {
			f := redirectNvidiaGPU(t)
			f.usable(t, p)
			if err := f.reconcile(t); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if got, ok := f.staged(t); !ok || got != testNvidiaManifest {
				t.Errorf("staged %q (present=%v), want the NVIDIA manifest", got, ok)
			}
			if !f.labelled() {
				t.Error("node with its module and CDI spec not labelled")
			}
		})
	}
}

// The manifest is staged whether or not a GPU is usable: the DaemonSet's
// nodeSelector is what keeps the pod off nodes without one.
func TestReconcileNvidiaGPU_StagesManifestWithoutUsableGPU(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := f.staged(t); !ok {
		t.Error("manifest not staged")
	}
	if f.labelled() {
		t.Error("labelled a node without a usable GPU")
	}
}

func TestReconcileNvidiaGPU_NoModuleIsNotLabelled(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	writeFile(t, filepath.Join(f.runCDI, "nvidia.yaml"), testNvidiaCDISpec)
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.labelled() {
		t.Error("labelled a node whose nvidia module is not loaded")
	}
}

func TestReconcileNvidiaGPU_NoCDISpecIsNotLabelled(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "nvidia-jp6")
	f.loadModule(t)
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.labelled() {
		t.Error("labelled a node without an NVIDIA CDI spec")
	}
}

// A CDI spec for another vendor's devices does not make an NVIDIA GPU usable.
func TestReconcileNvidiaGPU_OtherVendorCDISpecDoesNotCount(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	f.loadModule(t)
	writeFile(t, filepath.Join(f.etcCDI, "vendor.yaml"), "cdiVersion: 0.5.0\nkind: vendor.com/device\n")
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.labelled() {
		t.Error("labelled a node whose only CDI spec is another vendor's")
	}
}

// A driver that comes up late, or a GPU fitted later, is picked up on a
// later tick: that is why the reconcile runs on every one.
func TestReconcileNvidiaGPU_LabelFollowsLateCDISpec(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	f.loadModule(t)
	if err := f.reconcile(t); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if f.labelled() {
		t.Fatal("labelled before the CDI spec existed")
	}
	writeFile(t, filepath.Join(f.runCDI, "nvidia.yaml"), testNvidiaCDISpec)
	if err := f.reconcile(t); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if !f.labelled() {
		t.Error("not labelled once the CDI spec appeared")
	}
}

func TestReconcileNvidiaGPU_RemovesLabelWhenNoLongerUsable(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	f.node.labels[NvidiaGPUNodeLabel] = "true"
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.labelled() {
		t.Error("label kept on a node without a usable GPU")
	}
}

func TestReconcileNvidiaGPU_NoPatchWhenLabelMatches(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.usable(t, "ai-generic")
	f.node.labels[NvidiaGPUNodeLabel] = "true"
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.node.patches != 0 {
		t.Errorf("patched the node %d times, want 0", f.node.patches)
	}
}

func TestReconcileNvidiaGPU_ReturnsLabelPatchError(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.usable(t, "ai-generic")
	f.node.setErr = errors.New("api down")
	if err := f.reconcile(t); err == nil {
		t.Fatal("expected the patch error to be returned")
	}
}

func TestReconcileNvidiaGPU_RewritesChangedManifest(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	writeFile(t, filepath.Join(f.dst, nvidiaPluginManifestName), "stale")
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got, _ := f.staged(t); got != testNvidiaManifest {
		t.Errorf("staged %q, want the manifest this image ships", got)
	}
}

// Older EVE versions staged the manifest under a versioned name; left in
// place, k3s would keep applying its stale DaemonSet.
func TestReconcileNvidiaGPU_RemovesLegacyManifests(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "nvidia-jp6")
	legacy := []string{"nvidia-device-plugin-18.0.yml", "nvidia-device-plugin-18.0-dgpu.yml"}
	for _, name := range legacy {
		writeFile(t, filepath.Join(f.dst, name), "old")
	}
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, name := range legacy {
		if _, err := os.Stat(filepath.Join(f.dst, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("legacy manifest %s still present (err=%v)", name, err)
		}
	}
	if got, _ := f.staged(t); got != testNvidiaManifest {
		t.Errorf("staged %q, want the NVIDIA manifest", got)
	}
}

// Before k3s starts the manifest is refreshed with no API server to label
// the node with.
func TestStageNvidiaManifest_StagesWithoutTouchingLabel(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "nvidia-jp6")
	writeFile(t, filepath.Join(f.dst, nvidiaPluginManifestName), "stale")
	writeFile(t, filepath.Join(f.dst, "nvidia-device-plugin-18.0.yml"), "old")
	if err := stageNvidiaManifest(f.dst); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got, _ := f.staged(t); got != testNvidiaManifest {
		t.Errorf("staged %q, want the NVIDIA manifest", got)
	}
	if _, err := os.Stat(filepath.Join(f.dst, "nvidia-device-plugin-18.0.yml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy manifest still present (err=%v)", err)
	}
	if f.node.gets != 0 || f.node.patches != 0 {
		t.Errorf("node label accessed: gets=%d patches=%d", f.node.gets, f.node.patches)
	}
}

func TestStageNvidiaManifest_NoNvidiaUserlandStagesNothing(t *testing.T) {
	f := redirectNvidiaGPU(t)
	if err := stageNvidiaManifest(f.dst); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, ok := f.staged(t); ok {
		t.Error("staged a manifest on an image without an NVIDIA userland")
	}
}

// The auto-deploy dir belongs to the k3s server; until it exists there is
// nothing to stage into, and the next tick retries.
func TestReconcileNvidiaGPU_WaitsForK3sManifestsDir(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	if err := os.RemoveAll(f.dst); err != nil {
		t.Fatalf("remove dst: %v", err)
	}
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := os.Stat(f.dst); !errors.Is(err, os.ErrNotExist) {
		t.Error("created the k3s auto-deploy dir")
	}
}

// An unreadable CDI dir is an error, not "no GPU": treating it as the latter
// would take the plugin away from a GPU node.
func TestReconcileNvidiaGPU_UnreadableCDIDirKeepsLabel(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "ai-generic")
	f.loadModule(t)
	f.node.labels[NvidiaGPUNodeLabel] = "true"
	if err := os.RemoveAll(f.runCDI); err != nil {
		t.Fatalf("remove run cdi: %v", err)
	}
	writeFile(t, f.runCDI, "not a directory")
	if err := f.reconcile(t); err == nil {
		t.Fatal("expected an error for an unreadable CDI dir")
	}
	if !f.labelled() || f.node.patches != 0 {
		t.Errorf("label changed on a read error: labelled=%v patches=%d", f.labelled(), f.node.patches)
	}
}

// A missing CDI dir is simply "no spec there": /run/cdi exists only once
// nv-init has written to it.
func TestReconcileNvidiaGPU_MissingCDIDirIsNoSpec(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.setPlatform(t, "nvidia-jp6")
	f.loadModule(t)
	writeFile(t, filepath.Join(f.etcCDI, "jetson-orin.yaml"), testNvidiaCDISpec)
	if err := os.RemoveAll(f.runCDI); err != nil {
		t.Fatalf("remove run cdi: %v", err)
	}
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !f.labelled() {
		t.Error("a missing /run/cdi hid the static Jetson spec")
	}
}

func TestReconcileNvidiaGPU_UnreadablePlatformFileIsAnError(t *testing.T) {
	f := redirectNvidiaGPU(t)
	if err := os.MkdirAll(f.platform, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f.node.labels[NvidiaGPUNodeLabel] = "true"
	if err := f.reconcile(t); err == nil {
		t.Fatal("expected an error for an unreadable eve-platform")
	}
	if !f.labelled() || f.node.patches != 0 {
		t.Errorf("label changed on a read error: labelled=%v patches=%d", f.labelled(), f.node.patches)
	}
}

// On an image without an NVIDIA userland there is nothing to stage; only a
// label left by an earlier image is removed, once.
func TestReconcileNvidiaGPU_NoNvidiaUserlandStagesNothing(t *testing.T) {
	f := redirectNvidiaGPU(t)
	if err := f.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := f.staged(t); ok {
		t.Error("staged a manifest on an image without an NVIDIA userland")
	}
	if f.labelled() {
		t.Error("labelled a node on an image without an NVIDIA userland")
	}
}

func TestReconcileNvidiaGPU_NoNvidiaUserlandClearsStaleLabelOnce(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.node.labels[NvidiaGPUNodeLabel] = "true"
	for i := 0; i < 3; i++ {
		if err := f.reconcile(t); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	if f.labelled() {
		t.Error("stale label kept")
	}
	if f.node.gets != 1 || f.node.patches != 1 {
		t.Errorf("gets=%d patches=%d, want 1 and 1", f.node.gets, f.node.patches)
	}
}

func TestReconcileNvidiaGPU_NoNvidiaUserlandRetriesUntilChecked(t *testing.T) {
	f := redirectNvidiaGPU(t)
	f.node.getErr = errors.New("api not ready")
	if err := f.reconcile(t); err == nil {
		t.Fatal("expected the API error on the first tick")
	}
	f.node.getErr = nil
	if err := f.reconcile(t); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if f.node.gets != 2 {
		t.Errorf("gets=%d, want 2: a failed check must be retried", f.node.gets)
	}
}

// The DaemonSet's nodeSelector and the label kube-init sets are defined in
// different files; nothing else ties them together.
func TestNvidiaManifestSelectsNodeLabel(t *testing.T) {
	name := nvidiaPluginManifestName
	data, err := os.ReadFile(filepath.Join("..", "..", "nvidia-container-runtime", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var ds appsv1.DaemonSet
	for _, doc := range strings.Split(string(data), "\n---\n") {
		if err := yaml.Unmarshal([]byte(doc), &ds); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if ds.Kind == "DaemonSet" {
			break
		}
	}
	if ds.Kind != "DaemonSet" {
		t.Fatalf("%s declares no DaemonSet", name)
	}
	if got := ds.Spec.Template.Spec.NodeSelector[NvidiaGPUNodeLabel]; got != "true" {
		t.Errorf("%s nodeSelector[%s] = %q, want \"true\"", name, NvidiaGPUNodeLabel, got)
	}
}

// nodesAt is the Nodes client of an apiserver served by handler.
func nodesAt(t *testing.T, handler http.HandlerFunc) typedcorev1.NodeInterface {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("build clientset: %v", err)
	}
	return cs.CoreV1().Nodes()
}

// hungAPI accepts every request and never answers. It drains the body
// first: until it does, the server cannot notice the client hanging up, so
// the request context would never end and the server could not close.
func hungAPI(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	<-r.Context().Done()
}

// shortNvidiaAPICallBudget shrinks the per-call bound so a hung call costs
// the test a fraction of a second.
func shortNvidiaAPICallBudget(t *testing.T) {
	t.Helper()
	old := nvidiaAPICallBudget
	nvidiaAPICallBudget = 200 * time.Millisecond
	t.Cleanup(func() { nvidiaAPICallBudget = old })
}

// workerContext stands in for the health worker's context: it outlives any
// single call by far.
func workerContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The reconcile runs on the health worker's context, which has no
// deadline, and the worker runs its ticks one at a time. A label call that
// waits on a hung apiserver for as long as that context lives parks every
// later tick behind it, so each call has to give up on its own.
func TestNvidiaNodeLabelGetGivesUpOnAHungAPI(t *testing.T) {
	shortNvidiaAPICallBudget(t)
	nodes := nodesAt(t, hungAPI)
	ctx := workerContext(t)

	start := time.Now()
	if _, _, err := getNodeNvidiaLabel(ctx, nodes, "node"); err == nil {
		t.Fatal("expected an error from a hung apiserver")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("label Get took %v; it must give up near nvidiaAPICallBudget (%v)",
			elapsed, nvidiaAPICallBudget)
	}
	if ctx.Err() != nil {
		t.Error("the worker's context ran out; the per-call bound did not hold")
	}
}

func TestNvidiaNodeLabelPatchGivesUpOnAHungAPI(t *testing.T) {
	shortNvidiaAPICallBudget(t)
	nodes := nodesAt(t, hungAPI)
	ctx := workerContext(t)

	start := time.Now()
	if err := patchNodeNvidiaLabel(ctx, nodes, "node", true); err == nil {
		t.Fatal("expected an error from a hung apiserver")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("label Patch took %v; it must give up near nvidiaAPICallBudget (%v)",
			elapsed, nvidiaAPICallBudget)
	}
	if ctx.Err() != nil {
		t.Error("the worker's context ran out; the per-call bound did not hold")
	}
}

// The label calls against a live apiserver: Get reads the label, Patch
// sets it to "true" and removes it with a null in a JSON merge patch.
func TestNvidiaNodeLabelRoundTripsThroughTheAPI(t *testing.T) {
	var patches []string
	nodes := nodesAt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			patches = append(patches, r.Header.Get("Content-Type")+" "+string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"Node","apiVersion":"v1","metadata":{"name":"node",`+
			`"labels":{"`+NvidiaGPUNodeLabel+`":"true"}}}`)
	})
	ctx := workerContext(t)

	value, has, err := getNodeNvidiaLabel(ctx, nodes, "node")
	if err != nil || !has || value != "true" {
		t.Fatalf("Get = %q, %v, %v; want \"true\", true, nil", value, has, err)
	}
	if err := patchNodeNvidiaLabel(ctx, nodes, "node", true); err != nil {
		t.Fatalf("Patch on: %v", err)
	}
	if err := patchNodeNvidiaLabel(ctx, nodes, "node", false); err != nil {
		t.Fatalf("Patch off: %v", err)
	}
	want := []string{
		`application/merge-patch+json {"metadata":{"labels":{"` + NvidiaGPUNodeLabel + `":"true"}}}`,
		`application/merge-patch+json {"metadata":{"labels":{"` + NvidiaGPUNodeLabel + `":null}}}`,
	}
	if len(patches) != len(want) || patches[0] != want[0] || patches[1] != want[1] {
		t.Errorf("patches = %q; want %q", patches, want)
	}
}
