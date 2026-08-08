// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/kube/kube-init/versions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const (
	longhornUninstallSettings = "/etc/longhorn_uninstall_settings.yaml"
	longhornUninstallJobURL   = "https://raw.githubusercontent.com/longhorn/longhorn/" +
		versions.Longhorn + "/uninstall/uninstall.yaml"
	longhornDeployURL = "https://raw.githubusercontent.com/longhorn/longhorn/" +
		versions.Longhorn + "/deploy/longhorn.yaml"

	longhornUninstallMaxPolls     = 1000
	longhornUninstallPollInterval = 5 * time.Second

	replicatedStorageUninstallComplete state.Marker = "/var/lib/replicated-storage-uninstall-complete"
)

// storageClassGVR is the CRD-less storage class resource. Used for
// listing and deleting per-provisioner storage classes.
var storageClassGVR = schema.GroupVersionResource{
	Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses",
}

// ErrLonghornUninstallTimedOut is returned by UninstallLonghorn
// when the uninstall Job did not complete inside the poll budget.
var ErrLonghornUninstallTimedOut = errors.New("longhorn uninstall job did not complete within poll budget")

// UninstallAll runs the full K3sBase conversion.
func UninstallAll(ctx context.Context) error {
	log.Printf("starting component uninstall for K3sBase conversion")

	if err := state.Mark(longhornUninstallGuard); err != nil {
		return fmt.Errorf("mark uninstall in progress: %w", err)
	}
	if err := waitForAPIServer(ctx); err != nil {
		return fmt.Errorf("wait for API server: %w", err)
	}
	if err := waitForAllNodesReady(ctx); err != nil {
		return fmt.Errorf("wait for nodes ready: %w", err)
	}

	for _, step := range []struct {
		name string
		fn   func(context.Context) error
	}{
		{"descheduler", UninstallDescheduler},
		{"longhorn", UninstallLonghorn},
		{"cdi", UninstallCDI},
		{"kubevirt", UninstallKubeVirt},
		{"multus", UninstallMultus},
	} {
		err := step.fn(ctx)
		if err == nil {
			continue
		}
		if errors.Is(err, ErrLonghornUninstallTimedOut) {
			return fmt.Errorf("%s uninstall: %w", step.name, err)
		}
		log.Printf("warning: %s uninstall: %v", step.name, err)
	}

	if err := state.Unmark(longhornUninstallGuard); err != nil {
		log.Printf("warning: unmark uninstall guard: %v", err)
	}
	if err := state.Mark(state.NativeKubernetesMode); err != nil {
		return fmt.Errorf("mark native-kubernetes-mode: %w", err)
	}
	if err := state.Mark(replicatedStorageUninstallComplete); err != nil {
		log.Printf("warning: mark uninstall complete: %v", err)
	}
	log.Printf("component uninstall complete, native-kubernetes-mode set")
	return nil
}

// UninstallDescheduler removes descheduler RBAC and the policy
// ConfigMap. Delete failures are warnings (best-effort cleanup).
func UninstallDescheduler(ctx context.Context) error {
	log.Printf("uninstalling descheduler")
	kc := kubeclient.Default()
	for _, f := range []string{deschedulerRBAC, deschedulerPolicy} {
		if err := kubectlx.DeleteFile(ctx, kc, f); err != nil {
			log.Printf("warning: delete %s: %v", f, err)
		}
	}
	log.Printf("descheduler uninstall complete")
	return nil
}

// UninstallLonghorn performs the full Longhorn teardown.
func UninstallLonghorn(ctx context.Context) error {
	log.Printf("uninstalling Longhorn")

	longhornPostInstallConfigClean()

	kc := kubeclient.Default()
	if err := kubectlx.ApplyFile(ctx, kc,
		longhornUninstallSettings, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply longhorn uninstall settings: %w", err)
	}
	if err := kubectlx.ApplyURL(ctx, kc,
		longhornUninstallJobURL, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("create longhorn uninstall job: %w", err)
	}
	if err := waitForLonghornUninstallJob(ctx); err != nil {
		return fmt.Errorf("wait for longhorn uninstall job: %w", err)
	}

	for _, url := range []string{longhornDeployURL, longhornUninstallJobURL} {
		if err := kubectlx.DeleteURL(ctx, kc, url); err != nil {
			log.Printf("warning: delete %s: %v", url, err)
		}
	}
	if err := deleteLonghornStorageClasses(ctx); err != nil {
		log.Printf("warning: delete longhorn storage classes: %v", err)
	}
	if err := state.Unmark(state.LonghornInitialized); err != nil {
		log.Printf("warning: unmark longhorn initialized: %v", err)
	}
	log.Printf("Longhorn uninstall complete")
	return nil
}

// UninstallCDI removes the CDI CR and operator.
func UninstallCDI(ctx context.Context) error {
	log.Printf("uninstalling CDI")
	kc := kubeclient.Default()
	cdiOperatorURL := fmt.Sprintf(
		"https://github.com/kubevirt/containerized-data-importer/releases/download/%s/cdi-operator.yaml",
		cdiVersion)
	cdiCRURL := fmt.Sprintf(
		"https://github.com/kubevirt/containerized-data-importer/releases/download/%s/cdi-cr.yaml",
		cdiVersion)
	for _, url := range []string{cdiCRURL, cdiOperatorURL} {
		if err := kubectlx.DeleteURL(ctx, kc, url); err != nil {
			log.Printf("warning: delete %s: %v", url, err)
		}
	}
	log.Printf("CDI uninstall complete")
	return nil
}

// UninstallKubeVirt removes the KubeVirt CR, operator, API services,
// webhooks, and every kubevirt.io label from every node.
func UninstallKubeVirt(ctx context.Context) error {
	log.Printf("uninstalling KubeVirt")
	kc := kubeclient.Default()

	// Delete the KubeVirt CR.
	if err := kubectlx.IgnoreNotFound(
		kc.Dynamic.Resource(kubectlx.KubeVirtGVR).Namespace(kubectlx.KubeVirtNamespace).
			Delete(ctx, "kubevirt", metav1.DeleteOptions{})); err != nil {
		log.Printf("warning: delete kubevirt CR: %v", err)
	}

	// Delete the kubevirt APIService.
	apiservicesGVR := schema.GroupVersionResource{
		Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices",
	}
	if err := kubectlx.IgnoreNotFound(
		kc.Dynamic.Resource(apiservicesGVR).
			Delete(ctx, "v1.subresources.kubevirt.io", metav1.DeleteOptions{})); err != nil {
		log.Printf("warning: delete kubevirt apiservice: %v", err)
	}

	// Delete every KubeVirt admission-webhook configuration by name.
	if err := kubectlx.IgnoreNotFound(
		kc.Clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().
			Delete(ctx, "virt-api-mutator", metav1.DeleteOptions{})); err != nil {
		log.Printf("warning: delete virt-api-mutator: %v", err)
	}
	for _, name := range []string{"virt-operator-validator", "virt-api-validator"} {
		if err := kubectlx.IgnoreNotFound(
			kc.Clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().
				Delete(ctx, name, metav1.DeleteOptions{})); err != nil {
			log.Printf("warning: delete %s: %v", name, err)
		}
	}

	// Delete the operator manifest (does not wait — virt-operator pods
	// sometimes hang after API resources are gone).
	if err := kubectlx.DeleteFile(ctx, kc, kubevirtOperator); err != nil {
		log.Printf("warning: delete kubevirt operator: %v", err)
	}
	if err := removeKubeVirtNodeLabels(ctx); err != nil {
		log.Printf("warning: remove kubevirt node labels: %v", err)
	}
	if err := state.Unmark(state.KubevirtInitialized); err != nil {
		log.Printf("warning: unmark kubevirt initialized: %v", err)
	}
	log.Printf("KubeVirt uninstall complete")
	return nil
}

// UninstallMultus removes the Multus DaemonSet and the
// initialization marker.
func UninstallMultus(ctx context.Context) error {
	log.Printf("uninstalling Multus")
	if err := kubectlx.DeleteFile(ctx, kubeclient.Default(), MultusYAMLDst); err != nil {
		log.Printf("warning: delete multus daemonset: %v", err)
	}
	if err := state.Unmark(state.MultusInitialized); err != nil {
		log.Printf("warning: unmark multus initialized: %v", err)
	}
	log.Printf("Multus uninstall complete")
	return nil
}

// CleanupStorageClasses removes storage-classes.yaml, the k3s AddOn,
// and the lh-sc-rep1 storage class.
func CleanupStorageClasses(ctx context.Context) error {
	log.Printf("cleaning up storage classes")
	scManifest := filepath.Join(manifestsDst, "storage-classes.yaml")
	if err := os.Remove(scManifest); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove %s: %v", scManifest, err)
	}
	kc := kubeclient.Default()

	// Delete the k3s AddOn CR that installs storage-classes.
	if err := kubectlx.IgnoreNotFound(
		kc.Dynamic.Resource(kubectlx.AddonGVR).Namespace("kube-system").
			Delete(ctx, "storage-classes", metav1.DeleteOptions{})); err != nil {
		log.Printf("warning: delete storage-classes AddOn: %v", err)
	}
	if err := kubectlx.IgnoreNotFound(
		kc.Clientset.StorageV1().StorageClasses().
			Delete(ctx, "lh-sc-rep1", metav1.DeleteOptions{})); err != nil {
		log.Printf("warning: delete lh-sc-rep1 storage class: %v", err)
	}
	log.Printf("storage classes cleanup complete")
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// waitForAPIServer polls the ServerVersion endpoint until it succeeds.
// The endpoint is unauthenticated on k3s (returns version regardless
// of RBAC) so a dial success == API server is up.
func waitForAPIServer(ctx context.Context) error {
	log.Printf("waiting for API server...")
	disco := kubeclient.Default().Discovery
	for {
		if _, err := disco.ServerVersion(); err == nil {
			log.Printf("API server is available")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for API server: %w", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

// waitForAllNodesReady polls until every node reports Ready=True.
func waitForAllNodesReady(ctx context.Context) error {
	log.Printf("waiting for all nodes to be Ready...")
	for {
		ready, err := allNodesReady(ctx)
		if err == nil && ready {
			log.Printf("all nodes are Ready")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for nodes: %w", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

// allNodesReady reports whether every node reports Ready=True.
// Empty node list is treated as an error so a transient API miss
// doesn't pass.
func allNodesReady(ctx context.Context) (bool, error) {
	list, err := kubeclient.Default().Clientset.CoreV1().
		Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	if len(list.Items) == 0 {
		return false, fmt.Errorf("no nodes found")
	}
	for i := range list.Items {
		if !kubectlx.IsNodeReady(&list.Items[i]) {
			return false, nil
		}
	}
	return true, nil
}

// waitForLonghornUninstallJob polls the longhorn-uninstall Job's
// .status.succeeded until it equals 1 or the poll budget is exhausted.
func waitForLonghornUninstallJob(ctx context.Context) error {
	log.Printf("waiting for Longhorn uninstall job (max %d polls × %v)...",
		longhornUninstallMaxPolls, longhornUninstallPollInterval)
	jobsClient := kubeclient.Default().Clientset.BatchV1().Jobs(kubectlx.LonghornNamespace)
	for i := 0; i < longhornUninstallMaxPolls; i++ {
		j, err := jobsClient.Get(ctx, "longhorn-uninstall", metav1.GetOptions{})
		if err == nil && j.Status.Succeeded >= 1 {
			log.Printf("Longhorn uninstall job succeeded after %d polls", i+1)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for longhorn uninstall job: %w", ctx.Err())
		case <-time.After(longhornUninstallPollInterval):
		}
	}
	return fmt.Errorf("%w: %d polls × %v",
		ErrLonghornUninstallTimedOut,
		longhornUninstallMaxPolls, longhornUninstallPollInterval)
}

// longhornPostInstallConfigClean removes the runtime longhorn-cfg
// from the auto-deploy dir.
func longhornPostInstallConfigClean() {
	cfgPath := filepath.Join(manifestsDst, "longhorn-cfg.yaml")
	if err := os.Remove(cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove %s: %v", cfgPath, err)
	}
}

// deleteLonghornStorageClasses removes every storage class whose
// provisioner is driver.longhorn.io.
func deleteLonghornStorageClasses(ctx context.Context) error {
	scClient := kubeclient.Default().Clientset.StorageV1().StorageClasses()
	list, err := scClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list storage classes: %w", err)
	}
	for _, sc := range list.Items {
		if sc.Provisioner != "driver.longhorn.io" {
			continue
		}
		if err := kubectlx.IgnoreNotFound(
			scClient.Delete(ctx, sc.Name, metav1.DeleteOptions{})); err != nil {
			log.Printf("warning: delete storage class %s: %v", sc.Name, err)
		}
	}
	return nil
}

// removeKubeVirtNodeLabels deletes every label containing
// "kubevirt.io" from every node. Per-node failures are collected and
// returned together via errors.Join so the caller sees which nodes
// still carry stale labels.
func removeKubeVirtNodeLabels(ctx context.Context) error {
	nodes := kubeclient.Default().Clientset.CoreV1().Nodes()
	list, err := nodes.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("get node names: %w", err)
	}
	var errs []error
	for _, n := range list.Items {
		removals := kubeVirtLabelsToRemove(n.Labels)
		if len(removals) == 0 {
			continue
		}
		// Build a merge patch that sets each target label to null —
		// the Kubernetes-JSON convention for "remove this key".
		labelPatch := make(map[string]any, len(removals))
		for _, k := range removals {
			labelPatch[k] = nil
		}
		patchBody := map[string]any{
			"metadata": map[string]any{"labels": labelPatch},
		}
		patchJSON, err := json.Marshal(patchBody)
		if err != nil {
			errs = append(errs, fmt.Errorf("node %q: build label patch: %w", n.Name, err))
			continue
		}
		if _, err := nodes.Patch(ctx, n.Name,
			types.MergePatchType, patchJSON, metav1.PatchOptions{}); err != nil {
			errs = append(errs, fmt.Errorf("node %q: %w", n.Name, err))
		}
	}
	return errors.Join(errs...)
}

// kubeVirtLabelsToRemove returns the label keys containing "kubevirt.io".
func kubeVirtLabelsToRemove(labels map[string]string) []string {
	var out []string
	for key := range labels {
		if strings.Contains(key, "kubevirt.io") {
			out = append(out, key)
		}
	}
	return out
}
