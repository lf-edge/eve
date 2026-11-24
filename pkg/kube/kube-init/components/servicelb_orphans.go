// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	servicelbNamespace = "kube-system"
	// Labels k3s's servicelb puts on every DaemonSet it creates.
	servicelbSvcNameLabel      = "svccontroller.k3s.cattle.io/svcname"
	servicelbSvcNamespaceLabel = "svccontroller.k3s.cattle.io/svcnamespace"
	// servicelbSysctl is allowlisted on the kubelet only while servicelb
	// is enabled.
	servicelbSysctl = "net.ipv4.ip_forward"

	traefikRelease     = "traefik"
	lbCleanupFinalizer = "service.kubernetes.io/load-balancer-cleanup"
)

var helmChartGVR = schema.GroupVersionResource{
	Group: "helm.cattle.io", Version: "v1", Resource: "helmcharts",
}

// vars so tests can shorten them.
var (
	// servicelbPassBudget bounds a whole pass, so the serial health
	// worker is never held for long; servicelbAPICallBudget bounds
	// each call within it.
	servicelbPassBudget    = 30 * time.Second
	servicelbAPICallBudget = 10 * time.Second
	// lbFinalizerGrace leaves a terminating Traefik Service to a
	// load-balancer provider (kube-vip-cloud-provider) before its
	// finalizer is removed.
	lbFinalizerGrace = 2 * time.Minute
)

// ServiceLBCleanup removes what k3s's servicelb and packaged Traefik left
// behind once they were disabled; see docs/EVE-K.md. Nothing in k3s does:
// servicelb's DaemonSets have no owner and their pods fail with
// SysctlForbidden, and the Traefik Service stays stuck on the finalizer
// the cloud-controller-manager would have removed.
//
// Run is called on every health tick but only works until a pass
// settles; Reset, called on every k3s start, arms it again.
type ServiceLBCleanup struct {
	settled atomic.Bool // Reset runs on the event loop, Run on the worker.
	noted   string      // last message logged; touched only by Run.
}

// Reset arms the cleanup for another round of passes.
func (c *ServiceLBCleanup) Reset() {
	c.settled.Store(false)
}

// Run does one pass unless an earlier one settled.
func (c *ServiceLBCleanup) Run(ctx context.Context) {
	if c.settled.Load() || !kubeclient.HasDefault() {
		return
	}
	kc := kubeclient.Default()
	c.run(ctx, kc.Clientset, kc.Dynamic, time.Now())
}

func (c *ServiceLBCleanup) run(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) {
	if c.settled.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, servicelbPassBudget)
	defer cancel()
	res := cleanupServiceLBOrphans(ctx, cs, dyn, now)
	msg := res.reason
	if res.err != nil {
		msg = "WARNING: " + res.err.Error()
	}
	// Once per change, so a lasting condition is not logged every tick.
	if msg != c.noted {
		c.noted = msg
		if msg != "" {
			log.Printf("servicelb orphan cleanup: %s", msg)
		}
	}
	c.settled.Store(res.settled && res.err == nil)
}

// passResult is the outcome of one pass. settled means there is nothing
// more to do, or nothing this node may do, until the next k3s start.
// reason says why the pass held back.
type passResult struct {
	settled bool
	reason  string
	err     error
}

func cleanupServiceLBOrphans(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) passResult {
	daemonSets, err := listServiceLBDaemonSets(ctx, cs)
	if err != nil {
		return passResult{err: err}
	}
	svc, err := getTraefikService(ctx, cs)
	if err != nil {
		return passResult{err: err}
	}
	if !isPackagedTraefikService(svc) {
		svc = nil
	}
	if len(daemonSets) == 0 && svc == nil {
		return passResult{settled: true}
	}

	// A node with servicelb enabled owns these objects and would
	// recreate them. When it upgrades, its own k3s start runs this.
	node, err := servicelbEnabledNode(ctx, cs)
	if err != nil {
		return passResult{err: err}
	}
	if node != "" {
		return passResult{settled: true,
			reason: "servicelb is enabled on node " + node + "; leaving its objects"}
	}

	var errs []error
	for i := range daemonSets {
		if err := deleteServiceLBDaemonSet(ctx, cs, &daemonSets[i]); err != nil {
			errs = append(errs, err)
		}
	}
	res := passResult{}
	if svc != nil {
		res = cleanupTraefikService(ctx, cs, dyn, svc, now)
	}
	// Anything deleted is checked again next tick, which then settles.
	res.settled = res.settled && len(daemonSets) == 0
	res.err = errors.Join(append(errs, res.err)...)
	return res
}

func listServiceLBDaemonSets(ctx context.Context, cs kubernetes.Interface) ([]appsv1.DaemonSet, error) {
	callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
	defer cancel()
	list, err := cs.AppsV1().DaemonSets(servicelbNamespace).
		List(callCtx, metav1.ListOptions{LabelSelector: servicelbSvcNameLabel})
	if err != nil {
		return nil, fmt.Errorf("list servicelb DaemonSets: %w", err)
	}
	return list.Items, nil
}

func getTraefikService(ctx context.Context, cs kubernetes.Interface) (*corev1.Service, error) {
	callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
	defer cancel()
	svc, err := cs.CoreV1().Services(servicelbNamespace).
		Get(callCtx, traefikRelease, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get Service %s/%s: %w", servicelbNamespace, traefikRelease, err)
	}
	return svc, nil
}

// isPackagedTraefikService reports whether svc is the LoadBalancer Service
// of k3s's packaged chart: Helm release traefik in kube-system.
func isPackagedTraefikService(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Namespace == servicelbNamespace &&
		svc.Name == traefikRelease &&
		svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		svc.Labels["app.kubernetes.io/managed-by"] == "Helm" &&
		svc.Annotations["meta.helm.sh/release-name"] == traefikRelease &&
		svc.Annotations["meta.helm.sh/release-namespace"] == servicelbNamespace
}

// servicelbEnabledNode returns a Ready node whose kubelet allows
// servicelb's sysctl, or "". The running kubelet's config covers every way
// servicelb can be on: an older EVE, a fallback to one, a user override.
func servicelbEnabledNode(ctx context.Context, cs kubernetes.Interface) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
	nodes, err := cs.CoreV1().Nodes().List(callCtx, metav1.ListOptions{})
	cancel()
	if err != nil {
		return "", fmt.Errorf("list nodes: %w", err)
	}
	checked := 0
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !kubectlx.IsNodeReady(node) {
			continue
		}
		configz, err := getKubeletConfigz(ctx, cs, node.Name)
		if err != nil {
			return "", err
		}
		allowed, err := kubeletAllowsSysctl(configz, servicelbSysctl)
		if err != nil {
			return "", fmt.Errorf("kubelet config of node %s: %w", node.Name, err)
		}
		if allowed {
			return node.Name, nil
		}
		checked++
	}
	if checked == 0 {
		return "", errors.New("no Ready node to check servicelb on")
	}
	return "", nil
}

func getKubeletConfigz(ctx context.Context, cs kubernetes.Interface, node string) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
	defer cancel()
	raw, err := cs.CoreV1().RESTClient().Get().
		AbsPath("/api/v1/nodes", node, "proxy", "configz").
		Do(callCtx).Raw()
	if err != nil {
		return nil, fmt.Errorf("read kubelet config of node %s: %w", node, err)
	}
	return raw, nil
}

// kubeletAllowsSysctl reports whether a kubelet /configz response allows
// sysctl, by name or by a trailing-"*" pattern.
func kubeletAllowsSysctl(configz []byte, sysctl string) (bool, error) {
	var body struct {
		KubeletConfig *struct {
			AllowedUnsafeSysctls []string `json:"allowedUnsafeSysctls"`
		} `json:"kubeletconfig"`
	}
	if err := json.Unmarshal(configz, &body); err != nil {
		return false, fmt.Errorf("parse configz: %w", err)
	}
	if body.KubeletConfig == nil {
		return false, errors.New("configz has no kubeletconfig")
	}
	for _, allowed := range body.KubeletConfig.AllowedUnsafeSysctls {
		if allowed == sysctl {
			return true, nil
		}
		if prefix, ok := strings.CutSuffix(allowed, "*"); ok && strings.HasPrefix(sysctl, prefix) {
			return true, nil
		}
	}
	return false, nil
}

func deleteServiceLBDaemonSet(ctx context.Context, cs kubernetes.Interface, ds *appsv1.DaemonSet) error {
	callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
	defer cancel()
	uid := ds.UID
	propagation := metav1.DeletePropagationBackground
	err := cs.AppsV1().DaemonSets(ds.Namespace).Delete(callCtx, ds.Name, metav1.DeleteOptions{
		Preconditions:     &metav1.Preconditions{UID: &uid},
		PropagationPolicy: &propagation,
	})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete DaemonSet %s/%s: %w", ds.Namespace, ds.Name, err)
	}
	log.Printf("servicelb orphan cleanup: deleted DaemonSet %s/%s (Service %s/%s, created %s)",
		ds.Namespace, ds.Name, ds.Labels[servicelbSvcNamespaceLabel],
		ds.Labels[servicelbSvcNameLabel], ds.CreationTimestamp.UTC().Format(time.RFC3339))
	return nil
}

// cleanupTraefikService deletes the orphaned Traefik Service, then removes
// the load-balancer finalizer if it is still terminating after
// lbFinalizerGrace.
func cleanupTraefikService(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, svc *corev1.Service, now time.Time) passResult {
	held := func(settled bool, why string) passResult {
		return passResult{settled: settled,
			reason: fmt.Sprintf("Service %s/%s %s", svc.Namespace, svc.Name, why)}
	}

	// helm-controller is still installing or uninstalling it: wait.
	hasChart, err := traefikHelmChartExists(ctx, dyn)
	if err != nil {
		return passResult{err: err}
	}
	if hasChart {
		return held(false, "is still owned by HelmChart "+servicelbNamespace+"/"+traefikRelease)
	}
	// A release record without a HelmChart is someone else's Traefik.
	record, err := traefikReleaseRecord(ctx, cs)
	if err != nil {
		return passResult{err: err}
	}
	if record != "" {
		return held(true, "is owned by Helm release record "+record+"; leaving it")
	}

	callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
	defer cancel()
	services := cs.CoreV1().Services(svc.Namespace)

	if svc.DeletionTimestamp == nil {
		uid := svc.UID
		err := services.Delete(callCtx, svc.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		})
		if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			return passResult{}
		}
		if err != nil {
			return passResult{err: fmt.Errorf("delete Service %s/%s: %w", svc.Namespace, svc.Name, err)}
		}
		log.Printf("servicelb orphan cleanup: deleted Service %s/%s (created %s)",
			svc.Namespace, svc.Name, svc.CreationTimestamp.UTC().Format(time.RFC3339))
		return passResult{}
	}

	patch, err := finalizerRemovalPatch(svc.Finalizers, lbCleanupFinalizer, svc.ResourceVersion)
	if err != nil {
		return passResult{err: err}
	}
	if patch == nil {
		// Held by some other finalizer; not ours to release.
		return held(true, "is terminating on finalizers that are not ours; leaving it")
	}
	if now.Sub(svc.DeletionTimestamp.Time) < lbFinalizerGrace {
		return held(false, fmt.Sprintf("is terminating; releasing %s after %s",
			lbCleanupFinalizer, lbFinalizerGrace))
	}
	_, err = services.Patch(callCtx, svc.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return passResult{}
	}
	if err != nil {
		return passResult{err: fmt.Errorf("remove %s from Service %s/%s: %w",
			lbCleanupFinalizer, svc.Namespace, svc.Name, err)}
	}
	log.Printf("servicelb orphan cleanup: removed %s from Service %s/%s (terminating since %s)",
		lbCleanupFinalizer, svc.Namespace, svc.Name,
		svc.DeletionTimestamp.UTC().Format(time.RFC3339))
	return passResult{}
}

func traefikHelmChartExists(ctx context.Context, dyn dynamic.Interface) (bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
	defer cancel()
	_, err := dyn.Resource(helmChartGVR).Namespace(servicelbNamespace).
		Get(callCtx, traefikRelease, metav1.GetOptions{})
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	}
	return false, fmt.Errorf("get HelmChart %s/%s: %w", servicelbNamespace, traefikRelease, err)
}

// traefikReleaseRecord returns the name of a Helm release record for
// traefik in kube-system, or "". Helm keeps records in Secrets by default
// and in ConfigMaps with its configmap driver. Only metadata is fetched:
// a record holds the release's values.
func traefikReleaseRecord(ctx context.Context, cs kubernetes.Interface) (string, error) {
	for _, resource := range []string{"secrets", "configmaps"} {
		callCtx, cancel := context.WithTimeout(ctx, servicelbAPICallBudget)
		raw, err := cs.CoreV1().RESTClient().Get().
			Namespace(servicelbNamespace).Resource(resource).
			Param("labelSelector", "owner=helm,name="+traefikRelease).
			Param("limit", "1").
			SetHeader("Accept", "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1").
			Do(callCtx).Raw()
		cancel()
		if err != nil {
			return "", fmt.Errorf("list Helm release records in %s: %w", resource, err)
		}
		var list metav1.PartialObjectMetadataList
		if err := json.Unmarshal(raw, &list); err != nil {
			return "", fmt.Errorf("parse Helm release records in %s: %w", resource, err)
		}
		if len(list.Items) > 0 {
			return resource + "/" + list.Items[0].Name, nil
		}
	}
	return "", nil
}

// finalizerRemovalPatch returns a merge patch dropping finalizer, guarded
// by resourceVersion, or nil when finalizer is absent.
func finalizerRemovalPatch(finalizers []string, finalizer, resourceVersion string) ([]byte, error) {
	kept := make([]string, 0, len(finalizers))
	found := false
	for _, f := range finalizers {
		if f == finalizer {
			found = true
			continue
		}
		kept = append(kept, f)
	}
	if !found {
		return nil, nil
	}
	return json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": resourceVersion,
			"finalizers":      kept,
		},
	})
}
