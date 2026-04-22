// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"kubevirt.io/client-go/kubecli"
)

// DeschedulerEvictAnnotation is the annotation placed on VMI ReplicaSet templates
// and VMI objects to allow the Kubernetes descheduler to evict them for rebalancing.
const DeschedulerEvictAnnotation = "descheduler.alpha.kubernetes.io/evict"

const (
	deschedulerNamespace              = "kube-system"
	deschedulerJobName                = "descheduler-job"
	deschedulerSAName                 = "descheduler-sa"
	deschedulerClusterRoleName        = "descheduler-cluster-role"
	deschedulerClusterRoleBindingName = "descheduler-cluster-role-binding"
	deschedulerConfigMapName          = "descheduler-policy-configmap"
	deschedulerImage                  = "registry.k8s.io/descheduler/descheduler:v0.29.0"

	// deschedulerPolicyYAML is the inline descheduler policy that rebalances
	// EVE app pods to meet preferred node-affinity constraints.
	deschedulerPolicyYAML = `apiVersion: "descheduler/v1alpha2"
kind: "DeschedulerPolicy"
profiles:
  - name: EveAppNodeAffinity
    pluginConfig:
    - name: "RemovePodsViolatingNodeAffinity"
      args:
        namespaces:
          include:
          - "eve-kube-app"
        nodeAffinityType:
        - "preferredDuringSchedulingIgnoredDuringExecution"
    plugins:
      deschedule:
        enabled:
          - "RemovePodsViolatingNodeAffinity"
`
)

// IsDeschedulerReady checks whether all preconditions for running the descheduler
// are satisfied. Returns (false, nil) when conditions are not yet met so the caller
// can retry, and (false, err) on an API error.
func IsDeschedulerReady(log *base.LogObject, nodeName string) (bool, error) {
	client, err := GetClientSet()
	if err != nil {
		return false, fmt.Errorf("IsDeschedulerReady: GetClientSet: %w", err)
	}
	return isDeschedulerReadyWithClient(log, client, nodeName)
}

func isDeschedulerReadyWithClient(log *base.LogObject, client kubernetes.Interface, nodeName string) (bool, error) {
	ctx := context.Background()

	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("IsDeschedulerReady: get node %s: %w", nodeName, err)
	}
	if node.Spec.Unschedulable {
		log.Noticef("IsDeschedulerReady: node %s is unschedulable", nodeName)
		return false, nil
	}
	nodeReady := false
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
			nodeReady = true
			break
		}
	}
	if !nodeReady {
		log.Noticef("IsDeschedulerReady: node %s is not ready", nodeName)
		return false, nil
	}

	if err := waitForLonghornReady(client, nodeName); err != nil {
		log.Noticef("IsDeschedulerReady: longhorn not ready: %v", err)
		return false, nil
	}

	_, err = client.CoreV1().Namespaces().Get(ctx, "kubevirt", metav1.GetOptions{})
	if err == nil {
		kubeConfig, err := GetKubeConfig()
		if err != nil {
			return false, fmt.Errorf("IsDeschedulerReady: GetKubeConfig: %w", err)
		}
		if err := waitForKubevirtReady(kubeConfig); err != nil {
			log.Noticef("IsDeschedulerReady: kubevirt not ready: %v", err)
			return false, nil
		}
	} else if !k8serrors.IsNotFound(err) {
		return false, fmt.Errorf("IsDeschedulerReady: check kubevirt namespace: %w", err)
	}

	return true, nil
}

// TriggerDescheduler runs the descheduler Job. The caller must have already
// verified readiness via IsDeschedulerReady.
func TriggerDescheduler(log *base.LogObject, nodeName string) error {
	client, err := GetClientSet()
	if err != nil {
		return fmt.Errorf("TriggerDescheduler: GetClientSet: %w", err)
	}
	return triggerDeschedulerWithClient(log, client, nodeName)
}

func triggerDeschedulerWithClient(log *base.LogObject, client kubernetes.Interface, nodeName string) error {
	ctx := context.Background()

	if err := ensureDeschedulerSetupWithClient(ctx, client); err != nil {
		return fmt.Errorf("TriggerDescheduler: setup: %w", err)
	}

	// Try Create first to avoid a multi-node race: if two nodes reboot near-
	// simultaneously, an unconditional Delete would kill the other node's
	// already-running descheduler pod mid-eviction.
	_, err := client.BatchV1().Jobs(deschedulerNamespace).Create(ctx, deschedulerJob(), metav1.CreateOptions{})
	if err == nil {
		log.Noticef("TriggerDescheduler: descheduler job created on node %s", nodeName)
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("TriggerDescheduler: create job: %w", err)
	}

	// Job already exists — check whether it is still active.
	existing, err := client.BatchV1().Jobs(deschedulerNamespace).Get(ctx, deschedulerJobName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("TriggerDescheduler: get existing job: %w", err)
	}
	if existing.Status.Active > 0 {
		// Another node's descheduler is running — nothing to do.
		log.Noticef("TriggerDescheduler: descheduler job already active, skipping (node %s)", nodeName)
		return nil
	}

	// Job is completed or failed — delete and recreate.
	deletePolicy := metav1.DeletePropagationForeground
	if err := client.BatchV1().Jobs(deschedulerNamespace).Delete(ctx, deschedulerJobName,
		metav1.DeleteOptions{PropagationPolicy: &deletePolicy}); err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("TriggerDescheduler: delete stale job: %w", err)
	}
	if _, err = client.BatchV1().Jobs(deschedulerNamespace).Create(ctx, deschedulerJob(), metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("TriggerDescheduler: recreate job: %w", err)
	}
	log.Noticef("TriggerDescheduler: recreated descheduler job on node %s", nodeName)
	return nil
}

func ensureDeschedulerSetup(ctx context.Context) error {
	client, err := GetClientSet()
	if err != nil {
		return fmt.Errorf("ensureDeschedulerSetup: GetClientSet: %w", err)
	}
	return ensureDeschedulerSetupWithClient(ctx, client)
}

func ensureDeschedulerSetupWithClient(ctx context.Context, client kubernetes.Interface) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deschedulerSAName,
			Namespace: deschedulerNamespace,
		},
	}
	existingSA, err := client.CoreV1().ServiceAccounts(deschedulerNamespace).Get(ctx, sa.Name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = client.CoreV1().ServiceAccounts(deschedulerNamespace).Create(ctx, sa, metav1.CreateOptions{})
	} else if err == nil {
		sa.ResourceVersion = existingSA.ResourceVersion
		_, err = client.CoreV1().ServiceAccounts(deschedulerNamespace).Update(ctx, sa, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("ensureDeschedulerSetup: service account: %w", err)
	}

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: deschedulerClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"events.k8s.io"}, Resources: []string{"events"}, Verbs: []string{"create", "update"}},
			{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get", "watch", "list"}},
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get", "watch", "list"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "watch", "list", "delete"}},
			{APIGroups: []string{""}, Resources: []string{"pods/eviction"}, Verbs: []string{"create"}},
			{APIGroups: []string{"scheduling.k8s.io"}, Resources: []string{"priorityclasses"}, Verbs: []string{"get", "watch", "list"}},
			{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"create"}},
			{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{"descheduler"}, Verbs: []string{"get", "patch", "delete"}},
		},
	}
	existingCR, err := client.RbacV1().ClusterRoles().Get(ctx, cr.Name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = client.RbacV1().ClusterRoles().Create(ctx, cr, metav1.CreateOptions{})
	} else if err == nil {
		cr.ResourceVersion = existingCR.ResourceVersion
		_, err = client.RbacV1().ClusterRoles().Update(ctx, cr, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("ensureDeschedulerSetup: cluster role: %w", err)
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: deschedulerClusterRoleBindingName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     deschedulerClusterRoleName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      deschedulerSAName,
			Namespace: deschedulerNamespace,
		}},
	}
	existingCRB, err := client.RbacV1().ClusterRoleBindings().Get(ctx, crb.Name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = client.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
	} else if err == nil {
		crb.ResourceVersion = existingCRB.ResourceVersion
		_, err = client.RbacV1().ClusterRoleBindings().Update(ctx, crb, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("ensureDeschedulerSetup: cluster role binding: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deschedulerConfigMapName,
			Namespace: deschedulerNamespace,
		},
		Data: map[string]string{
			"policy.yaml": deschedulerPolicyYAML,
		},
	}
	existingCM, err := client.CoreV1().ConfigMaps(deschedulerNamespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = client.CoreV1().ConfigMaps(deschedulerNamespace).Create(ctx, cm, metav1.CreateOptions{})
	} else if err == nil {
		cm.ResourceVersion = existingCM.ResourceVersion
		_, err = client.CoreV1().ConfigMaps(deschedulerNamespace).Update(ctx, cm, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("ensureDeschedulerSetup: configmap: %w", err)
	}

	return nil
}

func deschedulerJob() *batchv1.Job {
	f, t := false, true
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deschedulerJobName,
			Namespace: deschedulerNamespace,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: "descheduler-pod",
				},
				Spec: corev1.PodSpec{
					PriorityClassName:  "system-cluster-critical",
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: deschedulerSAName,
					Containers: []corev1.Container{{
						Name:    "descheduler",
						Image:   deschedulerImage,
						Command: []string{"/bin/descheduler"},
						Args:    []string{"--policy-config-file", "/policy-dir/policy.yaml", "--v", "3"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "policy-volume",
							MountPath: "/policy-dir",
						}},
						LivenessProbe: &corev1.Probe{
							FailureThreshold: 3,
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/healthz",
									Port:   intstr.FromInt(10258),
									Scheme: corev1.URISchemeHTTPS,
								},
							},
							InitialDelaySeconds: 3,
							PeriodSeconds:       10,
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &f,
							Privileged:               &f,
							ReadOnlyRootFilesystem:   &t,
							RunAsNonRoot:             &t,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
					}},
					Volumes: []corev1.Volume{{
						Name: "policy-volume",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: deschedulerConfigMapName,
								},
							},
						},
					}},
				},
			},
		},
	}
}

// EnsureVMsDeschedulerAnnotated adds DeschedulerEvictAnnotation to any VMIRS Template
// or VMI in EVEKubeNameSpace that is missing it. Idempotent: resources already annotated
// are not updated. No-op in base-k3s mode.
func EnsureVMsDeschedulerAnnotated(log *base.LogObject) error {
	if err := registrationAppliedToCluster(); err == nil {
		return nil
	}
	config, err := GetKubeConfig()
	if err != nil {
		return fmt.Errorf("EnsureVMsDeschedulerAnnotated: GetKubeConfig: %w", err)
	}
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		return fmt.Errorf("EnsureVMsDeschedulerAnnotated: GetKubevirtClientFromRESTConfig: %w", err)
	}
	return ensureVMsDeschedulerAnnotatedWithClient(log, virtClient)
}

func ensureVMsDeschedulerAnnotatedWithClient(log *base.LogObject, virtClient kubecli.KubevirtClient) error {
	ctx := context.Background()
	var firstErr error

	vmirsPatch := []byte(`{"spec":{"template":{"metadata":{"annotations":{"` + DeschedulerEvictAnnotation + `":"true"}}}}}`)
	vmrsList, err := virtClient.ReplicaSet(EVEKubeNameSpace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("EnsureVMsDeschedulerAnnotated: list VMIRSs: %w", err)
	}
	for i := range vmrsList.Items {
		vmirs := &vmrsList.Items[i]
		if vmirs.Spec.Template.ObjectMeta.Annotations[DeschedulerEvictAnnotation] == "true" {
			continue
		}
		if _, err := virtClient.ReplicaSet(EVEKubeNameSpace).Patch(ctx, vmirs.Name, ktypes.StrategicMergePatchType, vmirsPatch, metav1.PatchOptions{}); err != nil {
			log.Errorf("EnsureVMsDeschedulerAnnotated: patch vmirs %s: %v", vmirs.Name, err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			log.Noticef("EnsureVMsDeschedulerAnnotated: annotated vmirs %s", vmirs.Name)
		}
	}

	vmiPatch := []byte(`{"metadata":{"annotations":{"` + DeschedulerEvictAnnotation + `":"true"}}}`)
	vmiList, err := virtClient.VirtualMachineInstance(EVEKubeNameSpace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("EnsureVMsDeschedulerAnnotated: list VMIs: %w", err)
		}
		return firstErr
	}
	for i := range vmiList.Items {
		vmi := &vmiList.Items[i]
		if vmi.ObjectMeta.Annotations[DeschedulerEvictAnnotation] == "true" {
			continue
		}
		if _, err := virtClient.VirtualMachineInstance(EVEKubeNameSpace).Patch(ctx, vmi.Name, ktypes.StrategicMergePatchType, vmiPatch, metav1.PatchOptions{}); err != nil {
			log.Errorf("EnsureVMsDeschedulerAnnotated: patch vmi %s: %v", vmi.Name, err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			log.Noticef("EnsureVMsDeschedulerAnnotated: annotated vmi %s", vmi.Name)
		}
	}
	return firstErr
}
