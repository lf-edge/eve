// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// reconcileVMIRSAffinity corrects the node affinity recorded in an
// AppInstance's VMI ReplicaSet when it no longer matches this node, but only
// for apps whose cluster DNID is currently assigned to this node.
//
// The VMIRS's affinity is set once, by whichever node happens to create it
// (see hypervisor.CreateReplicaVMIConfig), and is never revisited by that
// creation path afterward. A cluster DNID reassignment (e.g. node
// replacement) does not update it, so it can keep pointing at a node that no
// longer runs (or never ran) this app.
//
// Gating on "am I the DNID node" -- rather than "am I the node currently
// running this app" -- is deliberate: a temporary failover (e.g. the DNID
// node reboots and the app runs elsewhere for a while, with DNID unchanged)
// must NOT rewrite the affinity to the failover node, since the descheduler
// (EnsureVMsDeschedulerAnnotated / RemovePodsViolatingNodeAffinity) relies on
// the affinity still pointing at the true home node to move the app back
// once it recovers.
//
// But IsDesignatedNodeID alone can't tell a genuine permanent reassignment
// apart from that same DNID node simply reconnecting after such a temporary
// failover -- both look identical from here. So patching also requires
// nodeExists to confirm the node currently named in the affinity is gone
// from the cluster altogether, not merely unreachable or NotReady: a node
// that's only temporarily down keeps its Node object, so this can't misfire
// the instant it reconnects, only once it's actually been replaced.
//
// Patching only spec.template.spec.affinity does not disturb a VMI already
// running: a ReplicaSet controller consults the template only when creating
// a NEW replica to satisfy the desired count, never retroactively for a
// replica already running.
//
// wdFunc is invoked once per app so the watchdog budget resets between
// per-app API calls; see checkAppsFailover for the same pattern. Without it,
// N apps each incurring a kubeAPITimeout-bounded Get+Update could together
// exceed the agent's errorTime budget.
func (z *zedkube) reconcileVMIRSAffinity(wdFunc func()) {
	sub := z.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}
	if !anyDesignatedVMI(items) {
		// Nothing for this node to reconcile; skip the kubeconfig/client
		// construction cost on this tick.
		return
	}

	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("reconcileVMIRSAffinity: get kubeconfig: %v", err)
		return
	}
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		log.Errorf("reconcileVMIRSAffinity: kubevirt client: %v", err)
		return
	}
	nodeClient, err := getKubeClientSet()
	if err != nil {
		log.Errorf("reconcileVMIRSAffinity: clientset: %v", err)
		return
	}

	reconcileVMIRSAffinityWithClient(z.nodeName, virtClient, nodeClient, items, wdFunc)
}

// anyDesignatedVMI reports whether any item is a VMI-backed app for which
// this node is the DNID, i.e. whether reconcileVMIRSAffinityWithClient would
// do any real work for these items.
func anyDesignatedVMI(items map[string]interface{}) bool {
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		if aiconfig.IsDesignatedNodeID && aiconfig.FixedResources.VirtualizationMode != types.NOHYPER {
			return true
		}
	}
	return false
}

func reconcileVMIRSAffinityWithClient(nodeName string, virtClient kubecli.KubevirtClient,
	nodeClient kubernetes.Interface, items map[string]interface{}, wdFunc func()) {
	for _, item := range items {
		wdFunc()

		aiconfig := item.(types.AppInstanceConfig)
		if !aiconfig.IsDesignatedNodeID {
			continue
		}
		if aiconfig.FixedResources.VirtualizationMode == types.NOHYPER {
			// Native containers use a plain Kubernetes ReplicaSet/Pod
			// template (CreateReplicaPodConfig), not a VMIRS.
			continue
		}

		vmiRsName := base.GetAppKubeNameWithPurge(aiconfig.DisplayName,
			aiconfig.UUIDandVersion.UUID, aiconfig.PurgeCmd.Counter+aiconfig.LocalPurgeCmd.Counter)

		getCtx, getCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
		existing, err := virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Get(getCtx, vmiRsName, metav1.GetOptions{})
		getCancel()
		if err != nil {
			if !errors.IsNotFound(err) {
				log.Errorf("reconcileVMIRSAffinity: get vmirs %s: %v", vmiRsName, err)
			}
			// Not found: nothing to reconcile yet, Start() will create it
			// with the correct affinity for whichever node activates it.
			continue
		}

		// Gate 1: the recorded affinity actually disagrees with the DNID.
		staleNode := vmirsAffinityNode(existing)
		if staleNode == "" || staleNode == nodeName {
			continue
		}
		// Gate 2: that disagreement is permanent, not a live node merely
		// being unreachable right now.
		if nodeExists(nodeClient, staleNode) {
			continue
		}

		existing.Spec.Template.Spec.Affinity = hypervisor.SetKubeAffinity(nodeName, aiconfig.AffinityType)
		updateCtx, updateCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
		_, err = virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Update(updateCtx, existing, metav1.UpdateOptions{})
		updateCancel()
		if err != nil {
			log.Errorf("reconcileVMIRSAffinity: update vmirs %s affinity: %v", vmiRsName, err)
			continue
		}
		log.Noticef("reconcileVMIRSAffinity: updated vmirs %s affinity to node %s (node %s no longer in cluster)",
			vmiRsName, nodeName, staleNode)
	}
}

// nodeExists reports whether a Node object named nodeName is currently
// registered with the cluster. Any error other than a clean "not found" is
// treated as still existing (fail safe): the caller only acts on affinity
// staleness once it can positively confirm the referenced node is gone for
// good, never on an ambiguous API error.
func nodeExists(clientset kubernetes.Interface, nodeName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	_, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err == nil {
		return true
	}
	return !errors.IsNotFound(err)
}

// patchVMIRSAffinity rewrites vmiRsName's template affinity to nodeName
// when it currently names a different node. Returns whether it actually
// patched anything (false when the affinity already matched or there is no
// VMIRS yet).
//
// Patching only spec.template.spec.affinity does not disturb a VMI
// already running: a ReplicaSet controller consults the template only
// when creating a NEW replica to satisfy the desired count, never
// retroactively for a replica already running.
func patchVMIRSAffinity(virtClient kubecli.KubevirtClient, nodeName, vmiRsName string,
	affinityType types.Affinity) (bool, error) {
	getCtx, getCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	existing, err := virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Get(getCtx, vmiRsName, metav1.GetOptions{})
	getCancel()
	if err != nil {
		if errors.IsNotFound(err) {
			// Nothing to reconcile yet, Start() will create it with the
			// correct affinity for whichever node activates it.
			return false, nil
		}
		return false, err
	}

	staleNode := vmirsAffinityNode(existing)
	if staleNode == "" || staleNode == nodeName {
		return false, nil
	}

	existing.Spec.Template.Spec.Affinity = hypervisor.SetKubeAffinity(nodeName, affinityType)
	updateCtx, updateCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	_, err = virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Update(updateCtx, existing, metav1.UpdateOptions{})
	updateCancel()
	if err != nil {
		return false, err
	}
	log.Noticef("patchVMIRSAffinity: updated vmirs %s affinity to node %s (was %s)",
		vmiRsName, nodeName, staleNode)
	return true, nil
}

// vmirsAffinityNode returns the node a VMIRS template's affinity names.
func vmirsAffinityNode(vmirs *virtv1.VirtualMachineInstanceReplicaSet) string {
	if vmirs.Spec.Template == nil {
		return ""
	}
	return affinityNode(vmirs.Spec.Template.Spec.Affinity)
}

// affinityNode extracts the kubernetes.io/hostname value from the node
// affinity EVE sets on a VMI, a pod or their templates. EVE encodes the
// owner node via hypervisor.SetKubeAffinity using either
// preferredDuringSchedulingIgnoredDuringExecution or
// requiredDuringSchedulingIgnoredDuringExecution. Returns "" if neither is
// present or the hostname matchExpression is absent.
func affinityNode(aff *corev1.Affinity) string {
	if aff == nil || aff.NodeAffinity == nil {
		return ""
	}
	na := aff.NodeAffinity
	for _, pref := range na.PreferredDuringSchedulingIgnoredDuringExecution {
		for _, expr := range pref.Preference.MatchExpressions {
			if expr.Key == "kubernetes.io/hostname" && len(expr.Values) > 0 {
				return expr.Values[0]
			}
		}
	}
	if req := na.RequiredDuringSchedulingIgnoredDuringExecution; req != nil {
		for _, term := range req.NodeSelectorTerms {
			for _, expr := range term.MatchExpressions {
				if expr.Key == "kubernetes.io/hostname" && len(expr.Values) > 0 {
					return expr.Values[0]
				}
			}
		}
	}
	return ""
}
