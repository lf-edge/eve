// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"kubevirt.io/client-go/kubecli"
)

// The periodic event of kubernetes.vmi.deschedule.events makes the
// designated node of an app pull it back whenever it runs elsewhere.
// Kubernetes moves an app away from a node that fails, and nothing brings it
// back unless that node reboots (the boot event) -- not after a network
// outage, and not when the designated node changes, e.g. to a replacement
// device.
//
// The event is opt-in, except in a 2-node HA cluster, where the placement
// of an app is what keeps it running: the seed hosts the witness, so losing
// the seed loses quorum, and with it the ability to restart an app anywhere.
// An app is safe only on the non-seed, where the controller designates it.

// isTwoNodeHACluster reports whether this node belongs to a 2-node cluster
// whose third etcd vote is a witness.
func (z *zedkube) isTwoNodeHACluster() bool {
	for _, item := range z.subEdgeNodeClusterConfig.GetAll() {
		if config := item.(types.EdgeNodeClusterConfig); config.WitnessIP != nil {
			return true
		}
	}
	return false
}

// misplacedApps returns the apps designated to this node that run on
// another node.
func (z *zedkube) misplacedApps() []types.AppInstanceConfig {
	statuses := make(map[string]types.ENClusterAppStatus)
	for _, item := range z.pubENClusterAppStatus.GetAll() {
		status := item.(types.ENClusterAppStatus)
		statuses[status.AppUUID.String()] = status
	}
	var apps []types.AppInstanceConfig
	for _, item := range z.subAppInstanceConfig.GetAll() {
		aiconfig := item.(types.AppInstanceConfig)
		status, ok := statuses[aiconfig.UUIDandVersion.UUID.String()]
		if ok && isMisplaced(aiconfig, status) {
			apps = append(apps, aiconfig)
		}
	}
	return apps
}

// isMisplaced reports whether an app designated to this node runs on
// another one. The controller designates an app explicitly when its
// failover matters. Without a designated node every node counts as
// designated (see parseAppInstanceConfig), so such an app is left wherever
// it runs. An app with required affinity never leaves its node.
func isMisplaced(aiconfig types.AppInstanceConfig, status types.ENClusterAppStatus) bool {
	return aiconfig.DesignatedNodeUUID != "" && aiconfig.IsDesignatedNodeID &&
		aiconfig.AffinityType == types.PreferredDuringScheduling &&
		!status.ScheduledOnThisNode &&
		status.AppKubeStatus == types.AppKubeStatusRunningState
}

// misplacedApp is an app to move here, with its running instance.
type misplacedApp struct {
	aiconfig types.AppInstanceConfig
	pod      corev1.Pod
	isVMI    bool
}

// placementPlan is how to bring the misplaced apps back to this node.
type placementPlan struct {
	// deschedule are the apps the descheduler Job can move: their running
	// instance prefers this node, so running elsewhere violates its own
	// affinity.
	deschedule []misplacedApp
	// stale are the apps whose running instance prefers another node,
	// because the app was designated to this node after it started. The
	// Job sees nothing wrong with them.
	stale []misplacedApp
}

// planPlacement decides how to move each app from its running pod, which
// for a VMI app is its virt-launcher pod, carrying the VMI's affinity.
func planPlacement(nodeName string, apps []types.AppInstanceConfig,
	pods []corev1.Pod) placementPlan {
	var plan placementPlan
	for _, aiconfig := range apps {
		pod, isVMI, found := findAppPod(pods, aiconfig)
		if !found {
			continue
		}
		app := misplacedApp{aiconfig: aiconfig, pod: pod, isVMI: isVMI}
		if affinityNode(pod.Spec.Affinity) == nodeName {
			plan.deschedule = append(plan.deschedule, app)
			continue
		}
		plan.stale = append(plan.stale, app)
	}
	return plan
}

// findAppPod returns the app's pod that is not terminating, matched by name
// as checkAppsStatus does.
func findAppPod(pods []corev1.Pod, aiconfig types.AppInstanceConfig) (corev1.Pod, bool, bool) {
	kubeName := appKubeName(aiconfig)
	for _, pod := range pods {
		if isPodTerminating(pod) {
			continue
		}
		if strings.HasPrefix(pod.Name, "virt-launcher-"+kubeName) {
			return pod, true, true
		}
		if strings.HasPrefix(pod.Name, kubeName) {
			return pod, false, true
		}
	}
	return corev1.Pod{}, false, false
}

func appKubeName(aiconfig types.AppInstanceConfig) string {
	return base.GetAppKubeNameWithPurge(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID,
		aiconfig.PurgeCmd.Counter+aiconfig.LocalPurgeCmd.Counter)
}

// restorePlacement brings the apps designated to this node that run
// elsewhere back to it: with the descheduler Job where the Job can see the
// app is misplaced, and otherwise by retargeting the app's ReplicaSet at
// this node and replacing its running instance, which the Job cannot do
// since a running pod's affinity cannot be changed. Returns false if any
// step failed, so a caller that acts only once can retry.
func (z *zedkube) restorePlacement(wdFunc func()) bool {
	apps := z.misplacedApps()
	if len(apps) == 0 {
		return true
	}
	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("restorePlacement: clientset: %v", err)
		return false
	}
	listCtx, listCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(listCtx, metav1.ListOptions{})
	listCancel()
	if err != nil {
		log.Errorf("restorePlacement: list pods: %v", err)
		return false
	}
	plan := planPlacement(z.nodeName, apps, pods.Items)
	for _, app := range plan.deschedule {
		log.Noticef("restorePlacement: %s runs on node %s and its pod %s prefers this "+
			"node: moving it with the descheduler", app.aiconfig.DisplayName,
			app.pod.Spec.NodeName, app.pod.Name)
	}

	done := true
	var virtClient kubecli.KubevirtClient
	for _, app := range plan.stale {
		wdFunc()
		name := appKubeName(app.aiconfig)
		owner := "ReplicaSet"
		if app.isVMI {
			owner = "VMIRS"
		}
		log.Noticef("restorePlacement: %s runs on node %s and its pod %s prefers node %q: "+
			"retargeting its %s %s at this node and replacing the pod",
			app.aiconfig.DisplayName, app.pod.Spec.NodeName, app.pod.Name,
			affinityNode(app.pod.Spec.Affinity), owner, name)
		if !app.isVMI {
			if err := moveReplicaSetPod(clientset, z.nodeName, name, app.pod.Name,
				app.aiconfig.AffinityType); err != nil {
				log.Errorf("restorePlacement: move %s: %v", name, err)
				done = false
			}
			continue
		}
		if virtClient == nil {
			config, err := kubeapi.GetKubeConfig()
			if err == nil {
				virtClient, err = kubecli.GetKubevirtClientFromRESTConfig(config)
			}
			if err != nil {
				log.Errorf("restorePlacement: kubevirt client: %v", err)
				return false
			}
		}
		if _, err := patchVMIRSAffinity(virtClient, z.nodeName, name,
			app.aiconfig.AffinityType); err != nil {
			log.Errorf("restorePlacement: patch vmirs %s: %v", name, err)
			done = false
			continue
		}
		if err := kubeapi.DetachUtilVmirsReplicaReset(log, name); err != nil {
			log.Errorf("restorePlacement: cycle vmirs %s: %v", name, err)
			done = false
		}
	}

	if len(plan.deschedule) > 0 {
		wdFunc()
		if err := kubeapi.TriggerDescheduler(log, z.nodeName); err != nil {
			log.Errorf("restorePlacement: trigger descheduler: %v", err)
			return false
		}
		log.Noticef("restorePlacement: descheduler triggered")
	}
	return done
}

// moveReplicaSetPod retargets a native container app's ReplicaSet at
// nodeName and deletes its running pod, so that the ReplicaSet recreates
// it there. Like a VMIRS, a ReplicaSet consults its template only when it
// creates a pod.
func moveReplicaSetPod(clientset kubernetes.Interface, nodeName, rsName, podName string,
	affinityType types.Affinity) error {
	rsClient := clientset.AppsV1().ReplicaSets(kubeapi.EVEKubeNameSpace)
	getCtx, getCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	rs, err := rsClient.Get(getCtx, rsName, metav1.GetOptions{})
	getCancel()
	if err != nil {
		return err
	}
	if affinityNode(rs.Spec.Template.Spec.Affinity) != nodeName {
		rs.Spec.Template.Spec.Affinity = hypervisor.SetKubeAffinity(nodeName, affinityType)
		updateCtx, updateCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
		_, err = rsClient.Update(updateCtx, rs, metav1.UpdateOptions{})
		updateCancel()
		if err != nil {
			return err
		}
	}
	deleteCtx, deleteCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer deleteCancel()
	err = clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).Delete(deleteCtx, podName,
		metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}
