// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

const (
	// pendingVMIDeleteThreshold is how long a VMI must be stuck Pending with a
	// Running virt-launcher on this node before we force-delete it.
	pendingVMIDeleteThreshold = 3 * time.Minute
	// pendingVMIMaxDeletes caps consecutive FastDeleteVmi attempts per app;
	// reset when the VMI reaches Running.
	pendingVMIMaxDeletes = 3
	// pendingVMISuppressWindow is how long checkAppsStatus pins StatusRunning=true
	// after a delete so zedmanager does not cascade to DomainConfig.Activate=false.
	pendingVMISuppressWindow = 5 * time.Minute
	// failoverVMISuppressWindow is how long checkStuckPendingVMI suppresses
	// force-delete after checkAppsFailover detects an active failover on this
	// node. The window is refreshed every tick while the Terminating pod
	// exists, so it self-extends until failover completes.
	failoverVMISuppressWindow = 15 * time.Minute
)

// checkStuckPendingVMI looks for VMIs that are Pending while their virt-launcher
// pod is either Running or in an error state on this node (Failed, or Running
// with a container stuck in CrashLoopBackOff / image-pull / error-waiting /
// terminated-with-error). If the condition persists past the threshold, it
// force-deletes the VMI (not the VMIRS) so the cluster re-creates it cleanly.
// A per-app counter caps retries at pendingVMIMaxDeletes.
func (z *zedkube) checkStuckPendingVMI() {
	sub := z.subAppInstanceConfig
	items := sub.GetAll()

	// Reap entries for apps that no longer exist in config so the three
	// maps do not leak across AppInstanceConfig deletes.
	live := make(map[string]struct{}, len(items))
	for _, item := range items {
		live[item.(types.AppInstanceConfig).UUIDandVersion.UUID.String()] = struct{}{}
	}
	for k := range z.vmiPendingSince {
		if _, ok := live[k]; !ok {
			delete(z.vmiPendingSince, k)
		}
	}
	for k := range z.vmiDeleteCount {
		if _, ok := live[k]; !ok {
			delete(z.vmiDeleteCount, k)
		}
	}
	for k := range z.vmiDeleteSuppressUntil {
		if _, ok := live[k]; !ok {
			delete(z.vmiDeleteSuppressUntil, k)
		}
	}
	for k := range z.vmiFailoverSuppressUntil {
		if _, ok := live[k]; !ok {
			delete(z.vmiFailoverSuppressUntil, k)
		}
	}

	if len(items) == 0 {
		return
	}

	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("checkStuckPendingVMI: get kubeconfig: %v", err)
		return
	}
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		log.Errorf("checkStuckPendingVMI: kubevirt client: %v", err)
		return
	}

	vmiList, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("checkStuckPendingVMI: list VMIs: %v", err)
		return
	}

	now := time.Now()
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		appUUID := aiconfig.UUIDandVersion.UUID.String()
		// VMIRS name carries the purge counter (see cbed950d8); VMI
		// OwnerReferences[0].Name matches this exactly, and virt-launcher
		// pod names start with this prefix.
		appKubeName := base.GetAppKubeNameWithPurge(
			aiconfig.DisplayName,
			aiconfig.UUIDandVersion.UUID,
			aiconfig.PurgeCmd.Counter+aiconfig.LocalPurgeCmd.Counter,
		)

		vmi := findAppVMI(vmiList.Items, appKubeName)
		if vmi == nil {
			delete(z.vmiPendingSince, appUUID)
			delete(z.vmiDeleteCount, appUUID)
			continue
		}

		if vmi.Status.Phase == virtv1.Running {
			delete(z.vmiPendingSince, appUUID)
			delete(z.vmiDeleteCount, appUUID)
			continue
		}

		if vmi.Status.Phase != virtv1.Pending {
			delete(z.vmiPendingSince, appUUID)
			delete(z.vmiDeleteCount, appUUID)
			continue
		}

		if !z.virtLauncherActiveOnThisNode(appKubeName) {
			delete(z.vmiPendingSince, appUUID)
			delete(z.vmiDeleteCount, appUUID)
			continue
		}

		// If checkAppsFailover set a suppress window for this app (because a
		// failover is actively landing on this node), skip the force-delete.
		// The window self-extends every tick while the Terminating pod exists.
		if until, ok := z.vmiFailoverSuppressUntil[appUUID]; ok {
			if now.Before(until) {
				log.Functionf("checkStuckPendingVMI: aiUUID:%s VMI:%s failover suppress active until %v; skipping",
					appUUID, vmi.Name, until)
				delete(z.vmiPendingSince, appUUID)
				continue
			}
			delete(z.vmiFailoverSuppressUntil, appUUID)
		}

		since, ok := z.vmiPendingSince[appUUID]
		if !ok {
			z.vmiPendingSince[appUUID] = now
			continue
		}
		if now.Sub(since) < pendingVMIDeleteThreshold {
			continue
		}

		if z.vmiDeleteCount[appUUID] >= pendingVMIMaxDeletes {
			log.Errorf("checkStuckPendingVMI: aiUUID:%s VMI:%s stuck Pending after %d deletes; giving up",
				appUUID, vmi.Name, pendingVMIMaxDeletes)
			continue
		}

		log.Noticef("checkStuckPendingVMI: aiUUID:%s VMI:%s Pending >%v on this node with active/error virt-launcher; force-deleting (attempt %d/%d)",
			appUUID, vmi.Name, pendingVMIDeleteThreshold, z.vmiDeleteCount[appUUID]+1, pendingVMIMaxDeletes)
		if err := kubeapi.TryFastDeleteVmi(log, virtClient, vmi.Name); err != nil {
			log.Errorf("checkStuckPendingVMI: TryFastDeleteVmi VMI:%s err:%v", vmi.Name, err)
			continue
		}
		z.vmiDeleteCount[appUUID]++
		z.vmiDeleteSuppressUntil[appUUID] = now.Add(pendingVMISuppressWindow)
		delete(z.vmiPendingSince, appUUID)
	}
}

// findAppVMI returns the VMI whose replicaset prefix matches the app kube name.
func findAppVMI(vmis []virtv1.VirtualMachineInstance, appKubeName string) *virtv1.VirtualMachineInstance {
	for i := range vmis {
		if len(vmis[i].OwnerReferences) == 0 {
			continue
		}
		if vmis[i].OwnerReferences[0].Name == appKubeName {
			return &vmis[i]
		}
	}
	return nil
}

// virtLauncherActiveOnThisNode returns true iff a virt-launcher pod for the
// given app is on the local node and either in Running phase or in a pod-level
// error state (Failed, or Running with a container stuck in CrashLoopBackOff /
// error-waiting / terminated-with-error). In all of these, the cluster has
// placed the launcher here but the VMI is not making progress, which is the
// signature of the kubevirt/longhorn stuck-Pending-VMI condition.
//
// The pod is identified by name prefix "virt-launcher-<appKubeName>" since the
// App-Domain-Name label is set to status.DomainName (UUID.Version.AppNum)
// rather than appKubeName and a label-selector lookup would not match.
func (z *zedkube) virtLauncherActiveOnThisNode(appKubeName string) bool {
	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("virtLauncherActiveOnThisNode: get clientset: %v", err)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Errorf("virtLauncherActiveOnThisNode: list pods: %v", err)
		return false
	}
	vlPrefix := base.VMIPodNamePrefix + appKubeName
	for _, p := range pods.Items {
		if !strings.HasPrefix(p.Name, vlPrefix) {
			continue
		}
		if p.Spec.NodeName != z.nodeName {
			continue
		}
		if isPodTerminating(p) {
			continue
		}
		if p.Status.Phase == corev1.PodRunning ||
			p.Status.Phase == corev1.PodFailed ||
			podHasContainerError(p) {
			return true
		}
	}
	return false
}

// podHasContainerError returns true if any container in the pod is in a
// waiting state with an error-indicating reason (CrashLoopBackOff,
// ImagePullBackOff, ErrImagePull, CreateContainerError, RunContainerError)
// or has terminated with a non-zero exit code. These surface as "Error" or
// similar in kubectl's STATUS column even when Pod.Status.Phase=Running.
func podHasContainerError(p corev1.Pod) bool {
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil {
			switch w.Reason {
			case "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull",
				"CreateContainerError", "RunContainerError":
				return true
			}
		}
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
			return true
		}
	}
	return false
}

// suppressedStatusRunning returns (overrideValue, active) for the given app UUID.
// While active, checkAppsStatus pins the ENClusterAppStatus.StatusRunning field
// to the returned value so downstream consumers (zedmanager) do not observe a
// transient false during our own VMI delete + re-create.
func (z *zedkube) suppressedStatusRunning(appUUID string) (bool, bool) {
	until, ok := z.vmiDeleteSuppressUntil[appUUID]
	if !ok {
		return false, false
	}
	if time.Now().After(until) {
		delete(z.vmiDeleteSuppressUntil, appUUID)
		return false, false
	}
	return true, true
}
