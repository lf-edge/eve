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

		if !vmiPhaseIsPreRunning(vmi.Status.Phase) {
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

// vmiPhaseIsPreRunning reports whether the VMI phase represents a not-yet-running
// state. Returns true for Pending and Scheduling — both indicate the VM has not
// started. All other phases (Running, Succeeded, Failed, Unknown) return false.
func vmiPhaseIsPreRunning(phase virtv1.VirtualMachineInstancePhase) bool {
	return phase == virtv1.Pending || phase == virtv1.Scheduling
}

// virtLauncherPodIsActiveOnNode reports whether any virt-launcher pod for
// appKubeName is assigned to nodeName and in an active state. Active means
// the pod is Running, Failed, has a container-level error, or is in the
// Pending phase with Spec.NodeName already set (i.e. the init container is
// running but has not yet completed — Init:0/1 in kubectl STATUS).
//
// Pods are matched by name prefix rather than label selector because the
// App-Domain-Name label is set to the domain name (UUID.Version.AppNum),
// not appKubeName.
func virtLauncherPodIsActiveOnNode(pods []corev1.Pod, appKubeName, nodeName string) bool {
	vlPrefix := base.VMIPodNamePrefix + appKubeName
	for _, p := range pods {
		if !strings.HasPrefix(p.Name, vlPrefix) {
			continue
		}
		if p.Spec.NodeName != nodeName {
			continue
		}
		if isPodTerminating(p) {
			continue
		}
		if p.Status.Phase == corev1.PodRunning ||
			p.Status.Phase == corev1.PodFailed ||
			podHasContainerError(p) ||
			p.Status.Phase == corev1.PodPending {
			return true
		}
	}
	return false
}

// virtLauncherActiveOnThisNode returns true iff a virt-launcher pod for the
// given app is on the local node and in an active state. See
// virtLauncherPodIsActiveOnNode for the full definition of active.
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
	return virtLauncherPodIsActiveOnNode(pods.Items, appKubeName, z.nodeName)
}

// podHasContainerError returns true if any container in the pod is in a
// waiting state with an error-indicating reason (CrashLoopBackOff,
// ImagePullBackOff, ErrImagePull, CreateContainerError,
// CreateContainerConfigError, RunContainerError) or has terminated with a
// non-zero exit code. These surface as "Error" or similar in kubectl's STATUS
// column even when Pod.Status.Phase=Running. CreateContainerConfigError in
// particular covers a pod blocked on a missing Secret/ConfigMap (e.g. an
// orphaned CDI upload pod whose TLS secret was deleted), which must not be
// mistaken for a volume-mount wedge.
func podHasContainerError(p corev1.Pod) bool {
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil {
			switch w.Reason {
			case "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull",
				"CreateContainerError", "CreateContainerConfigError", "RunContainerError":
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
