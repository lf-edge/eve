// Copyright (c) 2025 Zededa, Inc.
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
)

func (z *zedkube) shouldDetachApp(oldStatus *types.ENClusterAppStatus, newStatus *types.ENClusterAppStatus) bool {
	return (oldStatus == nil) && newStatus.ScheduledOnThisNode
}

// Interface to determining a node allowed to make cluster-wide operations
func (z *zedkube) isDecisionNode() (isNode bool) {
	if z.isKubeStatsLeader.Load() {
		isNode = true
	}
	return isNode
}

func (z *zedkube) checkAppsFailover(wdFunc func()) {
	sub := z.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("checkAppsFailover: can't get clientset %v", err)
		return
	}

	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("checkAppsFailover: can't get pods %v", err)
		return
	}

	for _, item := range items {
		wdFunc()

		aiconfig := item.(types.AppInstanceConfig)
		encAppStatus := types.ENClusterAppStatus{
			AppUUID:    aiconfig.UUIDandVersion.UUID,
			IsDNidNode: aiconfig.IsDesignatedNodeID,
		}
		contName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)

		//
		// We're looking for two pods:
		// 1. An existing copy of a VMs virt-launcher pod which is terminating
		//  We use this as a starting anchor to find and detach persistent volumes
		//  So that the app can complete failover
		// 2. A new copy of a VMs virt-launcher pod which is starting on a new node
		//	We use this to fill in the ENClusterAppStatus above and tell the controller
		//	Where the app is moved to.
		//
		// Both Pods will be of the pattern <appname>-<uuid prefix>-<pod uuid suffix>
		terminatingVirtLauncherPod := ""
		terminatingNodeName := ""
		appDomainNameLbl := ""
		foundNewSchedulingPod := false
		var durationTerminating time.Duration

		for _, pod := range pods.Items {
			contVMIName := "virt-launcher-" + contName
			log.Noticef("checkAppsStatus: pod %s, looking for cont %s", pod.Name, contName)
			foundVMIPod := strings.HasPrefix(pod.Name, contVMIName)
			if strings.HasPrefix(pod.Name, contName) || foundVMIPod {
				// Case 1
				if isPodTerminating(pod) {
					// This is the old copy on the failed node, ignore it.
					// Next in the list should be a new copy in 'Scheduling'
					log.Noticef("aiDisplayName:%s aiUUID:%s Pod:%s is terminating onNode:%s deletionTime:%v",
						aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID, pod.Name, pod.Spec.NodeName, pod.ObjectMeta.DeletionTimestamp)
					terminatingVirtLauncherPod = pod.Name
					terminatingNodeName = pod.Spec.NodeName
					val, lblExists := pod.ObjectMeta.Labels[kubeapi.EVEAppDomainNameLbl]
					if lblExists {
						appDomainNameLbl = val
					}
					durationTerminating = getPodTerminatingTime(pod)
					continue
				}

				// Case 2
				if pod.Spec.NodeName == z.nodeName {
					encAppStatus.ScheduledOnThisNode = true
				}
				if pod.Status.Phase == corev1.PodRunning {
					encAppStatus.StatusRunning = true
				}
				if foundVMIPod {
					encAppStatus.AppIsVMI = true
					encAppStatus.AppKubeName, _ = base.GetVMINameFromVirtLauncher(pod.Name)
					log.Functionf("aiDisplayName:%s aiUUID:%s Pod:%s is attempting to start onNode:%s",
						aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID, pod.Name, pod.Spec.NodeName)
				}
				foundNewSchedulingPod = true
			}
		}

		//
		// If the app is running, nothing to do.
		//
		if (terminatingVirtLauncherPod == "") && encAppStatus.StatusRunning {
			// No need to failover
			log.Functionf("aiDisplayName:%s aiUUID:%s no terminating virtLauncher and reporting status running",
				aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)
			continue
		}

		//
		// App is not running, but kubernetes has not scheduled a new copy yet.
		//
		// Sometimes when a node becomes unreachable, the k3s control-plane seems to
		// Get stuck and not schedule a new VMI or virt-launcher pod.  This tested step seems
		// to push k3s into scheduling a new replica.
		//
		if !foundNewSchedulingPod && ((durationTerminating > (time.Minute * 2)) && z.isDecisionNode()) {
			log.Noticef("aiDisplayName:%s aiUUID:%s only a terminating pod for 2+min, moving to reset vmirs",
				aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)
			vmiRsName, err := kubeapi.GetVmiRsName(log, appDomainNameLbl)
			if err != nil {
				log.Errorf("aiDisplayName:%s aiUUID:%s vmirsname get err:%v",
					aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID, err)
			} else {
				err := kubeapi.DetachUtilVmirsReplicaReset(log, vmiRsName)
				if err != nil {
					log.Errorf("aiDisplayName:%s aiUUID:%s replica reset for vmirs:%s err:%v",
						aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID, vmiRsName, err)
				}
			}
			continue
		}

		log.Functionf("aiDisplayName:%s aiUUID:%s newStatus:%v",
			aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID, encAppStatus)

		if encAppStatus.ScheduledOnThisNode {
			log.Noticef("checkAppsFailover: failover start for appDomainName: %s", appDomainNameLbl)
			kubeapi.DetachOldWorkload(log, terminatingNodeName, appDomainNameLbl, wdFunc)
			log.Noticef("checkAppsFailover: failover complete for appDomainName: %s", appDomainNameLbl)
			continue
		}
	}
}
