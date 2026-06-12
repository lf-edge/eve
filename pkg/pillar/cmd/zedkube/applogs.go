// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collect App logs from pods which covers both containers and virt-launcher pods
func (z *zedkube) collectAppLogs() {
	sub := z.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		return
	}

	var sinceSec int64
	sinceSec = logcollectInterval

	// Cache all pods once and separate into virt-launcher pods (for VMI apps) and other pods (for native containers).
	podsAllList, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("collectAppLogs: can't list pods in namespace %s: %v", kubeapi.EVEKubeNameSpace, err)
		return
	}
	virtLauncherPods := make([]corev1.Pod, 0)
	nativePods := make([]corev1.Pod, 0)
	for _, p := range podsAllList.Items {
		if strings.HasPrefix(p.ObjectMeta.Name, "virt-launcher-") {
			virtLauncherPods = append(virtLauncherPods, p)
		} else {
			nativePods = append(nativePods, p)
		}
	}

	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		if !aiconfig.IsDesignatedNodeID {
			continue
		}
		kubeName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)
		contName := kubeName
		opt := &corev1.PodLogOptions{}
		if z.appLogStarted {
			opt = &corev1.PodLogOptions{
				SinceSeconds: &sinceSec,
			}
		} else {
			z.appLogStarted = true
		}

		// First try the normal app pods (native containers) from the cached list
		found := false
		for _, pod := range nativePods {
			if strings.HasPrefix(pod.ObjectMeta.Name, kubeName) {
				contName = pod.ObjectMeta.Name
				found = true
				break
			}
		}

		// If not found and this is a VMI-backed app, search the cached virt-launcher pods
		// and read the guest console container logs.
		if !found && aiconfig.FixedResources.VirtualizationMode != types.NOHYPER {
			// virt-launcher-<displayName>-<uuidprefix>-<suffix>
			// where <uuidprefix> is the first 5 chars of the UUID.
			// the virt-launcher pod has a init-container 'guest-console-log' to tail -f VMI console logs.
			// the section is to get those logs only from this container
			uuidStr := aiconfig.UUIDandVersion.UUID.String()
			uuidNoDash := strings.ReplaceAll(uuidStr, "-", "")
			uuidPrefix := uuidNoDash
			if len(uuidPrefix) > 5 {
				uuidPrefix = uuidPrefix[:5]
			}
			vmiPrefix := fmt.Sprintf("virt-launcher-%s-%s", aiconfig.DisplayName, uuidPrefix)
			for _, pod := range virtLauncherPods {
				if strings.HasPrefix(pod.ObjectMeta.Name, vmiPrefix) {
					contName = pod.ObjectMeta.Name
					// instruct GetLogs to fetch the guest console container
					if opt == nil {
						opt = &corev1.PodLogOptions{}
					}
					opt.Container = "guest-console-log"
					found = true
					break
				}
			}
		}

		if !found {
			// No matching pod found for this app; skip
			continue
		}

		req := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).GetLogs(contName, opt)
		podLogs, err := req.Stream(context.Background())
		if err != nil {
			log.Errorf("collectAppLogs: pod %s, log error %v", contName, err)
			continue
		}
		defer podLogs.Close()

		scanner := bufio.NewScanner(podLogs)
		for scanner.Scan() {
			logLine := scanner.Text()

			// Process and print the log line here
			aiLogger := z.appContainerLogger.WithFields(logrus.Fields{
				"appuuid": aiconfig.UUIDandVersion.UUID.String(),
			})
			aiLogger.Infof("%s", logLine)
		}
		if err := scanner.Err(); err != nil {
			log.Errorf("collectAppLogs: scanner error for pod %s: %v", contName, err)
		}
	}
}

func (z *zedkube) checkAppsStatus() {
	sub := z.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("checkAppsStatus: can't get clientset %v", err)
		return
	}

	stItems := z.pubENClusterAppStatus.GetAll()

	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("checkAppsStatus: can't get pods %v", err)
		// If we can't get pods, process the error and return
		z.handleKubePodsGetError(items, stItems)
		return
	}

	z.getKubePodsError.getKubePodsErrorTime = time.Time{}
	z.getKubePodsError.processedErrorCondition = false

	var oldStatus *types.ENClusterAppStatus
	for _, item := range items {
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
		for _, pod := range pods.Items {
			contVMIName := "virt-launcher-" + contName
			log.Functionf("checkAppsStatus: pod %s, looking for cont %s", pod.Name, contName)
			foundVMIPod := strings.HasPrefix(pod.Name, contVMIName)
			if strings.HasPrefix(pod.Name, contName) || foundVMIPod {
				// Case 1
				if isPodTerminating(pod) {
					// This is the old copy on the failed node, ignore it.
					// Next in the list should be a new copy in 'Scheduling'
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
			}
		}

		for _, st := range stItems {
			aiStatus := st.(types.ENClusterAppStatus)
			if aiStatus.AppUUID == aiconfig.UUIDandVersion.UUID {
				oldStatus = &aiStatus
				break
			}
		}

		log.Functionf("checkAppsStatus: devname %s, pod (%d) status %+v, old %+v", z.nodeName, len(pods.Items), encAppStatus, oldStatus)

		// If this is first time after zedkube started (oldstatus is nil) and I am DNid and the app is not scheduled
		// on this node. This condition is seen for two reasons
		// 1) We just got appinstanceconfig and domainmgr did not get chance to start it yet, timing issue, zedkube checked first
		// 2) We are checking after app failover to other node, either this node network failed and came back or this just got rebooted
		if oldStatus == nil || !oldStatus.Equal(encAppStatus) {
			log.Functionf("checkAppsStatus: aiDisplayName:%s aiUUID:%s status differ, publish", aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)
			// If app scheduled on this node, could happen for 3 reasons.
			// 1) I am designated node.
			// 2) I am not designated node but failover happened.
			// 3) I am designated node but this is failback after failover.
			z.pubENClusterAppStatus.Publish(aiconfig.Key(), encAppStatus)
		}
	}
}

func (z *zedkube) handleKubePodsGetError(items, stItems map[string]interface{}) {
	if z.getKubePodsError.getKubePodsErrorTime.IsZero() {
		now := time.Now()
		z.getKubePodsError.getKubePodsErrorTime = now
		log.Noticef("handleKubePodsGetError: can't get pods, set error time")
	} else if time.Since(z.getKubePodsError.getKubePodsErrorTime) > 2*time.Minute {
		// The settings of kubernetes the node is 'NotReady' after unreachable for 1 minute,
		// and the replicaSet policy for POD/VMI is after 30 seconds post the 'NotReady' node
		// the App will be rescheduled to other node. So, we use the 2 minutes as the threshold
		if z.getKubePodsError.processedErrorCondition == false {
			z.getKubePodsError.processedErrorCondition = true
			for _, item := range items {
				aiconfig := item.(types.AppInstanceConfig)
				for _, st := range stItems {
					aiStatus := st.(types.ENClusterAppStatus)
					if aiStatus.AppUUID == aiconfig.UUIDandVersion.UUID {
						// if we used to publish the status, of this app is scheduled on this node
						// need to reset this, since we have lost the connection to the kubernetes
						// for longer time than the app is to be migrated to other node
						if aiStatus.ScheduledOnThisNode {
							aiStatus.ScheduledOnThisNode = false
							z.pubENClusterAppStatus.Publish(aiconfig.Key(), aiStatus)
							log.Noticef("handleKubePodsGetError: can't get pods set ScheduledOnThisNode off for %s, ", aiconfig.DisplayName)
						}
					}
				}
			}
		}
	}
}
