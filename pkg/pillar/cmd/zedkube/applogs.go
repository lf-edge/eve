// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
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

	// "Thu Aug 17 05:39:04 UTC 2023"
	timestampRegex := regexp.MustCompile(`(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \w+ \d{4})`)
	nowStr := time.Now().String()

	var sinceSec int64
	sinceSec = logcollectInterval
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		if aiconfig.FixedResources.VirtualizationMode != types.NOHYPER {
			continue
		}
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

		pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("app=%s", kubeName),
		})
		if err != nil {
			logrus.Errorf("checkReplicaSetMetrics: can't get pod %v", err)
			continue
		}
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.ObjectMeta.Name, kubeName) {
				contName = pod.ObjectMeta.Name
				break
			}
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

			matches := timestampRegex.FindStringSubmatch(logLine)
			var timeStr string
			if len(matches) > 0 {
				timeStr = matches[0]
				ts := strings.Split(logLine, timeStr)
				if len(ts) > 1 {
					logLine = ts[0]
				}
			} else {
				timeStr = nowStr
			}
			// Process and print the log line here
			aiLogger := z.appContainerLogger.WithFields(logrus.Fields{
				"appuuid":       aiconfig.UUIDandVersion.UUID.String(),
				"containername": contName,
				"eventtime":     timeStr,
			})
			aiLogger.Infof("%s", logLine)
		}
		if scanner.Err() != nil {
			if scanner.Err() == io.EOF {
				break // Break out of the loop when EOF is reached
			}
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

	options := metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", z.nodeName),
	}
	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), options)
	if err != nil {
		log.Errorf("checkAppsStatus: can't get pods %v", err)
		return
	}

	pub := z.pubENClusterAppStatus
	stItems := pub.GetAll()
	var oldStatus *types.ENClusterAppStatus
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		if !aiconfig.IsDesignatedNodeID { // if not for cluster app, skip
			continue
		}
		encAppStatus := types.ENClusterAppStatus{
			AppUUID:    aiconfig.UUIDandVersion.UUID,
			IsDNidNode: aiconfig.IsDesignatedNodeID,
		}
		contName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)

		for _, pod := range pods.Items {
			contVMIName := "virt-launcher-" + contName
			log.Functionf("checkAppsStatus: pod %s, cont %s", pod.Name, contName)
			if strings.HasPrefix(pod.Name, contName) || strings.HasPrefix(pod.Name, contVMIName) {
				encAppStatus.ScheduledOnThisNode = true
				if pod.Status.Phase == corev1.PodRunning {
					encAppStatus.StatusRunning = true
				}
				break
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

		if oldStatus == nil || oldStatus.IsDNidNode != encAppStatus.IsDNidNode ||
			oldStatus.ScheduledOnThisNode != encAppStatus.ScheduledOnThisNode || oldStatus.StatusRunning != encAppStatus.StatusRunning {
			log.Functionf("checkAppsStatus: status differ, publish")
			z.pubENClusterAppStatus.Publish(aiconfig.Key(), encAppStatus)
		}
	}
}
