// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func collectKubeStats(ctx *zedkubeContext) {
	// we are the elected leader, start collecting kube stats
	// regardless if we are in cluster or single node mode
	if ctx.isKubeStatsLeader {
		log.Noticef("collectKubeStats: Started collecting kube stats")

		clientset, err := getKubeClientSet()
		if err != nil {
			log.Errorf("collectKubeStats: can't get clientset %v", err)
			return
		}

		var podsInfo []types.KubePodInfo
		var nodesInfo []types.KubeNodeInfo

		nodes, err := getKubeNodes(clientset)
		if err != nil {
			log.Errorf("collectKubeStats: can't get nodes %v", err)
			return
		}
		for _, node := range nodes {
			nodeInfo := getKubeNodeInfo(node)
			nodesInfo = append(nodesInfo, *nodeInfo)
		}

		pods, err := getAppKubePods(clientset)
		if err != nil {
			log.Errorf("collectKubeStats: can't get pods %v", err)
			return
		}
		for _, pod := range pods {
			podInfo := getKubePodInfo(pod)
			podsInfo = append(podsInfo, *podInfo)
		}

		// Publish the cluster info, first w/ nodes and app pods
		clusterInfo := types.KubeClusterInfo{
			Nodes:   nodesInfo,
			AppPods: podsInfo,
		}
		ctx.pubKubeClusterInfo.Publish("global", clusterInfo)
	}
}

func getKubeNodes(clientset *kubernetes.Clientset) ([]corev1.Node, error) {
	nodes, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("getKubeNodes: can't get nodes %v", err)
		return nil, err
	}
	return nodes.Items, nil
}

func getKubeNodeInfo(node corev1.Node) *types.KubeNodeInfo {
	//log.Noticef("getKubeNodeInfo: node %s", node.Name)
	status := "Unknown"
	var lastTransitionTime time.Time
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			if condition.Status == corev1.ConditionTrue {
				status = "Ready"
			} else if condition.Status == corev1.ConditionFalse {
				status = "NotReady"
			} else if condition.Status == corev1.ConditionUnknown {
				status = "Unknown"
			}
			lastTransitionTime = condition.LastTransitionTime.Time
			break
		}
	}

	isMaster := false
	isEtcd := false
	if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
		isMaster = true
	}
	if _, ok := node.Labels["node-role.kubernetes.io/etcd"]; ok {
		isEtcd = true
	}

	// Get creation time
	creationTimestamp := node.CreationTimestamp.Time

	// Get API version
	kubeletVersion := node.Status.NodeInfo.KubeletVersion

	// Get internal and external IPs
	var internalIP, externalIP string
	for _, address := range node.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			internalIP = address.Address
		} else if address.Type == corev1.NodeExternalIP {
			externalIP = address.Address
		}
	}

	// Check if the node is schedulable
	schedulable := !node.Spec.Unschedulable
	log.Functionf("getKubeNodeInfo: node %s, status %s, isMaster %v, isEtcd %v, creationTime %v, lastTrasitionTime %v, kubeletVersion %s, internalIP %s, externalIP %s, schedulable %v",
		node.Name, status, isMaster, isEtcd, creationTimestamp, lastTransitionTime, kubeletVersion, internalIP, externalIP, schedulable)

	nodeInfo := types.KubeNodeInfo{
		Name:               node.Name,
		Status:             convertStringToKubeNodeStatus(status),
		IsMaster:           isMaster,
		IsEtcd:             isEtcd,
		CreationTime:       creationTimestamp,
		LastTransitionTime: lastTransitionTime,
		KubeletVersion:     kubeletVersion,
		InternalIP:         internalIP,
		ExternalIP:         externalIP,
		Schedulable:        schedulable,
	}

	return &nodeInfo
}

func getAppKubePods(clientset *kubernetes.Clientset) ([]corev1.Pod, error) {
	// List pods in the namespace
	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("getAppKubePods: can't get nodes %v", err)
		return nil, err
	}
	return pods.Items, nil
}

func getKubePodInfo(pod corev1.Pod) *types.KubePodInfo {
	status := pod.Status.Phase
	restartCount := int32(0)
	var restartTimestamp time.Time
	for _, containerStatus := range pod.Status.ContainerStatuses {
		restartCount += containerStatus.RestartCount
		if containerStatus.LastTerminationState.Terminated != nil {
			restartTimestamp = containerStatus.LastTerminationState.Terminated.FinishedAt.Time
		}
	}

	CreationTimestamp := pod.CreationTimestamp.Time
	PodIP := pod.Status.PodIP
	NodeName := pod.Spec.NodeName

	log.Functionf("getKubePodInfo: pod %s, status %s, restartCount %d, restartTimestamp %v, creationTime %v, podIP %s, nodeName %s",
		pod.Name, status, restartCount, restartTimestamp, CreationTimestamp, PodIP, NodeName)

	podInfo := types.KubePodInfo{
		Name:              pod.Name,
		Status:            convertStringToKubePodStatus(string(status)),
		RestartCount:      restartCount,
		RestartTimestamp:  restartTimestamp,
		CreationTimestamp: CreationTimestamp,
		PodIP:             PodIP,
		NodeName:          NodeName,
	}
	return &podInfo
}

// convertStringToKubeNodeStatus converts a string status to a KubeNodeStatus.
func convertStringToKubeNodeStatus(status string) types.KubeNodeStatus {
	switch status {
	case "Ready":
		return types.KubeNodeStatusReady
	case "NotReady":
		return types.KubeNodeStatusNotReady
	case "NotReachable":
		return types.KubeNodeStatusNotReachable
	default:
		return types.KubeNodeStatusUnknown
	}
}

// convertStringToKubePodStatus converts a string status to a KubePodStatus.
func convertStringToKubePodStatus(status string) types.KubePodStatus {
	switch status {
	case "Pending":
		return types.KubePodStatusPending
	case "Running":
		return types.KubePodStatusRunning
	case "Succeeded":
		return types.KubePodStatusSucceeded
	case "Failed":
		return types.KubePodStatusFailed
	default:
		return types.KubePodStatusUnknown
	}
}

func getKubeClientSet() (*kubernetes.Clientset, error) {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("getKubeClientSet: can't get config %v", err)
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("getKubeClientSet: can't get clientset %v", err)
		return nil, err
	}
	return clientset, nil
}
