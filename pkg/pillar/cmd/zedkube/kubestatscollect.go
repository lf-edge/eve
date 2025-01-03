// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

func (z *zedkube) collectKubeStats() {
	// we are the elected leader, start collecting kube stats
	// regardless if we are in cluster or single node mode
	if z.isKubeStatsLeader.Load() {
		log.Functionf("collectKubeStats: Started collecting kube stats")

		clientset, err := getKubeClientSet()
		if err != nil {
			log.Errorf("collectKubeStats: can't get clientset %v", err)
			return
		}

		var podsInfo []types.KubePodInfo
		var nodesInfo []types.KubeNodeInfo
		var vmisInfo []types.KubeVMIInfo

		// get nodes
		nodes, err := getKubeNodes(clientset)
		if err != nil {
			log.Errorf("collectKubeStats: can't get nodes %v", err)
			return
		}
		for _, node := range nodes {
			nodeInfo := getKubeNodeInfo(node, z)
			nodesInfo = append(nodesInfo, *nodeInfo)
		}

		// get app pods
		pods, err := getAppKubePods(clientset)
		if err != nil {
			log.Errorf("collectKubeStats: can't get pods %v", err)
			return
		}
		for _, pod := range pods {
			if strings.HasPrefix(pod.ObjectMeta.Name, "virt-launcher-") { // skip virt-launcher pods
				continue
			}
			podInfo := getKubePodInfo(pod)
			podsInfo = append(podsInfo, *podInfo)
		}

		// get VMIs
		virtClient, err := getVirtClient()
		if err != nil {
			log.Errorf("collectKubeStats: can't get virtClient %v", err)
			return
		}
		vmis, err := getAppVMIs(virtClient)
		if err != nil {
			log.Errorf("collectKubeStats: can't get VMIs %v", err)
			return
		}
		for _, vmi := range vmis {
			vmiInfo := getAppVMIInfo(vmi)
			vmisInfo = append(vmisInfo, *vmiInfo)
		}

		// Publish the cluster info, first w/ nodes and app pods and VMIs
		ksi, err := kubeapi.PopulateKSI()
		if err != nil {
			log.Errorf("collectKubeStats: can't get KSI %v", err)
		}

		var podNsInfoList []types.KubePodNameSpaceInfo
		allNs, err := getAllNs()
		if err == nil {
			for _, ns := range allNs {
				nsInfo, err := getPodNsInfo(ns)
				if err == nil {
					podNsInfoList = append(podNsInfoList, nsInfo)
				}
			}
		}
		// Publish the cluster info
		clusterInfo := types.KubeClusterInfo{
			Nodes:     nodesInfo,
			AppPods:   podsInfo,
			AppVMIs:   vmisInfo,
			Storage:   ksi,
			PodNsInfo: podNsInfoList,
		}
		z.pubKubeClusterInfo.Publish("global", clusterInfo)
	}
	if !z.isKubeStatsLeader.Load() {
		// Unpublish so that there isn't anything to send to the controller
		items := z.pubKubeClusterInfo.GetAll()
		if _, ok := items["global"].(types.KubeClusterInfo); ok {
			z.pubKubeClusterInfo.Unpublish("global")
		}
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

func getKubeNodeInfo(node corev1.Node, z *zedkube) *types.KubeNodeInfo {
	status := types.KubeNodeStatusUnknown
	var lastTransitionTime time.Time
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			if condition.Status == corev1.ConditionTrue {
				status = types.KubeNodeStatusReady
			} else if condition.Status == corev1.ConditionFalse {
				status = types.KubeNodeStatusNotReady
			} else if condition.Status == corev1.ConditionUnknown {
				status = types.KubeNodeStatusNotReachable
			}
			lastTransitionTime = condition.LastTransitionTime.Time
			break
		}
	}

	isMaster := false
	usesEtcd := false
	if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
		isMaster = true
	}
	if _, ok := node.Labels["node-role.kubernetes.io/etcd"]; ok {
		usesEtcd = true
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
	log.Functionf("getKubeNodeInfo: node %s, status %v, isMaster %v, usesEtcd %v, creationTime %v, lastTrasitionTime %v, kubeletVersion %s, internalIP %s, externalIP %s, schedulable %v",
		node.Name, status, isMaster, usesEtcd, creationTimestamp, lastTransitionTime, kubeletVersion, internalIP, externalIP, schedulable)

	admission := types.NodeAdmissionUnknown
	clusterCfgs := z.subEdgeNodeClusterConfig.GetAll()
	_, ok := clusterCfgs["global"].(types.EdgeNodeClusterConfig)
	if !ok {
		// No EdgeNodeClusterConfig
		if !usesEtcd {
			admission = types.NodeAdmissionNotClustered
		}
		if usesEtcd {
			admission = types.NodeAdmissionLeaving
		}
	} else {
		// EdgeNodeClusterConfig
		if usesEtcd {
			// Expected state shortly after requesting cluster config
			admission = types.NodeAdmissionJoined
		} else {
			// Node not yet set etcd label, should be a shorter state
			admission = types.NodeAdmissionJoining
		}
	}

	nodeInfo := types.KubeNodeInfo{
		Name:               node.Name,
		Status:             status,
		IsMaster:           isMaster,
		UsesEtcd:           usesEtcd,
		CreationTime:       creationTimestamp,
		LastTransitionTime: lastTransitionTime,
		KubeletVersion:     kubeletVersion,
		InternalIP:         internalIP,
		ExternalIP:         externalIP,
		Schedulable:        schedulable,
		Admission:          admission,
		NodeID:             node.Labels["node-uuid"],
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
		Status:            convertStringToKubePodStatus(status),
		RestartCount:      restartCount,
		RestartTimestamp:  restartTimestamp,
		CreationTimestamp: CreationTimestamp,
		PodIP:             PodIP,
		NodeName:          NodeName,
	}
	return &podInfo
}

func getAppVMIs(virtClient kubecli.KubevirtClient) ([]virtv1.VirtualMachineInstance, error) {
	// List pods in the namespace
	vmiList, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).List(context.Background(), &metav1.ListOptions{})
	if err != nil {
		log.Errorf("getAppVMIs: can't get nodes %v", err)
		return nil, err
	}
	return vmiList.Items, nil
}

func getAppVMIInfo(vmi virtv1.VirtualMachineInstance) *types.KubeVMIInfo {
	// Extract information from the VMI
	name := vmi.Name
	creationTime := vmi.CreationTimestamp.Time
	phase := vmi.Status.Phase
	nodeName := vmi.Status.NodeName
	ready := false
	var lastTransitionTime time.Time
	for _, condition := range vmi.Status.Conditions {
		if condition.Type == virtv1.VirtualMachineInstanceReady && condition.Status == corev1.ConditionTrue {
			lastTransitionTime = condition.LastTransitionTime.Time
			ready = true
			break
		}
	}

	// Log the information
	log.Functionf("getAppVMIInfo: VMI %s, createtime %v, phase %s, lastTransitionTime %v, nodeName %s, ready %t",
		name, creationTime, phase, lastTransitionTime, nodeName, ready)

	vmiInfo := types.KubeVMIInfo{
		Name:               name,
		Status:             convertStringToKubeVMIStatus(phase),
		CreationTime:       creationTime,
		LastTransitionTime: lastTransitionTime,
		IsReady:            ready,
		NodeName:           nodeName,
	}

	return &vmiInfo
}

// convertStringToKubePodStatus converts a string status to a KubePodStatus.
func convertStringToKubePodStatus(phase corev1.PodPhase) types.KubePodStatus {
	switch phase {
	case corev1.PodPending:
		return types.KubePodStatusPending
	case corev1.PodRunning:
		return types.KubePodStatusRunning
	case corev1.PodSucceeded:
		return types.KubePodStatusSucceeded
	case corev1.PodFailed:
		return types.KubePodStatusFailed
	default:
		return types.KubePodStatusUnknown
	}
}

func convertStringToKubeVMIStatus(status virtv1.VirtualMachineInstancePhase) types.KubeVMIStatus {
	switch status {
	case virtv1.VmPhaseUnset:
		return types.KubeVMIStatusUnset
	case virtv1.Pending:
		return types.KubeVMIStatusPending
	case virtv1.Scheduling:
		return types.KubeVMIStatusScheduling
	case virtv1.Scheduled:
		return types.KubeVMIStatusScheduled
	case virtv1.Running:
		return types.KubeVMIStatusRunning
	case virtv1.Succeeded:
		return types.KubeVMIStatusSucceeded
	case virtv1.Failed:
		return types.KubeVMIStatusFailed
	default:
		return types.KubeVMIStatusUnknown
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

func getVirtClient() (kubecli.KubevirtClient, error) {
	config, err := kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("getVirtClient: can't get config %v", err)
		return nil, err
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		log.Errorf("getVirtClient: can't get client %v", err)
		return nil, err
	}
	return virtClient, nil
}
