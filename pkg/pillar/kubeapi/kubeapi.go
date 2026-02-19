// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	netclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"kubevirt.io/client-go/kubecli"
)

const (
	// EVEKubeNameSpace : Kubernetes namespace used to deploy VMIs/Pods running
	// user applications.
	EVEKubeNameSpace = "eve-kube-app"
	// EVEkubeConfigFile : K3s config file path.
	EVEkubeConfigFile = "/run/.kube/k3s/k3s.yaml"
	// NetworkInstanceNAD : name of a (singleton) NAD used to define connection between
	// pod and (any) network instance.
	NetworkInstanceNAD = "network-instance-attachment"
	// VolumeCSIClusterStorageClass : CSI clustered storage class
	VolumeCSIClusterStorageClass = "longhorn"
	// VolumeCSIStorageClassReplicaPrefix : prefix for storage classes defining different replica counts
	VolumeCSIStorageClassReplicaPrefix = "lh-sc-rep"
	// VolumeCSILocalStorageClass : default local storage class
	VolumeCSILocalStorageClass = "local-path"
	// KubevirtPodsRunning : Wait for node to be ready, and require kubevirt namespace have at least 4 pods running
	// (virt-api, virt-controller, virt-handler, and virt-operator)
	KubevirtPodsRunning = 4
	// EVEAppDomainNameLbl is the label key applied to vmi/vmirs to associate it with the eve domain
	EVEAppDomainNameLbl = "App-Domain-Name"
	// KubevirtVMINameLbl is a label applied to a virt-launcher pod which contains the associated vmi object name
	KubevirtVMINameLbl = "vm.kubevirt.io/name"

	// TieBreakerNodeLbl is the label key applied to a kubernetes node
	TieBreakerNodeLbl = "tie-breaker-node"
	// TieBreakerNodeSet is the label value expected with the label TieBreakerNodeLbl
	TieBreakerNodeSet = "true"

	// DefaultLonghornScFullReplicaCount is the default replica count for a volume using the default
	// 'longhorn' StorageClass which can sustain a replica failure and still be redundant.
	DefaultLonghornScFullReplicaCount = 3

	// DefaultTieBreakerReplicaCount is the replica count for a tie breaker cluster using
	// the VolumeCSIStorageClassReplicaPrefix+"2" storage class.
	DefaultTieBreakerReplicaCount = 2

	// K3sConfigOverrideDir - default dir for k3s config override
	K3sConfigOverrideDir string = types.SealedDirName

	// K3sConfigOverrideFilename - path for controller defined k3s config additions and overridden keys
	K3sConfigOverrideFilename string = "k3s-user-override.yaml"
)

const (
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// GetKubeConfig : Get handle to Kubernetes config
func GetKubeConfig() (*rest.Config, error) {
	// Build the configuration from the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", EVEkubeConfigFile)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// GetClientSet : Get handle to kubernetes clientset
func GetClientSet() (*kubernetes.Clientset, error) {

	// Build the configuration from the provided kubeconfig file
	config, err := GetKubeConfig()
	if err != nil {
		return nil, err
	}

	// Create the Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

// GetNetClientSet : Get handle to kubernetes netclientset
func GetNetClientSet() (*netclientset.Clientset, error) {

	// Build the configuration from the provided kubeconfig file
	config, err := GetKubeConfig()
	if err != nil {
		return nil, err
	}

	// Create the Kubernetes netclientset
	nclientset, err := netclientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return nclientset, nil
}

/* NOTE: This code is commented out instead of deleting, just to keep a reference in case
 * we decide to move back to using k8s API.
 *
// GetKubevirtClientSet : Get handle to kubernetes kubevirt clientset
func GetKubevirtClientSet(kubeconfig *rest.Config) (KubevirtClientset, error) {

	if kubeconfig == nil {
		c, err := GetKubeConfig()
		if err != nil {
			return nil, err
		}
		kubeconfig = c
	}

	config := *kubeconfig
	config.ContentConfig.GroupVersion = &kubevirtapi.GroupVersion
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	coreClient, err := kubernetes.NewForConfig(&config)
	if err != nil {
		return nil, err
	}

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &kubevirtClient{restClient: client, Clientset: coreClient}, nil
}
*/

// WaitForKubernetes : Wait until kubernetes server is ready
func WaitForKubernetes(agentName string, ps *pubsub.PubSub, stillRunning *time.Ticker,
	alsoWatch ...pubsub.ChannelWatch) (err error) {

	var watches []pubsub.ChannelWatch
	stillRunningWatch := pubsub.ChannelWatch{
		Chan: reflect.ValueOf(stillRunning.C),
		Callback: func(_ interface{}) (exit bool) {
			ps.StillRunning(agentName, warningTime, errorTime)
			return false
		},
	}
	watches = append(watches, stillRunningWatch)

	var config *rest.Config
	checkTicker := time.NewTicker(5 * time.Second)
	startTime := time.Now()
	const maxWaitTime = 10 * time.Minute
	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(checkTicker.C),
		Callback: func(_ interface{}) (exit bool) {
			currentTime := time.Now()
			if currentTime.Sub(startTime) > maxWaitTime {
				err = fmt.Errorf("time exceeded 10 minutes")
				return true
			}
			if _, err := os.Stat(EVEkubeConfigFile); err == nil {
				config, err = GetKubeConfig()
				if err == nil {
					return true
				}
			}
			return false
		},
	})

	watches = append(watches, alsoWatch...)

	// wait until the Kubernetes server is started
	pubsub.MultiChannelWatch(watches)

	if err != nil {
		return err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	devUUID, err := os.Hostname()
	if err != nil {
		return err
	}

	// Wait for the Kubernetes clientset to be ready, node ready and kubevirt pods in Running status
	readyCh := make(chan bool)
	go waitForNodeReady(client, readyCh, devUUID)

	watches = nil
	watches = append(watches, stillRunningWatch)
	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(readyCh),
		Callback: func(_ interface{}) (exit bool) {
			return true
		},
	})
	watches = append(watches, alsoWatch...)
	pubsub.MultiChannelWatch(watches)
	return nil
}

func waitForLonghornReady(client *kubernetes.Clientset, hostname string) error {
	// Only wait for longhorn if we are not in base-k3s mode.
	if err := registrationAppliedToCluster(); err == nil {
		// In base k3s mode, pillar not deploying redundant storage
		return nil
	}

	// First we'll gate on the longhorn daemonsets existing
	lhDaemonsets, err := client.AppsV1().DaemonSets("longhorn-system").
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list longhorn daemonsets: %v", err)
	}
	// Keep a running table of which expected Daemonsets exist
	var lhExpectedDaemonsets = map[string]bool{
		"longhorn-manager":    false,
		"longhorn-csi-plugin": false,
		"engine-image":        false,
	}
	// Check if each daemonset is running and ready on this node
	for _, lhDaemonset := range lhDaemonsets.Items {
		lhDsName := lhDaemonset.GetName()
		for dsPrefix := range lhExpectedDaemonsets {
			if strings.HasPrefix(lhDsName, dsPrefix) {
				lhExpectedDaemonsets[dsPrefix] = true
			}
		}

		var labelSelectors []string
		for dsLabelK, dsLabelV := range lhDaemonset.Spec.Template.Labels {
			labelSelectors = append(labelSelectors, dsLabelK+"="+dsLabelV)
		}
		pods, err := client.CoreV1().Pods("longhorn-system").List(context.Background(), metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + hostname,
			LabelSelector: strings.Join(labelSelectors, ","),
		})
		if err != nil {
			return fmt.Errorf("unable to get daemonset pods on node: %v", err)
		}
		if len(pods.Items) != 1 {
			return fmt.Errorf("longhorn daemonset:%s missing on this node", lhDsName)
		}
		for _, pod := range pods.Items {
			if pod.Status.Phase != "Running" {
				return fmt.Errorf("daemonset:%s not running on node", lhDsName)
			}
			for _, podContainerState := range pod.Status.ContainerStatuses {
				if !podContainerState.Ready {
					return fmt.Errorf("daemonset:%s not ready on node", lhDsName)
				}
			}
		}
	}

	for dsPrefix, dsPrefixExists := range lhExpectedDaemonsets {
		if !dsPrefixExists {
			return fmt.Errorf("longhorn missing daemonset:%s", dsPrefix)
		}
	}

	return nil
}

func waitForNodeReady(client *kubernetes.Clientset, readyCh chan bool, devUUID string) {
	err := wait.PollImmediate(time.Second, time.Minute*20, func() (bool, error) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			labelSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"node-uuid": devUUID}}
			options := metav1.ListOptions{
				LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
			nodes, err := client.CoreV1().Nodes().List(context.Background(), options)
			if err != nil {
				return err
			}

			var hostname string
			for _, node := range nodes.Items {
				hostname = node.Name
				break
			}
			if hostname == "" {
				return fmt.Errorf("node not found by label uuid %s", devUUID)
			}

			// Only wait for kubevirt if we are not in base-k3s mode.
			if err := registrationAppliedToCluster(); err == nil {
				// In base k3s mode, pillar not deploying kubevirt VM app instances
				return nil
			}

			// get all pods from kubevirt, and check if they are all running
			pods, err := client.CoreV1().Pods("kubevirt").
				List(context.Background(), metav1.ListOptions{
					FieldSelector: "status.phase=Running",
				})
			if err != nil {
				return err
			}
			// Wait for kubevirt namespace to have at least 4 pods running
			// (virt-api, virt-controller, virt-handler, and virt-operator)
			// to consider kubevirt system is ready
			if len(pods.Items) < KubevirtPodsRunning {
				return fmt.Errorf("kubevirt running pods less than 4")
			}

			err = waitForLonghornReady(client, hostname)
			return err
		})

		if err == nil {
			return true, nil
		}

		return false, nil
	})

	if err != nil {
		readyCh <- false
	} else {
		readyCh <- true
	}
}

// WaitForPVCReady : Loop until PVC is ready for timeout
func WaitForPVCReady(pvcName string, log *base.LogObject) error {
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("WaitForPVCReady failed to get clientset err %v", err)
		return err
	}

	i := 10
	var count int
	var err2 error
	for {
		pvcs, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
			List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("GetPVCInfo failed to list pvc info err %v", err)
			err2 = err
		} else {

			count = 0
			for _, pvc := range pvcs.Items {
				pvcObjName := pvc.ObjectMeta.Name
				if strings.Contains(pvcObjName, pvcName) {
					count++
					log.Noticef("WaitForPVCReady(%d): get pvc %s", count, pvcObjName)
				}
			}
			if count == 1 {
				return nil
			}
		}
		i--
		if i <= 0 {
			break
		}
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("WaitForPVCReady: time expired count %d, err %v", count, err2)
}

// CleanupStaleVMIRs : delete all VMI replica sets on single node. Used by domainmgr on startup.
// There are two replica set types.
// 1) vmirs (VM replica sets)
// 2) podrs (Pod replica sets, basically native containers)
// Iterate through all replicasets and delete those.
func CleanupStaleVMIRs() (int, error) {
	// Only wait for kubevirt if we are not in base-k3s mode.
	if err := registrationAppliedToCluster(); err == nil {
		// In base k3s mode, pillar not deploying kubevirt VM app instances
		return 0, nil
	}

	kubeconfig, err := GetKubeConfig()
	if err != nil {
		return 0, fmt.Errorf("couldn't get the Kube Config: %v", err)
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)
	if err != nil {
		return 0, fmt.Errorf("couldn't get the Kube client Config: %v", err)
	}

	ctx := context.Background()

	// get a list of our VM replica sets
	vmrsList, err := virtClient.ReplicaSet(EVEKubeNameSpace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("couldn't get the Kubevirt VM replcia sets: %v", err)
	}

	var count int
	for _, vmirs := range vmrsList.Items {

		if err := virtClient.ReplicaSet(EVEKubeNameSpace).Delete(ctx, vmirs.ObjectMeta.Name, metav1.DeleteOptions{}); err != nil {
			return count, fmt.Errorf("delete vmirs error: %v", err)
		}
		count++
	}

	// Get list of native container pods replica sets
	podrsList, err := virtClient.AppsV1().ReplicaSets(EVEKubeNameSpace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return count, fmt.Errorf("couldn't get the pod replica sets: %v", err)
	}

	for _, podrs := range podrsList.Items {

		err := virtClient.AppsV1().ReplicaSets(EVEKubeNameSpace).Delete(ctx, podrs.ObjectMeta.Name, metav1.DeleteOptions{})
		if err != nil {
			return count, fmt.Errorf("delete podrs error: %v", err)
		}
		count++
	}

	return count, nil
}

// DeleteControlPlanePodsOnNode : handle unresponsive/unreachable node
// - delete all control plane pods for kubevirt and longhorn-system
// - update kubevirt label and annotation placed on node for scheduling/VMI ready state.
func DeleteControlPlanePodsOnNode(log *base.LogObject, kubernetesHostName string) {
	if log == nil {
		return
	}
	if kubernetesHostName == "" {
		log.Errorf("kubernetesHostName is required!")
		return
	}

	config, err := GetKubeConfig()
	if err != nil {
		log.Errorf("can't get kubeconfig %v", err)
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("can't get clientset %v", err)
		return
	}

	log.Noticef("cleaning up control plane pods on host:%s", kubernetesHostName)

	// 1. Is the node unreachable?
	node, err := clientset.CoreV1().Nodes().Get(context.Background(), kubernetesHostName, metav1.GetOptions{})
	if (err != nil) || (node == nil) {
		log.Errorf("can't get node:%s object err:%v", kubernetesHostName, err)
		return
	}
	if !kubeNodeNotReporting(log, node) {
		log.Errorf("node:%s NOT declared unreachable long enough to force delete all kubevirt pods", kubernetesHostName)
		return
	}

	// 2. Modify kubevirt heartbeat to allow vmi to be marked not Ready
	node.Labels["kubevirt.io/schedulable"] = "false"
	heartbeatTs := time.Now().UTC().Format(time.RFC3339)
	node.Annotations["kubevirt.io/heartbeat"] = heartbeatTs
	log.Noticef("node:%s marking kubevirt label unschedulable and heartbeat to:%s", kubernetesHostName, heartbeatTs)
	_, err = clientset.CoreV1().Nodes().Update(context.TODO(), node, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("node:%s unable to update kubevirt label and annotation err:%v", kubernetesHostName, err)
	}

	log.Noticef("node:%s IS declared unreachable long enough to force delete all kubevirt pods", kubernetesHostName)

	// 3. find all the kubevirt pods on this node
	pods, err := clientset.CoreV1().Pods("kubevirt").List(context.Background(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + kubernetesHostName,
	})
	if err != nil {
		log.Errorf("can't get node:%s object err:%v", kubernetesHostName, err)
		return
	}

	// 3. Delete them all !
	// https://kubevirt.io/user-guide/cluster_admin/unresponsive_nodes/#deleting-stuck-vmis-when-the-whole-node-is-unresponsive
	// The length of this list should be max 4 (depending on scheduling): virt-api, virt-controller, virt-handler, virt-operator
	for _, pod := range pods.Items {
		podName := pod.ObjectMeta.Name

		log.Noticef("deleting kubevirt pod:%s", podName)

		gracePeriod := int64(0)
		propagationPolicy := metav1.DeletePropagationForeground
		err = clientset.CoreV1().Pods("kubevirt").Delete(context.Background(), podName,
			metav1.DeleteOptions{
				GracePeriodSeconds: &gracePeriod,
				PropagationPolicy:  &propagationPolicy,
			})
		if err != nil {
			log.Errorf("can't delete pod:%s err:%v", podName, err)
		}
	}

	log.Noticef("node:%s IS declared unreachable long enough to force delete all longhorn-system pods", kubernetesHostName)
	// 4. find all the kubevirt pods on this node
	pods, err = clientset.CoreV1().Pods("longhorn-system").List(context.Background(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + kubernetesHostName,
	})
	if err != nil {
		log.Errorf("can't get node:%s object err:%v", kubernetesHostName, err)
		return
	}

	// 5. Delete them all !
	for _, pod := range pods.Items {
		podName := pod.ObjectMeta.Name

		log.Noticef("deleting longhorn-system pod:%s", podName)

		gracePeriod := int64(0)
		propagationPolicy := metav1.DeletePropagationForeground
		err = clientset.CoreV1().Pods("longhorn-system").Delete(context.Background(), podName,
			metav1.DeleteOptions{
				GracePeriodSeconds: &gracePeriod,
				PropagationPolicy:  &propagationPolicy,
			})
		if err != nil {
			log.Errorf("Can't delete pod:%s err:%v", podName, err)
		}
	}
	return

}

func vmirsReplicaCountSet(log *base.LogObject, vmiRsName string, replicaCount int) error {
	config, err := GetKubeConfig()
	if err != nil {
		log.Errorf("vmirsReplicaCountSet: can't get kubeconfig %v", err)
		return err
	}

	kvClientset, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		log.Errorf("vmirsReplicaCountSet couldn't get the Kube client Config: %v", err)
		return err
	}

	vmirs, err := kvClientset.ReplicaSet(EVEKubeNameSpace).Get(context.Background(), vmiRsName, metav1.GetOptions{})
	if err == nil {
		reps := int32(replicaCount)
		vmirs.Spec.Replicas = &reps
		_, err := kvClientset.ReplicaSet(EVEKubeNameSpace).Update(context.Background(), vmirs, metav1.UpdateOptions{})
		if err != nil {
			log.Noticef("vmirsReplicaCountSet vmirs:%s scaled to %d err:%v", vmiRsName, replicaCount, err)
			return err
		}
	}
	log.Noticef("vmirsReplicaCountSet complete for vmirs:%s", vmiRsName)
	return nil
}

// DetachUtilVmirsReplicaReset manages retries around scaling down and back up the replica
// count of a vmirs to push the control plane into scheduling a new vmi
func DetachUtilVmirsReplicaReset(log *base.LogObject, vmiRsName string) (err error) {
	vmiRsResetMaxTries := 60
	vmiRsResetTry := 0
	// Retries to handle connection issues to virt-api
	for {
		vmiRsResetTry++
		if vmiRsResetTry > vmiRsResetMaxTries {
			log.Errorf("DetachOldWorkload vmirs scale reset timeout, breaking...")
			break
		}
		time.Sleep(time.Second * 1)
		err = vmirsReplicaCountSet(log, vmiRsName, 0)
		if err != nil {
			log.Errorf("DetachOldWorkload retrying scale:%s to 0 err:%v", vmiRsName, err)
			time.Sleep(time.Second * 2)
			continue
		}

		err = vmirsReplicaCountSet(log, vmiRsName, 1)
		if err != nil {
			log.Errorf("DetachOldWorkload retrying scale:%s to 1 err:%v", vmiRsName, err)
			time.Sleep(time.Second * 2)
			continue
		}
		log.Noticef("DetachOldWorkload vmirs:%s scale reset", vmiRsName)
		return nil
	}
	return
}

// GetVmiRsName returns the replicated VMI object name, the parent of a vmi
func GetVmiRsName(log *base.LogObject, appDomainName string) (string, error) {
	podList, err := GetVirtLauncherPods(log, appDomainName)
	if err != nil {
		return "", err
	}
	if len(podList.Items) == 0 {
		return "", fmt.Errorf("No pods found for appDomainName:%s", appDomainName)
	}
	// All virt-launcher pods will have the same vmirs, just pick the first one.
	pod := podList.Items[0]
	vmiName := ""
	val, lblExists := pod.ObjectMeta.Labels[KubevirtVMINameLbl]
	if lblExists {
		vmiName = val
	}

	//
	// Kubernetes and kubevirt api handles
	//
	config, err := GetKubeConfig()
	if err != nil {
		log.Errorf("GetVmiRsName: can't get kubeconfig %v", err)
		return "", err
	}
	kvClientset, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		log.Errorf("GetVmiRsName couldn't get the Kube client Config: %v", err)
		return "", err
	}

	vmiRsName := ""
	vmi, err := kvClientset.VirtualMachineInstance(EVEKubeNameSpace).Get(context.Background(), vmiName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if len(vmi.ObjectMeta.OwnerReferences) > 0 {
		vmiRsName = vmi.ObjectMeta.OwnerReferences[0].Name
	}
	return vmiRsName, nil
}

// GetVirtLauncherPods returns all virt-launcher pods associated with a VMI which is labeled for
// the App-Domain-Name supplied.  There can be more than one pod if one has recently failed and
// a new copy is currently scheduled (eg. app failover after a node becomes unreachable).
func GetVirtLauncherPods(log *base.LogObject, appDomainName string) (*corev1.PodList, error) {
	//
	// Setup Handles to kubernetes
	//
	config, err := GetKubeConfig()
	if err != nil {
		log.Errorf("GetVmiName: can't get kubeconfig %v", err)
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("GetVmiName: can't get clientset %v", err)
		return nil, err
	}

	vlPods, err := clientset.CoreV1().Pods(EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "kubevirt.io=virt-launcher," + EVEAppDomainNameLbl + "=" + appDomainName,
	})
	return vlPods, err
}

func kubeNodeNotReporting(log *base.LogObject, node *corev1.Node) (notreporting bool) {
	for _, condition := range node.Status.Conditions {
		if condition.Type != "Ready" {
			continue
		}
		// Found the ready condition
		if condition.Status == "True" {
			log.Errorf("DetachOldWorkload: returning due to node:%s health Ready", node.ObjectMeta.Name)
			notreporting = false
			return notreporting
		}

		if condition.Message != "Kubelet stopped posting node status." {
			log.Errorf("DetachOldWorkload: node:%s not reporting in", node.ObjectMeta.Name)
			notreporting = false
			return notreporting
		}
	}
	notreporting = true
	return notreporting
}

func tryFastDeleteVmi(log *base.LogObject, kvClientset kubecli.KubevirtClient, vmiName string) error {
	vmi, err := kvClientset.VirtualMachineInstance(EVEKubeNameSpace).Get(context.Background(), vmiName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// VMI deletion can get stuck when the kubevirt control plane has been interrupted
	// by some failover breaking access to a kubevirt api pod, remove finalizers and force the delete
	vmi.ObjectMeta.Finalizers = []string{}
	_, err = kvClientset.VirtualMachineInstance(vmi.ObjectMeta.Namespace).Update(context.Background(), vmi, metav1.UpdateOptions{})
	if err != nil {
		// Not fatal, just means the delete may take longer to process
		// Don't return an error here and disrupt the failover process
		log.Errorf("DetachOldWorkload vmi:%s finalizer update result err:%v", vmiName, err)
	}

	// Policy for all deletes in the failover path
	gracePeriod := int64(0)
	propagationPolicy := metav1.DeletePropagationForeground
	return kvClientset.VirtualMachineInstance(EVEKubeNameSpace).Delete(context.Background(), vmiName,
		metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
			PropagationPolicy:  &propagationPolicy,
		})
}

func getPodsLhVols(log *base.LogObject, pod *corev1.Pod) (lhVolNames []string) {
	if pod == nil {
		return
	}

	config, err := GetKubeConfig()
	if err != nil {
		log.Errorf("GetVmiName: can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("GetVmiName: can't get clientset %v", err)
	}

	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim == nil {
			continue
		}
		pvcName := vol.PersistentVolumeClaim.ClaimName

		pvc, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).Get(context.Background(), pvcName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("DetachOldWorkload Can't get failed pod:%s PVC:%s err:%v", pod.ObjectMeta.Name, pvcName, err)
			continue
		}
		if pvc.ObjectMeta.Annotations["volume.kubernetes.io/storage-provisioner"] != "driver.longhorn.io" {
			continue
		}
		lhVolNames = append(lhVolNames, pvc.Spec.VolumeName)
	}
	return lhVolNames
}

// DetachOldWorkload is used when EVE detects a node is no longer reachable and was running a VM app instance
// This function will find the storage attached to that workload and detach it so that the VM app instance
// can be started on a remaining ready node.
// Caller is required to detect the VM app instances which
func DetachOldWorkload(log *base.LogObject, failedNodeName string, appDomainName string, wdFunc func()) {
	detachStart := time.Now()
	if log == nil {
		return
	}
	if failedNodeName == "" {
		log.Errorf("DetachOldWorkload: a node name is required")
		return
	}
	if appDomainName == "" {
		log.Errorf("DetachOldWorkload: an app domain name is required")
		return
	}
	if wdFunc == nil {
		log.Errorf("DetachOldWorkload missing watchdog func")
		return
	}

	log.Noticef("DetachOldWorkload node:%s appDomainName:%s", failedNodeName, appDomainName)

	// Setup handles
	config, err := GetKubeConfig()
	if err != nil {
		log.Errorf("DetachOldWorkload: can't get kubeconfig %v", err)
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("DetachOldWorkload: can't get clientset %v", err)
		return
	}
	kvClientset, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		log.Errorf("DetachOldWorkload couldn't get the Kube client Config: %v", err)
		return
	}

	// 1. Determine list of virt-launcher pods on the node
	//
	// The Pod lookup MUST be completed with List()
	// A pod which has been terminating long enough to the point of 'tombstone'
	// may just return NotFound and no object
	//
	// The failover could have already started and the system could have two
	// virt-launcher pods already: one on failed node stuck in terminating
	// and a second on a new node stuck in Scheduling because volumes are
	// still attached to the old node.
	//
	// For now we only want references to the old copies so they can be deleted
	failedNodevLPodName := ""
	failedNodeVmiName := ""
	var terminatingVlPod *corev1.Pod
	vlPodList, err := GetVirtLauncherPods(log, appDomainName)
	if err != nil {
		log.Errorf("DetachOldWorkload: can't list virt-launcher pods err:%v", err)
		return
	}
	for _, pod := range vlPodList.Items {
		if pod.Spec.NodeName != failedNodeName {
			continue
		}
		val, lblExists := pod.ObjectMeta.Labels[KubevirtVMINameLbl]
		if lblExists {
			failedNodeVmiName = val
		}
		failedNodevLPodName = pod.ObjectMeta.Name
		log.Noticef("DetachOldWorkload found pod:%s vmi:%s on failedNode:%s", failedNodevLPodName, failedNodeVmiName, failedNodeName)
		terminatingVlPod = &pod
		break
	}

	// 2. Make sure the node is unreachable
	node, err := clientset.CoreV1().Nodes().Get(context.Background(), failedNodeName, metav1.GetOptions{})
	if (err != nil) || (node == nil) {
		log.Errorf("DetachOldWorkload: can't get node:%s object err:%v", failedNodeName, err)
		return
	}
	if !kubeNodeNotReporting(log, node) {
		log.Warnf("DetachOldWorkload: node not unreachable, exiting")
		return
	}

	// 3. Need VMIRs Name to scale replicas.  The VMIRs name is also the anchor which will not change over
	// a failover.
	vmiRsName, err := GetVmiRsName(log, appDomainName)

	// 4. Get all replicas on the failed node which are part of a longhorn volume backing a pvc claimed by the vmi
	// We will need these references to fix volumeattachment and nodeId references.
	lhVolNames := []string{}
	if terminatingVlPod != nil {
		lhVolNames = getPodsLhVols(log, terminatingVlPod)
	}
	var replicaNames []string
	var allReps []*lhv1beta2.ReplicaList
	var appHasStorageRedundancy = true
	for _, lhVolName := range lhVolNames {
		// First look at reps on the failed node
		failedNodeLhVolReps, err := LonghornReplicaList(failedNodeName, lhVolName)
		if err != nil {
			log.Errorf("DetachOldWorkload Can't get failed replicas err:%v", err)
			continue
		}
		allReps = append(allReps, failedNodeLhVolReps)
		for _, replica := range failedNodeLhVolReps.Items {
			replicaNames = append(replicaNames, replica.ObjectMeta.Name)
		}

		// Now look at all reps, can this vol sustain a failure?
		lhVolAllReps, err := LonghornReplicaList("", lhVolName)
		if err != nil {
			log.Errorf("DetachOldWorkload Can't get failed replicas err:%v", err)
			continue
		}
		volRedundant := lhVolHasHealthyReplicaWithoutNode(log, lhVolAllReps, failedNodeName)
		if !volRedundant {
			appHasStorageRedundancy = false
			break
		}
	}

	// This is the point of no return, make sure the volume has redundancy
	// if the only fully built replica is on the failed node, just exit.
	if !appHasStorageRedundancy {
		log.Errorf("Cluster failover of appDomainName:%s cannot continue, storage not redundant", appDomainName)
		return
	}

	// Log all actions before taking them
	detachLogRecipe := "DetachOldWorkload Cluster Detach volume from VM pod:%s vmi:%s failedNode:%s replicas:%s"
	log.Noticef(detachLogRecipe, failedNodevLPodName, failedNodeVmiName, failedNodeName, strings.Join(replicaNames, ","))

	// Start Cleanup
	DeleteControlPlanePodsOnNode(log, failedNodeName)

	// Policy for all deletes in the failover path
	gracePeriod := int64(0)
	propagationPolicy := metav1.DeletePropagationForeground

	// Push the kubevirt control plane to schedule new pod, otherwise this can be a larger delay
	if vmiRsName != "" {
		DetachUtilVmirsReplicaReset(log, vmiRsName)
	}

	// Delete virt-launcher pod on failed node
	if failedNodevLPodName != "" {
		log.Noticef("DetachOldWorkload Deleting virt-launcher pod:%s", failedNodevLPodName)
		err = clientset.CoreV1().Pods(EVEKubeNameSpace).Delete(context.Background(), failedNodevLPodName,
			metav1.DeleteOptions{
				GracePeriodSeconds: &gracePeriod,
				PropagationPolicy:  &propagationPolicy,
			})
		if err != nil {
			log.Errorf("DetachOldWorkload Can't delete terminating virt-launcher pod:%s err:%v", failedNodevLPodName, err)
		}
	}

	// Delete vmi on failed node
	if failedNodeVmiName != "" {
		log.Noticef("DetachOldWorkload Deleting vmi:%s", failedNodeVmiName)
		err := tryFastDeleteVmi(log, kvClientset, failedNodeVmiName)
		if err != nil {
			log.Errorf("DetachOldWorkload couldn't delete the Kubevirt VMI:%s for appDomainName:%s err:%v", failedNodeVmiName, appDomainName, err)
		}
	}

	// Delete replica for PVC on failed node
	for _, repList := range allReps {
		for _, replica := range repList.Items {
			log.Noticef("DetachOldWorkload Deleting replica:%s", replica.ObjectMeta.Name)
			if err := longhornReplicaDelete(replica.ObjectMeta.Name); err != nil {
				log.Errorf("DetachOldWorkload Can't delete failed replica:%s err:%v", replica.ObjectMeta.Name, err)
			}
		}
	}

	newVAReportsAttached := false
	maxVAAttachTries := 10 //about 30sec
	currentVAAttachTry := 0
	//
	// The final phase of application failover is cleanup of Volume Attachments and Volume Owner NodeID
	//	Error handling in this path should be treated with the following policy: log it, retry
	//
	for {
		wdFunc()

		currentVAAttachTry++

		log.Noticef("DetachOldWorkload verifying old VA gone, lh vol node IDs correct, and new VA attached try:%d", currentVAAttachTry)

		//
		// First try to force delete all Volume Attachments
		//
		time.Sleep(time.Second * 1)
		vaList, err := GetVolumeAttachmentFromHost(failedNodeName, log)
		if len(vaList) == 0 {
			log.Noticef("DetachOldWorkload node/%s volumeattachment list empty finally", failedNodeName)
			break
		}
		for _, va := range vaList {
			log.Noticef("DetachOldWorkload Deleting volumeattachment %s on remote node %s", va, failedNodeName)
			err = DeleteVolumeAttachment(va, log)
			if err != nil {
				log.Errorf("DetachOldWorkload Error deleting volumeattachment %s from PV %v", va, err)
				continue
			}
		}

		// Wait a moment for consistency
		time.Sleep(time.Second * 1)

		// Sometimes at this point we get an odd mismatch in the node listed in the:
		// - virt-launcher pod
		// - volumeattachment
		// - lh vol spec.nodeID
		// - lh vol engine spec.nodeID

		// Find the new nodeID
		newNodeName := ""
		vlPods, err := GetVirtLauncherPods(log, appDomainName)
		if err != nil {
			log.Errorf("DetachOldWorkload: can't list virt-launcher pods err:%v", err)
			return
		}
		for _, vlPod := range vlPods.Items {
			if vlPod.Spec.NodeName == failedNodeName {
				continue
			}

			// Found newly scheduled virt-launcher pod
			newNodeName = vlPod.Spec.NodeName

			// Get new ref to all its vols
			lhVolNames = getPodsLhVols(log, &vlPod)
		}

		// Force set new scheduled node id to allow the volume to start on the new node
		for _, lhVolName := range lhVolNames {
			err = longhornVolumeSetNode(lhVolName, newNodeName)
			log.Noticef("DetachOldWorkload: set lhVol:%s to node:%s err:%v", lhVolName, newNodeName, err)

			attached, err := GetVolumeAttachmentAttached(lhVolName, newNodeName, log)
			log.Noticef("DetachOldWorkload: check attachment lhVol:%s node:%s attached:%v err:%v", lhVolName, newNodeName, attached, err)
			newVAReportsAttached = attached
		}

		if newVAReportsAttached {
			// New Failed-over-app should start shortly
			break
		}
		if currentVAAttachTry > maxVAAttachTries {
			//
			break
		}
	}
	log.Noticef("DetachOldWorkload Completed failover for appDomainName:%s vmiRs: pod:%s duration:%v", appDomainName, vmiRsName, time.Since(detachStart))
	return
}

// IsClusterMode : Returns true if this node is part of a cluster by checking EdgeNodeClusterConfigFile
// If EdgeNodeClusterConfigFile exists and is > 0 bytes then this node is part of a cluster.
func IsClusterMode() bool {

	fileInfo, err := os.Stat(types.EdgeNodeClusterConfigFile)
	if os.IsNotExist(err) {
		logrus.Debugf("This node is not in cluster mode")
		return false
	} else if err != nil {
		logrus.Errorf("Error checking file '%s': %v", types.EdgeNodeClusterConfigFile, err)
		return false
	}

	if fileInfo.Size() > 0 {
		logrus.Debugf("This node is in cluster mode")
		return true
	}

	return false
}

// GetSupportedReplicaCountForCluster : returns the max replica count a cluster can support
func GetSupportedReplicaCountForCluster() (int, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return DefaultLonghornScFullReplicaCount, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return DefaultLonghornScFullReplicaCount, err
	}

	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{
		LabelSelector: TieBreakerNodeLbl + "=" + TieBreakerNodeSet,
	})
	if (err != nil) || (len(nodes.Items) == 0) {
		return DefaultLonghornScFullReplicaCount, err
	}
	// Tie breaker Node exists, limit replicas
	return DefaultTieBreakerReplicaCount, nil
}

// GetStorageClassForReplicaCount : returns the storage class associated with the replica count
func GetStorageClassForReplicaCount(count int) string {
	if count == DefaultLonghornScFullReplicaCount {
		return VolumeCSIClusterStorageClass
	}
	return fmt.Sprintf("%s%d", VolumeCSIStorageClassReplicaPrefix, count)
}
