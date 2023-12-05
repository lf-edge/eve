package kubeapi

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	netclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	kubeConfigFile      = "/run/.kube/k3s/k3s.yaml"
	errorTime           = 3 * time.Minute
	warningTime         = 40 * time.Second
	stillRunningInerval = 25 * time.Second
	eveNameSpace        = "eve-kube-app"
)

func GetKubeConfig() (error, *rest.Config) {
	// Build the configuration from the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		// fmt.Errorf("getKubeConfig: spec Read kubeconfig failed: %v", err)
		return err, nil
	}
	return nil, config
}

func GetClientSet() (*kubernetes.Clientset, error) {

	// Build the configuration from the provided kubeconfig file
	err, config := GetKubeConfig()
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

func GetNetClientSet() (*netclientset.Clientset, error) {

	// Build the configuration from the provided kubeconfig file
	err, config := GetKubeConfig()
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

func WaitKubernetes(agentName string, ps *pubsub.PubSub, stillRunning *time.Ticker) (*rest.Config, error) {
	checkTimer := time.NewTimer(5 * time.Second)
	configFileExist := false

	var config *rest.Config
	// wait until the Kubernetes server is started
	for !configFileExist {
		select {
		case <-checkTimer.C:
			if _, err := os.Stat(kubeConfigFile); err == nil {
				err, config = GetKubeConfig()
				if err == nil {
					configFileExist = true
					break
				}
			}
			checkTimer = time.NewTimer(5 * time.Second)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// Wait for the Kubernetes clientset to be ready, node ready and kubevirt pods in Running status
	readyCh := make(chan bool)
	go WaitForNodeReady(client, readyCh)

	kubeNodeReady := false
	for !kubeNodeReady {
		select {
		case <-readyCh:
			kubeNodeReady = true
			break
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	return config, nil
}

func CheckLonghornReady(client *kubernetes.Clientset) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("Unable to check longhorn pods on host:%v", err)
	}

	// First we'll gate on the longhorn daemonsets existing
	lhDaemonsets, err := client.AppsV1().DaemonSets("longhorn-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Checking if longhorn daemonsets exist: %v", err)
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

		labelSelectors := []string{}
		for dsLabelK, dsLabelV := range lhDaemonset.Spec.Template.Labels {
			labelSelectors = append(labelSelectors, dsLabelK+"="+dsLabelV)
		}
		pods, err := client.CoreV1().Pods("longhorn-system").List(context.Background(), metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + hostname,
			LabelSelector: strings.Join(labelSelectors, ","),
		})
		if err != nil {
			return fmt.Errorf("Unable to get daemonset pods on node: %v", err)
		}
		if len(pods.Items) != 1 {
			return fmt.Errorf("Longhorn daemonset:%s missing on this node", lhDsName)
		}
		for _, pod := range pods.Items {
			if pod.Status.Phase != "Running" {
				return fmt.Errorf("Daemonset:%s not running on node", lhDsName)
			}
			for _, podContainerState := range pod.Status.ContainerStatuses {
				if !podContainerState.Ready {
					return fmt.Errorf("Daemonset:%s not ready on node", lhDsName)
				}
			}
		}
	}

	for dsPrefix, dsPrefixExists := range lhExpectedDaemonsets {
		if !dsPrefixExists {
			return fmt.Errorf("Longhorn missing daemonset:%s", dsPrefix)
		}
	}

	return nil
}

func WaitForNodeReady(client *kubernetes.Clientset, readyCh chan bool) {
	if client == nil {

	}
	err := wait.PollImmediate(time.Second, time.Minute*20, func() (bool, error) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			_, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				return err
			}
			// get all pods from kubevirt, and check if they are all running
			pods, err := client.CoreV1().Pods("kubevirt").List(context.Background(), metav1.ListOptions{
				FieldSelector: "status.phase=Running",
			})
			if err != nil {
				return err
			}
			if len(pods.Items) < 6 {
				return fmt.Errorf("kubevirt running pods less than 6")
			}

			if err = CheckLonghornReady(client); err != nil {
				return err
			}

			return nil
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
