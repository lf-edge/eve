package kubeapi

import (
	"context"
	"os"
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

	// Wait for the Kubernetes clientset to be ready
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

func WaitForNodeReady(client *kubernetes.Clientset, readyCh chan bool) {
	if client == nil {

	}
	err := wait.PollImmediate(time.Second, time.Minute*10, func() (bool, error) {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			_, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
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
