package kubeapi

import (
	//	"fmt"
	//	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	kubeConfigFile = "/run/.kube/k3s/k3s.yaml"
)

func getKubeConfig() (error, *rest.Config) {
	// Build the configuration from the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		// fmt.Errorf("getKubeConfig: spec Read kubeconfig failed: %v", err)
		return err, nil
	}
	return nil, config
}
