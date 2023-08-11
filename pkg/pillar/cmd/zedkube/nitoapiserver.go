package zedkube

import (
	"context"
	"fmt"
	"time"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	kubeConfigFile = "/run/.kube/k3s/k3s.yaml"
)

/* XXX
func getKubeConfig(ctx *zedkubeContext) error {
	// Build the configuration from the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		log.Errorf("getKubeConfig: spec Read kubeconfig failed: %v", err)
		return err
	}
	ctx.config = config
	return nil
}
*/

func sendToApiServer(ctx *zedkubeContext, yamlData []byte, name, namespace string) error {

	if ctx.config == nil {
		return fmt.Errorf("kubeConfig null\n")
	}
	// Create the clientset using the configuration
	client, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("sendAoApiServer: Failed to create clientset: %v", err)
		return err
	}

	netClientset, err := netclientset.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("sendAoApiServer: Failed to create netclientset: %v", err)
		return err
	}
	// Create the NAD.
	nad := &netattdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: netattdefv1.NetworkAttachmentDefinitionSpec{
			Config: string(yamlData),
		},
	}

	readyCh := make(chan bool)

	// Start a goroutine to check the Kubernetes API's reachability
	go kubeapi.WaitForNodeReady(client, readyCh)

	select {
	case isReady := <-readyCh:
		if isReady {
			log.Noticef("sendAoApiServer: spec Kubernetes cluster is ready!")
			createdNAD, err := netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Create(context.Background(), nad, metav1.CreateOptions{})
			if err != nil {
				log.Errorf("sendAoApiServer: spec create error %s", err)
				return err
			}
			log.Noticef("sendAoApiServer: spec NetworkAttachmentDefinition created successfully: %+v", createdNAD)
		} else {
			log.Noticef("sendAoApiServer: spec Kubernetes cluster isn't ready!")
		}
	case <-time.After(time.Minute * 10):
		log.Noticef("sendAoApiServer: spec NetworkAttachmentDefinition create timedout")
	}

	return nil
}

/*
func waitForNodeReady(client *kubernetes.Clientset, readyCh chan bool) {
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
*/

func monitorKubeCluster(ctx *zedkubeContext) {
	netClientset, err := netclientset.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("monitorKubeCluster: Failed to create netclientset: %v", err)
		return
	}

	checkTimer := time.NewTimer(5 * time.Minute)
	for {
		select {
		case <-checkTimer.C:
			namespace := eveNamespace                     // XXX
			nadname := "defaultlocal-canary-naiming-sm50" // XXX
			gotNAD, err := netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Get(context.Background(), nadname, metav1.GetOptions{})
			if err != nil {
				log.Errorf("monitorKubeCluster: spec get nad error %v", err)
			} else {
				log.Noticef("monitorKubeCluster: spec get nad %v", gotNAD)
			}
		}
	}
}
