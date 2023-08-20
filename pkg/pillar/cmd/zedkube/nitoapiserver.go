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
