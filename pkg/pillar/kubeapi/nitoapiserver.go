package kubeapi

import (
	"context"
	"time"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	agentName = "zedkube"
	// Time limits for event loop handlers
	stillRunningInterval = 25 * time.Second
)

func CreateNAD(ps *pubsub.PubSub, log *base.LogObject, yamlData []byte, name, namespace string) error {

	client, err := GetClientSet()
	if err != nil {
		log.Errorf("createNAD: Failed to create clientset: %v", err)
		return err
	}

	netClientset, err := GetNetClientSet()
	if err != nil {
		log.Errorf("createNAD: Failed to create netclientset: %v", err)
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
	go WaitForNodeReady(client, readyCh)

	stillRunning := time.NewTicker(stillRunningInterval)

	var done bool
	for !done {
		select {
		case <-readyCh:
			opStr := "created"
			log.Noticef("sendAoApiServer: spec Kubernetes cluster is ready!")
			createdNAD, err := netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Create(context.Background(), nad, metav1.CreateOptions{})
			if err != nil {
				if !errors.IsAlreadyExists(err) {
					log.Errorf("sendAoApiServer: spec create error %s", err)
					return err
				} else {
					opStr = "already exists"
				}
			}
			log.Noticef("sendAoApiServer: spec NetworkAttachmentDefinition %s successfully: %+v", opStr, createdNAD)
			done = true
		case <-time.After(time.Minute * 10):
			log.Noticef("sendToApiServer: spec NetworkAttachmentDefinition create timedout")
			done = true
		case <-stillRunning.C:
			log.Noticef("sendToApiServer: still running")
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	return nil
}

func monitorKubeCluster(log *base.LogObject) {
	netClientset, err := GetNetClientSet()
	if err != nil {
		log.Errorf("monitorKubeCluster: Failed to create netclientset: %v", err)
		return
	}

	checkTimer := time.NewTimer(5 * time.Minute)
	for {
		select {
		case <-checkTimer.C:
			namespace := eveNameSpace                     // XXX
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

func DeleteNAD(log *base.LogObject, nadName string) error {
	netClientset, err := GetNetClientSet()

	if err != nil {
		log.Errorf("deleteNAD: Failed to create netclientset: %v", err)
		return err
	}

	err = netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(eveNameSpace).Delete(context.Background(), nadName, metav1.DeleteOptions{})
	if err != nil {
		log.Errorf("deleteNAD: spec delete error %s", err)
		return err
	}
	log.Noticef("deleteNAD: spec NetworkAttachmentDefinition deleted successfully: %+v", nadName)
	return err
}
