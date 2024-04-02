//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/base"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateOrUpdateNAD : create a new or update an existing NAD (NetworkAttachmentDefinition).
func CreateOrUpdateNAD(log *base.LogObject, nadName, jsonSpec string) error {
	netClientset, err := GetNetClientSet()
	if err != nil {
		log.Errorf("CreateOrUpdateNAD: Failed to create netclientset: %v", err)
		return err
	}
	nad := &netattdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: nadName,
		},
		Spec: netattdefv1.NetworkAttachmentDefinitionSpec{
			Config: jsonSpec,
		},
	}
	createdNAD, err := netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVEKubeNameSpace).
		Create(context.Background(), nad, metav1.CreateOptions{})
	if err == nil {
		log.Noticef("CreateOrUpdateNAD: successfully created new NAD %s: %+v",
			nadName, createdNAD)
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		log.Errorf("CreateOrUpdateNAD: failed to create NAD %s: %v", nadName, err)
		return err
	}
	// NAD already exists, try to update.
	nad, err = netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVEKubeNameSpace).
		Get(context.Background(), nadName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("CreateOrUpdateNAD: failed to get NAD %s for update: %v", nadName, err)
		return err
	}
	nad.Spec.Config = jsonSpec
	var updatedNAD *netattdefv1.NetworkAttachmentDefinition
	updatedNAD, err = netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVEKubeNameSpace).
		Update(context.Background(), nad, metav1.UpdateOptions{})
	if err == nil {
		log.Noticef("CreateOrUpdateNAD: successfully updated existing NAD %s: %+v",
			nadName, updatedNAD)
		return nil
	}
	log.Errorf("CreateOrUpdateNAD: failed to update NAD %s: %v", nadName, err)
	return err
}

func CheckEtherPassThroughNAD(nadName string) error {
	netClientset, err := GetNetClientSet()
	if err != nil {
		return err
	}

	nad, err := netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVEKubeNameSpace).
		Get(context.Background(), nadName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if nad.ObjectMeta.Name != nadName {
		return fmt.Errorf("CheckEtherPassThroughNAD: NAD %s not found", nadName)
	}
	return nil
}

// DeleteNAD : delete NAD with the given name (NetworkAttachmentDefinition).
func DeleteNAD(log *base.LogObject, nadName string) error {
	netClientset, err := GetNetClientSet()
	if err != nil {
		log.Errorf("DeleteNAD: Failed to create netclientset: %v", err)
		return err
	}
	err = netClientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions(EVEKubeNameSpace).
		Delete(context.Background(), nadName, metav1.DeleteOptions{})
	if err == nil {
		log.Noticef("DeleteNAD: successfully deleted NAD %s", nadName)
	} else {
		log.Errorf("DeleteNAD: failed to delete NAD %s: %v", nadName, err)
	}
	return err
}
