// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreatePVC : creates a Persistent volume of given name and size.
func CreatePVC(pvcName string, size uint64, log *base.LogObject) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return err
	}

	// PVC minimum supported size is 10MB
	if size < 10*1024*1024 {
		size = 10 * 1024 * 1024
	}
	// Define the Longhorn PVC object
	pvc := NewPVCDefinition(pvcName, fmt.Sprint(size), nil, nil)

	// Create the PVC in Kubernetes
	result, err := clientset.CoreV1().PersistentVolumeClaims(pvc.Namespace).
		Create(context.Background(), pvc, metav1.CreateOptions{})
	if err != nil {
		err = fmt.Errorf("failed to CreatePVC %s: %v", pvcName, err)
		log.Error(err)
		return err
	}

	log.Noticef("Created PVC: %s\n", result.ObjectMeta.Name)
	return nil
}

// DeletePVC : deletes PVC of the given name.
func DeletePVC(pvcName string, log *base.LogObject) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return err
	}
	err = clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
		Delete(context.Background(), pvcName, metav1.DeleteOptions{})
	if err != nil {
		err = fmt.Errorf("failed to DeletePVC %s: %v", pvcName, err)
		log.Error(err)
		return err
	}
	return nil
}

// GetPVCList : Get the list of all PVCs.
func GetPVCList(log *base.LogObject) ([]string, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return nil, err
	}
	pvcs, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get PVC list: %v", err)
		log.Error(err)
		return nil, err
	}

	var pvclist []string
	for _, pvc := range pvcs.Items {
		pvclist = append(pvclist, pvc.Name)
	}
	return pvclist, nil
}

// FindPVC : Returns true if the PVC exists, else false and not found error is returned to callers.
// Callers are expected to process the not found error
func FindPVC(pvcName string, log *base.LogObject) (bool, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return false, err
	}
	_, err = clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
		Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetPVCInfo : Returns the PVC info in the ImgInfo format.
func GetPVCInfo(pvcName string, log *base.LogObject) (*types.ImgInfo, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return nil, err
	}

	pvc, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
		Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("GetPVCInfo failed to get info for pvc %s: %v", pvcName, err)
		log.Error(err)
		return nil, err
	}

	fmt := zconfig.Format_name[int32(zconfig.Format_PVC)]
	imgInfo := types.ImgInfo{
		Format:    fmt,
		Filename:  pvcName,
		DirtyFlag: false,
	}
	// Get the actual and used size of the PVC.
	actualSizeBytes, usedSizeBytes := getPVCSizes(pvc)

	imgInfo.ActualSize = actualSizeBytes
	imgInfo.VirtualSize = usedSizeBytes

	return &imgInfo, nil
}

// Returns the actual and used size of the PVC in bytes
func getPVCSizes(pvc *corev1.PersistentVolumeClaim) (actualSizeBytes, usedSizeBytes uint64) {
	// Extract the actual size of the PVC from its spec.
	actualSizeBytes = 0
	usedSizeBytes = 0

	if pvc.Spec.Resources.Requests != nil {
		if quantity, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			actualSizeBytes = uint64(quantity.Value())
		}
	}

	// Extract the used size of the PVC from its status.
	if pvc.Status.Phase == corev1.ClaimBound {
		if quantity, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
			usedSizeBytes = uint64(quantity.Value())
		}
	}

	return actualSizeBytes, usedSizeBytes

}

// longhorn PVC deals with Ki Mi not KB, MB
func convertBytesToSize(b uint64) string {
	bf := float64(b)
	for _, unit := range []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"} {
		if math.Abs(bf) < 1024.0 {
			return fmt.Sprintf("%3.1f%s", bf, unit)
		}
		bf /= 1024.0
	}
	// Do we ever come here ?!
	return fmt.Sprintf("%.1fYi", bf)
}

// NewPVCDefinition : returns a default PVC object
func NewPVCDefinition(pvcName string, size string, annotations,
	labels map[string]string) *corev1.PersistentVolumeClaim {

	var (
		// Filesystem is default so no need to declare
		volumeModeBlock = corev1.PersistentVolumeBlock
	)
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:        pvcName,
			Annotations: annotations,
			Labels:      labels,
			Namespace:   EVEKubeNameSpace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: stringPtr(VolumeCSIClusterStorageClass),
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			VolumeMode:       &volumeModeBlock,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceName(corev1.ResourceStorage): resource.MustParse(size),
				},
			},
		},
	}
}

// RolloutDiskToPVC : copy the content of diskfile to PVC
// diskfile can be in qcow or raw format
// If pvc does not exist, the command will create PVC and copies the data.
func RolloutDiskToPVC(ctx context.Context, log *base.LogObject, exists bool,
	diskfile string, pvcName string, filemode bool) error {

	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset %v", err)
		log.Error(err)
		return err
	}

	var service *corev1.Service
	// Get the Service from Kubernetes API.
	i := 5
	for {
		service, err = clientset.CoreV1().Services("cdi").
			Get(context.Background(), "cdi-uploadproxy", metav1.GetOptions{})

		if err != nil {
			if strings.Contains(err.Error(), "dial tcp 127.0.0.1:6443") && i <= 0 {
				err = fmt.Errorf("failed to get Service cdi/cdi-uploadproxy: %v\n", err)
				log.Error(err)
				return err
			}
			time.Sleep(10 * time.Second)
			log.Noticef("RolloutDiskToPVC loop (%d), wait for 10 sec, err %v", i, err)
		} else {
			break
		}
		i = i - 1
	}

	// Get the ClusterIP of the Service.
	clusterIP := service.Spec.ClusterIP
	uploadproxyURL := "https://" + clusterIP + ":443"
	log.Noticef("RolloutDiskToPVC diskfile %s pvc %s  URL %s", diskfile, pvcName, uploadproxyURL)
	volSize, err := diskmetrics.GetDiskVirtualSize(log, diskfile)
	if err != nil {
		err = fmt.Errorf("failed to get virtual size of disk %s: %v", diskfile, err)
		log.Error(err)
		return err
	}

	// ActualSize can be larger than VirtualSize for fully-allocated/not-thin QCOW2 files
	actualVolSize, err := diskmetrics.GetDiskActualSize(log, diskfile)
	if err != nil {
		err = fmt.Errorf("failed to get actual size of disk %s: %v", diskfile, err)
		log.Error(err)
		return err
	}
	if actualVolSize > volSize {
		volSize = actualVolSize
	}

	// Sample virtctl command
	// virtctl image-upload -n eve-kube-app pvc pvcname  --no-create --storage-class longhorn --image-path=<diskfile>
	// --insecure --uploadproxy-url https://10.43.31.180:8443  --access-mode RWO --block-volume --size 1000M

	args := []string{"image-upload", "-n", EVEKubeNameSpace, "pvc", pvcName,
		"--storage-class", "longhorn", "--image-path", diskfile, "--insecure",
		"--uploadproxy-url", uploadproxyURL, "--kubeconfig", EVEkubeConfigFile}

	args = append(args, "--access-mode", "ReadWriteOnce")

	// Though in EVE we only support block volumes, lets have code for filesystem too
	if !filemode {
		args = append(args, "--volume-mode", "block")
	} else {
		args = append(args, "--volume-mode", "filesystem")
	}

	// If PVC already exists just copy out the data, else virtctl will create the PVC before data copy
	if exists {
		args = append(args, "--no-create")
	} else {
		// Add size
		args = append(args, "--size", fmt.Sprint(volSize))
	}

	log.Noticef("virtctl args %v", args)

	// Wait for long long time since some volumes could be in TBs
	output, err := base.Exec(log, "/containers/services/kube/rootfs/usr/bin/virtctl", args...).
		WithContext(ctx).WithUnlimitedTimeout(432000 * time.Second).CombinedOutput()

	if err != nil {
		err = fmt.Errorf("RolloutDiskToPVC: Failed to convert qcow to PVC %s: %v", output, err)
		log.Error(err)
		return err
	}
	err = waitForPVCReady(ctx, log, pvcName)

	if err != nil {
		err = fmt.Errorf("RolloutDiskToPVC: error wait for PVC %v", err)
		log.Error(err)
		return err
	}

	return nil
}

func stringPtr(str string) *string {
	return &str
}
