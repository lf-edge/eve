// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubeapi

import (
	"context"
	"errors"
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

// CreatePVC : Creates a Persistent volume of given name and size
func CreatePVC(pvcName string, size uint64, log *base.LogObject) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("Failed to get clientset %v", err)
		errStr := fmt.Sprintf("Failed to get clientset %v", err)
		return errors.New(errStr)
	}

	// PVC minimum supported size is 10MB
	if size < 10*1024*1024 {
		size = 10 * 1024 * 1024
	}
	// Define the Longhorn PVC object
	pvc := NewPVCDefinition(pvcName, fmt.Sprint(size), nil, nil)

	// Create the PVC in Kubernetes
	result, err := clientset.CoreV1().PersistentVolumeClaims(pvc.Namespace).Create(context.Background(), pvc, metav1.CreateOptions{})
	if err != nil {
		log.Errorf("Failed to CreatePVC %s error %v", pvcName, err)
		errStr := fmt.Sprintf("Failed to CreatePVC %s error %v", pvcName, err)
		return errors.New(errStr)
	}

	log.Noticef("Created PVC: %s\n", result.ObjectMeta.Name)
	return nil
}

// DeletePVC : Deletes the PVC of given name
func DeletePVC(pvcName string, log *base.LogObject) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("Failed to get clientset %v", err)
		errStr := fmt.Sprintf("Failed to get clientset %v", err)
		return errors.New(errStr)
	}
	err = clientset.CoreV1().PersistentVolumeClaims(types.VolumeCSINameSpace).Delete(context.Background(), pvcName, metav1.DeleteOptions{})
	if err != nil {
		log.Errorf("Failed to DeletePVC %s error %v", pvcName, err)
		errStr := fmt.Sprintf("Failed to DeletePVC %s error %v", pvcName, err)
		return errors.New(errStr)
	}
	return nil
}

// GetPVCList : Get the list of PVCs in a given namespace
func GetPVCList(ns string, log *base.LogObject) ([]string, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("Failed to get clientset %v", err)
		errStr := fmt.Sprintf("Failed to get clientset %v", err)
		return nil, errors.New(errStr)
	}
	pvcs, err := clientset.CoreV1().PersistentVolumeClaims(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("Failed to get PVC list in namespace %s: %v", ns, err)
		errStr := fmt.Sprintf("Failed to get PVC list in namespace %s: %v", ns, err)
		return nil, errors.New(errStr)
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
		log.Errorf("Failed to get clientset %v", err)
		errStr := fmt.Sprintf("Failed to get clientset %v", err)
		return false, errors.New(errStr)
	}
	_, err = clientset.CoreV1().PersistentVolumeClaims(types.VolumeCSINameSpace).Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetPVCInfo : Returns the PVC info in the ImgInfo format
func GetPVCInfo(pvcName string, log *base.LogObject) (*types.ImgInfo, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("Failed to get clientset %v", err)
		errStr := fmt.Sprintf("Failed to get clientset %v", err)
		return nil, errors.New(errStr)
	}

	pvc, err := clientset.CoreV1().PersistentVolumeClaims(types.VolumeCSINameSpace).Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("GetPVCInfo failed to get info for pvc %s err %v", pvcName, err)
		errStr := fmt.Sprintf("GetPVCInfo failed to get info for pvc %s err %v", pvcName, err)
		return nil, errors.New(errStr)
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

	// Do we ever come here !!
	return fmt.Sprintf("%.1fYi", bf)
}

// NewPVCDefinition : returns a default PVC object
func NewPVCDefinition(pvcName string, size string, annotations, labels map[string]string) *corev1.PersistentVolumeClaim {

	var (
		volumeModeBlock = corev1.PersistentVolumeBlock // Filesystem is default so no need to declare
	)
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:        pvcName,
			Annotations: annotations,
			Labels:      labels,
			Namespace:   types.VolumeCSINameSpace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: stringPtr(types.VolumeCSIClusterStorageClass),
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode:       &volumeModeBlock,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceName(corev1.ResourceStorage): resource.MustParse(size),
				},
			},
		},
	}
}

// RolloutDiskToPVC :  copy the content of diskfile to PVC
// diskfile can be in qcow or raw format
// If pvc does not exist, the command will create PVC and copies the data.
func RolloutDiskToPVC(ctx context.Context, log *base.LogObject, exists bool, diskfile string, pvcName string, filemode bool) error {

	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("Failed to get clientset %v", err)
		errStr := fmt.Sprintf("Failed to get clientset %v", err)
		return errors.New(errStr)
	}

	var service *corev1.Service
	// Get the Service from Kubernetes API.
	i := 5
	for {
		service, err = clientset.CoreV1().Services("cdi").Get(context.Background(), "cdi-uploadproxy", metav1.GetOptions{})

		if err != nil {
			if strings.Contains(err.Error(), "dial tcp 127.0.0.1:6443") && i <= 0 {
				errStr := fmt.Sprintf("Failed to get Service cdi/cdi-uploadproxy: %v\n", err)
				return errors.New(errStr)
			}
			time.Sleep(10 * time.Second)
			log.Noticef("RolloutDiskToPVC loop (%d), wait for 10 sec, err %v", i, err)
		} else {
			break
		}
		i = i - 1
	}

	if service == nil {
		errStr := fmt.Sprintf("Failed to get Service cdi/cdi-uploadproxy\n")
		return errors.New(errStr)
	}
	// Get the ClusterIP of the Service.
	clusterIP := service.Spec.ClusterIP
	uploadproxyURL := "https://" + clusterIP + ":443"
	log.Noticef("RolloutDiskToPVC diskfile %s pvc %s  URL %s", diskfile, pvcName, uploadproxyURL)
	volSize, err := diskmetrics.GetDiskVirtualSize(log, diskfile)
	if err != nil {
		errStr := fmt.Sprintf("Failed to get virtual size of disk %s: %v", diskfile, err)
		return errors.New(errStr)
	}

	// ActualSize can be larger than VirtualSize for fully-allocated/not-thin QCOW2 files
	actualVolSize, err := diskmetrics.GetDiskActualSize(log, diskfile)
	if err != nil {
		errStr := fmt.Sprintf("Failed to get actual size of disk %s: %v", diskfile, err)
		return errors.New(errStr)
	}
	if actualVolSize > volSize {
		volSize = actualVolSize
	}

	// Sample virtctl command
	// virtctl image-upload -n eve-kube-app pvc pvcname  --no-create --storage-class longhorn --image-path=<diskfile>
	// --insecure --uploadproxy-url https://10.43.31.180:8443  --access-mode RWO --block-volume --size 1000M

	args := []string{"image-upload", "-n", eveNameSpace, "pvc", pvcName, "--storage-class", "longhorn", "--image-path", diskfile, "--insecure", "--uploadproxy-url", uploadproxyURL, "--kubeconfig", kubeConfigFile}

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
	// add more debug level, default is 2
	args = append(args, "-v", "7")

	log.Noticef("virtctl args %v", args)

	// Wait for long long time since some volumes could be in TBs
	output, err := base.Exec(log, "/containers/services/kube/rootfs/usr/bin/virtctl", args...).WithContext(ctx).WithUnlimitedTimeout(432000 * time.Second).CombinedOutput()

	if err != nil {
		errStr := fmt.Sprintf("RolloutDiskToPVC: Failed to convert qcow to PVC  %s: %v", output, err)
		return errors.New(errStr)
	} else {
		log.Noticef("virtctl no error, output %s", output)
	}
	err = waitForPVCReady(ctx, log, pvcName)

	if err != nil {
		errStr := fmt.Sprintf("RolloutDiskToPVC: error wait for PVC %v", err)
		return errors.New(errStr)
	}

	return nil
}

func stringPtr(str string) *string {
	return &str
}
