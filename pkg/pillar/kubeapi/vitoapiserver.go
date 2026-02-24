// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"
	"math"
	"strconv"
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
func CreatePVC(pvcName string, size uint64, log *base.LogObject, storageClass string) error {
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
	pvc := NewPVCDefinition(pvcName, fmt.Sprint(size), nil, nil, storageClass)

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

	imgFmt := zconfig.Format_name[int32(zconfig.Format_PVC)]
	imgInfo := types.ImgInfo{
		Format:    imgFmt,
		Filename:  pvcName,
		DirtyFlag: false,
	}
	// PVC asks for a minimum size, spec may be less than actual (status) provisioned
	imgInfo.VirtualSize = getPVCSize(pvc)

	// Ask longhorn for the PVCs backing-volume allocated space
	_, imgInfo.ActualSize, err = LonghornVolumeSizeDetails(pvc.Spec.VolumeName)
	if err != nil {
		err = fmt.Errorf("GetPVCInfo failed to get info for pvc %s volume %s: %v", pvcName, pvc.Spec.VolumeName, err)
		log.Error(err)
		return &imgInfo, err
	}
	return &imgInfo, nil
}

// Returns the provisioned size of the PVC in bytes
func getPVCSize(pvc *corev1.PersistentVolumeClaim) (provisionedSizeBytes uint64) {
	// Status field contains the size of the volume which actually bound to the claim
	if pvc.Status.Phase == corev1.ClaimBound {
		if quantity, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
			return uint64(quantity.Value())
		}
	}
	return 0
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
	labels map[string]string, storageClass string) *corev1.PersistentVolumeClaim {

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
			StorageClassName: stringPtr(storageClass),
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
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
// This does currently have extended retries but does not need to
// bump a watchdog as the volumecreate worker does not have one.
func RolloutDiskToPVC(ctx context.Context, log *base.LogObject, exists bool,
	diskfile string, pvcName string, filemode bool, pvcSize uint64, storageClass string) error {

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

	imgVirtBytes, err := diskmetrics.GetDiskVirtualSize(log, diskfile)
	if err != nil {
		err = fmt.Errorf("failed to get virtual size of disk %s: %v", diskfile, err)
		log.Error(err)
		return err
	}
	if pvcSize < imgVirtBytes {
		log.Noticef("Image file: %s has virtual size %d", diskfile, imgVirtBytes)
		pvcSize = imgVirtBytes
	}
	// ActualSize can be larger (by a very small amount) than VirtualSize for fully-allocated/not-thin QCOW2 files
	imgActualBytes, err := diskmetrics.GetDiskActualSize(log, diskfile)
	if err != nil {
		err = fmt.Errorf("failed to get actual size of disk %s: %v", diskfile, err)
		log.Error(err)
		return err
	}
	if pvcSize < imgActualBytes {
		pvcSize = imgActualBytes
	}

	// Create PVC and then copy data. We create PVC to set the designated node id label.
	if !exists {
		err = CreatePVC(pvcName, pvcSize, log, storageClass)
		if err != nil {
			err = fmt.Errorf("Error creating PVC %s", pvcName)
			log.Error(err)
			return err
		}
		exists = true
	}

	// Sample virtctl command
	// virtctl image-upload -n eve-kube-app pvc pvcname  --no-create --storage-class longhorn --image-path=<diskfile>
	// --insecure --uploadproxy-url https://10.43.31.180:8443  --access-mode RWO --block-volume --size 1000M

	uploadPodServerStartTimeBase := int64(600) // First upload may need to wait for image download of the uploader itself
	virtctlUploadServerRetryMax := int64(10)
	args := []string{"image-upload", "-n", EVEKubeNameSpace, "pvc", pvcName,
		"--storage-class", "longhorn", "--image-path", diskfile, "--insecure",
		"--uploadproxy-url", uploadproxyURL, "--kubeconfig", EVEkubeConfigFile,
		"--retry", strconv.FormatInt(virtctlUploadServerRetryMax, 10), "--wait-secs", strconv.FormatInt(uploadPodServerStartTimeBase, 10)}

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
		args = append(args, "--size", fmt.Sprint(pvcSize))
	}

	log.Noticef("virtctl args %v", args)

	uploadTry := 0
	maxRetries := 10
	timeoutBaseSeconds := int64(300) // 5 min
	volSizeGB := int64(pvcSize / 1024 / 1024 / 1024)
	timeoutPer1GBSeconds := int64(120)
	timeout := time.Duration(uploadPodServerStartTimeBase + timeoutBaseSeconds + (volSizeGB * timeoutPer1GBSeconds))
	log.Noticef("RolloutDiskToPVC pvc:%s calculated timeout to %d seconds due to volume size %d GB", pvcName, timeout, volSizeGB)

	startTimeOverall := time.Now()

	//
	// CDI Upload is quick to fail upon short-lived k8s api errors during its own upload-wait status loop
	// Try the upload again.
	//
	for uploadTry < maxRetries {
		uploadTry++

		startTimeThisUpload := time.Now()
		output, err := base.Exec(log, "/containers/services/kube/rootfs/usr/bin/virtctl", args...).
			WithContext(ctx).WithUnlimitedTimeout(timeout * time.Second).CombinedOutput()

		uploadDuration := time.Since(startTimeThisUpload)
		if err != nil && !strings.Contains(string(output), "already successfully imported") {
			err = fmt.Errorf("RolloutDiskToPVC: pvc:%s Failed after %f seconds to convert qcow to PVC %s: %v", pvcName, uploadDuration.Seconds(), output, err)
			log.Error(err)

			// This is a backoff to handle cases where the kubernetes api server
			// or the cdi-upload proxy may be temporarily unavailable due to a variety
			// of cases. EVE should wait as virtctl will just immediately throw
			// back some connection error.
			// 30 secs with 10 tries, 5 mins should be good enough even if k3s server restarts
			time.Sleep(30 * time.Second)
			continue
		}

		// Eventually the command should return something like:
		// PVC 688b9728-6f21-4bb6-b2f7-4928813fefdc-pvc-0 already successfully imported/cloned/updated
		overallDuration := time.Since(startTimeOverall)
		log.Functionf("RolloutDiskToPVC pvc:%s image upload completed on try:%d after %f seconds, total elapsed time %f seconds",
			pvcName, uploadTry, uploadDuration.Seconds(), overallDuration.Seconds())

		waitCdiAnnotationStart := time.Now()
		err = waitForPVCUploadComplete(ctx, pvcName, log)
		waitCdiAnnotationDuration := time.Since(waitCdiAnnotationStart)
		if err != nil {
			err = fmt.Errorf("RolloutDiskToPVC: error wait for PVC %v", err)
			log.Error(err)
			return err
		}
		overallDuration = time.Since(startTimeOverall)
		log.Noticef("RolloutDiskToPVC pvc:%s image upload completed on try:%d after virtctl-image-upload:%f seconds, cdi-upload-annotation-wait:%f seconds, total-elapsed-time:%f seconds",
			pvcName, uploadTry, uploadDuration.Seconds(), waitCdiAnnotationDuration.Seconds(), overallDuration.Seconds())
		return nil
	}

	//
	// This failure path can mask a list of possible failure points.
	// Attempt to diagnose the root causes and provide
	// differentiated detailed strings.
	//

	// 1. Use the PVC as our starting point to diagnose, we have it's name
	pvc, err := PVCGet(pvcName, log)
	if err != nil {
		return fmt.Errorf("PVC Upload for pvc:%s attempts to upload image failed, pvc not created", pvcName)
	}
	pvName := pvc.Spec.VolumeName
	// 2. Check if the uploader marked its annotation on the pvc
	cdiUploadPodName, exists := pvc.ObjectMeta.Annotations["cdi.kubevirt.io/storage.uploadPodName"]
	if !exists {
		return fmt.Errorf("PVC Upload for pvc:%s attempts to upload image failed, no upload pod annotation", pvcName)
	}
	// 3. Did the uploader get created?
	pod, err := PODGet(cdiUploadPodName, log)
	if err != nil {
		return fmt.Errorf("PVC Upload for pvc:%s attempts to upload image failed, upload pod:%s does not exist", pvcName, cdiUploadPodName)
	}
	uploadNodeName := pod.Spec.NodeName
	// 4. Did the PVC claim get a backing pv?
	lhVol, err := lhVolGet(pvName)
	if err != nil {
		return fmt.Errorf("PVC Upload for pvc:%s attempts to upload image failed, pv:%s does not exist", pvcName, pvName)
	}
	lhVolEi := lhVol.Status.CurrentImage
	// 5. Does the backing vol have an engine? Is that engine deployed on the node where the uploader is?
	deployed, err := lhEiDeployedOnNode(lhVolEi, uploadNodeName)
	if !deployed {
		return fmt.Errorf("PVC Upload for pvc:%s attempts to upload image failed, engine not deployed on node:%s %v", pvcName, uploadNodeName, err)
	}

	// Fallback to generic failure message
	return fmt.Errorf("RolloutDiskToPVC pvc:%s attempts to upload image failed", pvcName)
}

// GetPVFromPVC : Returns volume name (PV) from the PVC name
func GetPVFromPVC(pvcName string, log *base.LogObject) (string, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return "", err
	}
	// Get the PersistentVolumeClaim (PVC)
	pvc, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).Get(context.TODO(), pvcName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("Error fetching PersistentVolumeClaim %s: %v", pvcName, err)
		log.Error(err)
		return "", err
	}

	// Get the associated PersistentVolume (PV) name
	volumeName := pvc.Spec.VolumeName

	log.Noticef("PersistentVolume %s is associated with PVC %s", volumeName, pvcName)

	return volumeName, nil
}

// GetVolumeAttachmentFromPV : Return volume attachment if any for that PV along with nodename.
// longhorn attaches to the PV to serve to the apps. This API returns the attachment name and nodename.
// We use that attachment name to delete the attachment during failover.
// Basically the attachment of previous node needs to be deleted to attach to current node.
func GetVolumeAttachmentFromPV(volName string, nodeName string, log *base.LogObject) (string, string, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return "", "", err
	}
	// List all VolumeAttachments and find the one corresponding to the PV
	volumeAttachments, err := clientset.StorageV1().VolumeAttachments().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		err = fmt.Errorf("Error listing VolumeAttachments: %v", err)
		log.Error(err)
		return "", "", err
	}

	// Iterate through VolumeAttachments to find one that references the PV's CSI volume handle
	for _, va := range volumeAttachments.Items {
		if va.Spec.NodeName != nodeName {
			continue
		}
		if va.Spec.Source.PersistentVolumeName != nil && *va.Spec.Source.PersistentVolumeName == volName {
			log.Noticef("VolumeAttachment for vol %s found: %s (attached to node: %s)\n", volName, va.Name, va.Spec.NodeName)
			return va.Name, va.Spec.NodeName, nil
		}
	}

	return "", "", nil
}

// GetVolumeAttachmentFromHost : Return volume attachments on node
func GetVolumeAttachmentFromHost(nodeName string, log *base.LogObject) ([]string, error) {
	// Get the Kubernetes clientset
	vaList := []string{}

	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return vaList, err
	}
	// List all VolumeAttachments and find the one corresponding to the PV
	volumeAttachments, err := clientset.StorageV1().VolumeAttachments().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		err = fmt.Errorf("Error listing VolumeAttachments: %v", err)
		log.Error(err)
		return vaList, err
	}

	// Iterate through VolumeAttachments to find one that references the PV's CSI volume handle
	for _, va := range volumeAttachments.Items {
		if va.Spec.NodeName != nodeName {
			continue
		}
		if va.Spec.Source.PersistentVolumeName == nil {
			continue
		}
		log.Noticef("VolumeAttachment found: %s (attached to node: %s)\n", va.Name, va.Spec.NodeName)
		vaList = append(vaList, va.Name)
	}

	return vaList, nil
}

// DeleteVolumeAttachment : Delete the volumeattachment of given name
func DeleteVolumeAttachment(vaName string, log *base.LogObject) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return err
	}

	// Force delete the VolumeAttachment with grace period set to 0
	// This will ensure attachment is really deleted before its assigned to some other node.
	gracePeriod := int64(0)
	deletePolicy := metav1.DeletePropagationForeground
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod, // Set grace period to 0 for force deletion
		PropagationPolicy:  &deletePolicy,
	}

	// Delete the VolumeAttachment
	err = clientset.StorageV1().VolumeAttachments().Delete(context.TODO(), vaName, deleteOptions)
	if err != nil {
		err = fmt.Errorf("Error deleting VolumeAttachment %s: %v", vaName, err)
		log.Error(err)
		return err
	}
	return nil
}

// GetVolumeAttachmentAttached : Return true if VA is attached, not just requested
func GetVolumeAttachmentAttached(volName string, nodeName string, log *base.LogObject) (bool, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return false, err
	}
	// List all VolumeAttachments and find the one corresponding to the PV
	volumeAttachments, err := clientset.StorageV1().VolumeAttachments().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		err = fmt.Errorf("Error listing VolumeAttachments: %v", err)
		log.Error(err)
		return false, err
	}

	// Iterate through VolumeAttachments to find one that references the PV's CSI volume handle
	for _, va := range volumeAttachments.Items {
		if va.Spec.NodeName != nodeName {
			continue
		}
		if va.Spec.Source.PersistentVolumeName == nil {
			continue
		}
		if *va.Spec.Source.PersistentVolumeName != volName {
			continue
		}
		return va.Status.Attached, nil
	}

	return false, fmt.Errorf("VA for vol:%s node:%s not found", volName, nodeName)
}

func stringPtr(str string) *string {
	return &str
}

// PVCGet : returns the kubernetes pvc object matched by name
func PVCGet(pvcName string, log *base.LogObject) (*corev1.PersistentVolumeClaim, error) {
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
		return nil, err
	}
	return pvc, nil
}

// PODGet : returns the kubernetes pod object matched by name
func PODGet(podName string, log *base.LogObject) (*corev1.Pod, error) {
	clientset, err := GetClientSet()
	if err != nil {
		err = fmt.Errorf("failed to get clientset: %v", err)
		log.Error(err)
		return nil, err
	}
	pod, err := clientset.CoreV1().Pods(EVEKubeNameSpace).
		Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return pod, nil
}
