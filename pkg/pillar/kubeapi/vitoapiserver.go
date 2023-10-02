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
	//	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
	//"k8s.io/client-go/tools/clientcmd"
)

func CreatePVC(pvcName string, size uint64) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		return err
	}

	// PVC minimum supported sizee is 10MB
	if size < 10*1024*1024 {
		size = 10 * 1024 * 1024
	}
	// Define the Longhorn PVC object
	pvc := NewPVCDefinition(pvcName, fmt.Sprint(size), nil, nil)

	// Create the PVC in Kubernetes
	result, err := clientset.CoreV1().PersistentVolumeClaims(pvc.Namespace).Create(context.Background(), pvc, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("Created PVC: %s\n", result.ObjectMeta.Name)
	return nil
}

func DeletePVC(pvcName string) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		return err
	}
	err = clientset.CoreV1().PersistentVolumeClaims(types.VolumeCSINameSpace).Delete(context.Background(), pvcName, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf("Delete PVC %s failed", pvcName)
		return err
	}
	return nil
}

func GetPVCList(ns string) ([]string, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		return nil, err
	}
	pvcs, err := clientset.CoreV1().PersistentVolumeClaims(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Failed to get PVC list in namespace %s: %v\n", ns, err)
		return nil, err
	}

	var pvclist []string
	for _, pvc := range pvcs.Items {
		pvclist = append(pvclist, pvc.Name)
	}
	return pvclist, nil
}

func FindPVC(pvcName string) (bool, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		return false, err
	}
	_, err = clientset.CoreV1().PersistentVolumeClaims(types.VolumeCSINameSpace).Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("FindPVC failed for pvc %s", pvcName)
		return false, err
	}
	return true, nil
}

func GetPVCInfo(pvcName string) (*types.ImgInfo, error) {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		fmt.Printf("GetPVCInfo failed to get clientset err %v", err)
		return nil, err
	}

	pvc, err := clientset.CoreV1().PersistentVolumeClaims(types.VolumeCSINameSpace).Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("GetPVCInfo failed to get pvc info err %v", err)
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
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			VolumeMode:       &volumeModeBlock,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceName(corev1.ResourceStorage): resource.MustParse(size),
				},
			},
		},
	}
}

// RolloutImgToPVC copy the content of diskfile to PVC
func RolloutImgToPVC(ctx context.Context, log *base.LogObject, exists bool, diskfile string, pvcName string, isAppImage bool) error {

	//fetch CDI proxy url
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		return err
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
			log.Noticef("PRAMOD RolloutImgToPVC loop (%d), wait for 10 sec, err %v", i, err)
		} else {
			break
		}
		i = i - 1
	}

	// Get the ClusterIP of the Service.
	clusterIP := service.Spec.ClusterIP
	uploadproxyURL := "https://" + clusterIP + ":443"
	log.Noticef("PRAMOD RolloutImgToPVC diskfile %s pvc %s  URL %s", diskfile, pvcName, uploadproxyURL)
	volSize, err := diskmetrics.GetDiskVirtualSize(log, diskfile)
	if err != nil {
		errStr := fmt.Sprintf("Failed to get virtual size of disk %s: %v", diskfile, err)
		return errors.New(errStr)
	}

	// TODO: Check if we can configure the reserved space
	// Allocate 10% more, longhorn PVC needs reserved space. This is needed only when virtctl is copying the data to
	// newly created PVC. It compares virtual disk size and available space in PVC.
	volSize = volSize + (volSize / 10)

	// virtctl image-upload -n eve-kube-app pvc a1030350-bd03-4b79-ac1c-4d8564d0e4b0-pvc-0   --no-create --storage-class longhorn --image-path=/persist/vault/containerd/io.containerd.content.v1.content/blobs/sha256/
	// 84ed078f3f0e1671d591d15409883a24bd30763eb10a9dec01a2fb38cf06cf6d --insecure --uploadproxy-url https://10.43.31.180:8443
	// Write API to get proxy url

	args := []string{"image-upload", "-n", "eve-kube-app", "pvc", pvcName, "--storage-class", "longhorn", "--image-path", diskfile, "--insecure", "--uploadproxy-url", uploadproxyURL, "--kubeconfig", kubeConfigFile}

	// We create PVC of filesystem mode if its appimage volume. longhorn PVC FS mode does not support ReadWriteMany mode.
	if isAppImage {
		args = append(args, "--access-mode", "ReadWriteOnce")
	} else {
		args = append(args, "--access-mode", "ReadWriteMany", "--block-volume")
	}
	//args := fmt.Sprintf("image-upload -n eve-kube-app pvc %s --no-create --storage-class longhorn --image-path=%s --insecure --uploadproxy-url %s", outputFile, diskfile, uploadproxyURL)

	// If PVC already exists just copy out the data, else virtctl will create the PVC before data copy
	if exists {
		args = append(args, "--no-create")
	} else {
		// Add size
		args = append(args, "--size", fmt.Sprint(volSize))
	}
	time.Sleep(10 * time.Second)
	log.Noticef("PRAMOD virtctl args %v", args)

	output, err := base.Exec(log, "/containers/services/kube/rootfs/usr/bin/virtctl", args...).WithContext(ctx).WithUnlimitedTimeout(432000 * time.Second).CombinedOutput()
	log.Noticef("RolloutImgToPVC: image-upload error %v", err)
	log.Noticef("RolloutImgToPVC: image-upload output %s", output)
	err = waitForPVCReady(ctx, log, pvcName)
	log.Noticef("RolloutImgToPVC: wait for pvc %v", err)
	return nil
}

func stringPtr(str string) *string {
	return &str
}

func waitForPVCReady(ctx context.Context, log *base.LogObject, pvcName string) error {
	clientset, err := GetClientSet()
	if err != nil {
		log.Errorf("waitForPVCReady failed to get clientset err %v", err)
		return err
	}

	i := 10
	var count int
	var err2 error
	for {
		pvcs, err := clientset.CoreV1().PersistentVolumeClaims(eveNameSpace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("GetPVCInfo failed to list pvc info err %v", err)
			err2 = err
		} else {

			count = 0
			for _, pvc := range pvcs.Items {
				pvcObjName := pvc.ObjectMeta.Name
				if strings.Contains(pvcObjName, pvcName) {
					count++
					log.Noticef("waitForPVCReady(%d): get pvc %s", count, pvcObjName)
				}
			}
			if count == 1 {
				return nil
			}
		}
		i -= 1
		if i <= 0 {
			break
		}
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("waitForPVCReady: time expired count %d, err %v", count, err2)
}
