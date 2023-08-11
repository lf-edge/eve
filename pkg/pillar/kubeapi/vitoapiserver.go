package kubeapi

import (
	"context"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	//	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
	//"k8s.io/client-go/tools/clientcmd"
)

func GetClientSet() (*kubernetes.Clientset, error) {

	// Build the configuration from the provided kubeconfig file
	err, config := getKubeConfig()
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
func CreatePVC(pvcName string, size uint64) error {
	// Get the Kubernetes clientset
	clientset, err := GetClientSet()
	if err != nil {
		return err
	}

	// Define the Longhorn PVC object
	pvc := NewPVCDefinition(pvcName, size, nil, nil)

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

	imgInfo := types.ImgInfo{
		Format:    "pv",
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

//func convertBytesToSize(bytes int64) string {
//	const unit = 1024
//	if bytes < unit {
//		return fmt.Sprintf("%d B", bytes)
//	}
//	div, exp := int64(unit), 0
//	for n := bytes / unit; n >= unit; n /= unit {
//		div *= unit
//		exp++
//	}
//////	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
//}

func NewPVCDefinition(pvcName string, size uint64, annotations, labels map[string]string) *corev1.PersistentVolumeClaim {

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
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceName(corev1.ResourceStorage): resource.MustParse(fmt.Sprint(size)),
				},
			},
		},
	}
}

func stringPtr(str string) *string {
	return &str
}
