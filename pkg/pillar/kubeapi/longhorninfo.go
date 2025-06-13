// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const longhornNamespace = "longhorn-system"

// LonghornVolumeSizeDetails returns the provisionedBytes and allocatedBytes size values for a longhorn volume
func LonghornVolumeSizeDetails(longhornVolumeName string) (provisionedBytes uint64, allocatedBytes uint64, err error) {
	apiExists, err := longhornAPIExists()
	if err != nil {
		return 0, 0, err
	}
	if !apiExists {
		return 0, 0, nil
	}

	config, err := GetKubeConfig()
	if err != nil {
		return 0, 0, fmt.Errorf("LonghornVolumeSizeDetails can't get kubeconfig %v", err)
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return 0, 0, fmt.Errorf("LonghornVolumeSizeDetails can't get versioned config: %v", err)
	}

	// Don't allow a k8s api timeout keep us waiting forever, set this one explicitly as its used in metrics path
	shortContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lhVol, err := lhClient.LonghornV1beta2().Volumes(longhornNamespace).Get(shortContext, longhornVolumeName, metav1.GetOptions{})
	if err != nil || lhVol == nil {
		return 0, 0, fmt.Errorf("LonghornVolumeSizeDetails can't get lh vol err:%v", err)
	}

	return uint64(lhVol.Spec.Size), uint64(lhVol.Status.ActualSize), nil
}

func min(a, b types.ServiceStatus) types.ServiceStatus {
	if a < b {
		return a
	}
	return b
}

// PopulateKVIFromPVCName uses the longhorn api to retrieve volume and replica health
// to be sent out to the controller as info messages
func populateKVIFromPVCName(kvi *types.KubeVolumeInfo) (*types.KubeVolumeInfo, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get clientset %v", err)
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get versioned config: %v", err)
	}

	pvc, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).Get(context.Background(), kvi.Name, metav1.GetOptions{})
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get pvc:%s err:%v", kvi.Name, err)
	}

	kvi.CreatedAt = pvc.ObjectMeta.CreationTimestamp.Time

	storage := pvc.Spec.Resources.Requests["storage"]
	bytes, _ := storage.AsInt64()
	kvi.ProvisionedBytes = uint64(bytes)

	switch pvc.Status.Phase {
	case corev1.ClaimBound:
		kvi.PvcStatus = types.StorageVolumePvcStatusBound
	}
	lhVolName := pvc.Spec.VolumeName

	lhVol, err := lhClient.LonghornV1beta2().Volumes(longhornNamespace).Get(context.Background(), lhVolName, metav1.GetOptions{})
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get lh vol err:%v", err)
	}
	kvi.AllocatedBytes = uint64(lhVol.Status.ActualSize)

	switch lhVol.Status.Robustness {
	case lhv1beta2.VolumeRobustnessHealthy:
		kvi.Robustness = types.StorageVolumeRobustnessHealthy
	case lhv1beta2.VolumeRobustnessDegraded:
		kvi.Robustness = types.StorageVolumeRobustnessDegraded
	case lhv1beta2.VolumeRobustnessFaulted:
		kvi.Robustness = types.StorageVolumeRobustnessFaulted
	case lhv1beta2.VolumeRobustnessUnknown:
		kvi.Robustness = types.StorageVolumeRobustnessUnknown
	}

	if kvi.Robustness == types.StorageVolumeRobustnessHealthy {
		kvi.RobustnessSubstate = types.StorageHealthStatusHealthy
	}
	if kvi.Robustness == types.StorageVolumeRobustnessFaulted {
		kvi.RobustnessSubstate = types.StorageHealthStatusFailed
	}

	switch lhVol.Status.State {
	case lhv1beta2.VolumeStateCreating:
		kvi.State = types.StorageVolumeStateCreating
	case lhv1beta2.VolumeStateAttached:
		kvi.State = types.StorageVolumeStateAttached
	case lhv1beta2.VolumeStateDetached:
		kvi.State = types.StorageVolumeStateDetached
	case lhv1beta2.VolumeStateAttaching:
		kvi.State = types.StorageVolumeStateAttaching
	case lhv1beta2.VolumeStateDetaching:
		kvi.State = types.StorageVolumeStateDetaching
	case lhv1beta2.VolumeStateDeleting:
		kvi.State = types.StorageVolumeStateDeleting
	}

	replicas, err := lhClient.LonghornV1beta2().Replicas(longhornNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "longhornvolume=" + lhVolName,
	})
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName pv:%s can't get replicas: %v", lhVolName, err)
	}

	onlineReps := 0
	consistentReps := 0
	for _, lhReplica := range replicas.Items {
		kviRep := types.KubeVolumeReplicaInfo{}
		kviRep.Name = lhReplica.ObjectMeta.Name
		kviRep.OwnerNode = ""
		kviRep.RebuildProgressPercentage = 0

		replicaEngineName := lhReplica.Spec.EngineName
		replicaEngineIP := lhReplica.Status.IP
		replicaEnginePort := lhReplica.Status.Port

		switch lhReplica.Status.CurrentState {
		case lhv1beta2.InstanceStateRunning:
			kviRep.Status = types.StorageVolumeReplicaStatusOnline
			kviRep.OwnerNode = lhReplica.Status.OwnerID

			engine, err := lhClient.LonghornV1beta2().Engines(longhornNamespace).Get(context.Background(), replicaEngineName, metav1.GetOptions{})
			if err != nil {
				return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get replica engine: %v", err)
			}
			replicaAddress := "tcp://" + replicaEngineIP + ":" + fmt.Sprintf("%d", replicaEnginePort)
			rebuildStatus, ok := engine.Status.RebuildStatus[replicaAddress]
			if !ok {
				kviRep.RebuildProgressPercentage = 100
				consistentReps++
			} else {
				kviRep.RebuildProgressPercentage = uint8(rebuildStatus.Progress)
				kviRep.Status = types.StorageVolumeReplicaStatusRebuilding
			}

			onlineReps++
		case lhv1beta2.InstanceStateError:
			kviRep.Status = types.StorageVolumeReplicaStatusFailed
		case lhv1beta2.InstanceStateStopped:
			kviRep.Status = types.StorageVolumeReplicaStatusOffline
		case lhv1beta2.InstanceStateStarting:
			kviRep.Status = types.StorageVolumeReplicaStatusStarting
		case lhv1beta2.InstanceStateStopping:
			kviRep.Status = types.StorageVolumeReplicaStatusStopping
		case lhv1beta2.InstanceStateUnknown:
			kviRep.Status = types.StorageVolumeReplicaStatusUnknown
		}

		kvi.Replicas = append(kvi.Replicas, kviRep)
	}

	//RobustnessSubstate
	//Take care of the simple cases, healthy and failed
	if kvi.Robustness == types.StorageVolumeRobustnessHealthy {
		kvi.RobustnessSubstate = types.StorageHealthStatusHealthy
	}
	if kvi.Robustness == types.StorageVolumeRobustnessFaulted {
		kvi.RobustnessSubstate = types.StorageHealthStatusFailed
	}
	if kvi.Robustness == types.StorageVolumeRobustnessDegraded {
		// Not rebuilding
		if onlineReps == 1 {
			kvi.RobustnessSubstate = types.StorageHealthStatusDegraded1ReplicaAvailableNotReplicating
		}
		// Rebuilding one or zero replicas
		if onlineReps == 2 {
			if consistentReps == 1 {
				kvi.RobustnessSubstate = types.StorageHealthStatusDegraded1ReplicaAvailableReplicating
			}
			if consistentReps == 2 {
				kvi.RobustnessSubstate = types.StorageHealthStatusDegraded2ReplicaAvailableNotReplicating
			}
		}
		if onlineReps == 3 {
			if consistentReps == 1 {
				kvi.RobustnessSubstate = types.StorageHealthStatusDegraded1ReplicaAvailableReplicating
			}
			if consistentReps == 2 {
				kvi.RobustnessSubstate = types.StorageHealthStatusDegraded2ReplicaAvailableReplicating
			}
		}
	}
	return kvi, nil
}

// Return transitionTime and health
func getDsServiceStatus(ds appsv1.DaemonSet) (time.Time, types.ServiceStatus) {
	latestTime := time.Time{}

	config, err := GetKubeConfig()
	if err != nil {
		return latestTime, types.ServiceStatusUnset
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return latestTime, types.ServiceStatusUnset
	}

	//get the matchLabel of the app
	//$ kubectl -n longhorn-system get daemonset/longhorn-manager -o json | jq .spec.selector.matchLabels.app
	//"longhorn-manager"
	matchLabel := ds.Spec.Selector.MatchLabels["app"]

	// get all the pods for that
	//kubectl -n longhorn-system get pods -l app=longhorn-manager
	pods, err := clientset.CoreV1().Pods(longhornNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=" + matchLabel,
	})
	if err != nil {
		return latestTime, types.ServiceStatusUnset
	}

	//get latest health time for that
	for _, pod := range pods.Items {
		for _, condition := range pod.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				if condition.LastTransitionTime.Compare(latestTime) == 1 {
					latestTime = condition.LastTransitionTime.Time
				}
			}
		}
	}
	if ds.Status.NumberReady == ds.Status.DesiredNumberScheduled {
		return latestTime, types.ServiceStatusHealthy
	}
	if ds.Status.NumberReady == 0 {
		return latestTime, types.ServiceStatusFailed
	}
	return latestTime, types.ServiceStatusDegraded
}

// PopulateKSI retrieve cluster-wide PVC health data which
// will be sent out to the controller as info messages
func PopulateKSI() (types.KubeStorageInfo, error) {
	ksi := types.KubeStorageInfo{}
	apiExists, err := longhornAPIExists()
	if err != nil {
		return ksi, err
	}
	if !apiExists {
		return ksi, nil
	}

	config, err := GetKubeConfig()
	if err != nil {
		return ksi, fmt.Errorf("PopulateKSI can't get kubeconfig %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return ksi, fmt.Errorf("PopulateKSI can't get clientset %v", err)
	}

	daemonsets, err := clientset.AppsV1().DaemonSets(longhornNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return ksi, fmt.Errorf("PopulateKSI failed to list longhorn daemonsets: %v", err)
	}
	ksi.Health = types.ServiceStatusHealthy
	for _, ds := range daemonsets.Items {
		healthTime, dsStat := getDsServiceStatus(ds)
		ksi.Health = min(ksi.Health, dsStat)
		ksi.TransitionTime = healthTime
	}

	pvcs, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return ksi, fmt.Errorf("PopulateKSI can't get pvcs err:%v", err)
	}
	for _, pvc := range pvcs.Items {
		kvi := &types.KubeVolumeInfo{Name: pvc.ObjectMeta.Name}
		kvi, err := populateKVIFromPVCName(kvi)
		if err != nil {
			return ksi, fmt.Errorf("PopulateKSI can't get kvi: %v", err)
		}
		kvi.VolumeID, _ = strings.CutSuffix(kvi.Name, "-pvc-0")

		ksi.Volumes = append(ksi.Volumes, *kvi)
	}
	return ksi, nil
}

// LonghornReplicaList returns the replica for a given longhorn volume which is hosted on a given kubernetes node
func LonghornReplicaList(ownerNodeName string, longhornVolName string) (*lhv1beta2.ReplicaList, error) {
	apiExists, err := longhornAPIExists()
	if err != nil {
		return &lhv1beta2.ReplicaList{}, err
	}
	if !apiExists {
		return &lhv1beta2.ReplicaList{}, nil
	}

	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("LonghornReplicaList can't get versioned config: %v", err)
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("LonghornReplicaList can't get versioned config: %v", err)
	}

	labelSelectors := []string{}
	if ownerNodeName != "" {
		labelSelectors = append(labelSelectors, "longhornnode="+ownerNodeName)
	}
	if longhornVolName != "" {
		labelSelectors = append(labelSelectors, "longhornvolume="+longhornVolName)
	}
	replicas, err := lhClient.LonghornV1beta2().Replicas(longhornNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: strings.Join(labelSelectors, ","),
	})
	if err != nil {
		return nil, fmt.Errorf("LonghornReplicaList labelSelector:%s can't get replicas: %v", strings.Join(labelSelectors, ","), err)
	}
	return replicas, nil
}

// longhornAPIExists will check for longhorn components installed and set
// a flag in this module to gate all API access.  In some configurations
// it is possible that longhorn is not installed but this intended configuration
// is not known until runtime at some time after first boot.  In the reverse situation
// it is possible there can be a long delay at runtime until longhorn installation
// has completed.
func longhornAPIExists() (bool, error) {
	cs, err := GetClientSet()
	if err != nil {
		return false, err
	}
	// If the longhorn-system namespace exists then we should expect the longhorn api endpoint is available.
	ns, err := cs.CoreV1().Namespaces().Get(context.Background(), longhornNamespace, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if ns == nil {
		return false, nil
	}
	return true, nil
}
