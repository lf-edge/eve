// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	"github.com/longhorn/longhorn-manager/k8s/pkg/client/clientset/versioned"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const longhornNamespace = "longhorn-system"

// VolumeDirInternalEntriesMap returns filenames placed in volume directories
// (VolumeEncryptedDirName, VolumeClearDirName) by subsystems other than
// volumemgr. gcObjects skips these entries to avoid spurious errors during
// garbage collection. Add an entry here when a new subsystem co-locates
// files alongside EVE volumes.
func VolumeDirInternalEntriesMap() map[string]struct{} {
	return map[string]struct{}{
		"longhorn-disk.cfg": {},
		"replicas":          {},
		"backing-images":    {},
	}
}

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

// LonghornVolumeSnapshotBytes returns the total bytes consumed by all snapshots
// for the given Longhorn volume, excluding the live-data volume-head entry.
// Returns 0 with no error when the Longhorn API is unavailable or no snapshots exist.
func LonghornVolumeSnapshotBytes(longhornVolumeName string) (int64, error) {
	apiExists, err := longhornAPIExists()
	if err != nil || !apiExists {
		return 0, err
	}
	config, err := GetKubeConfig()
	if err != nil {
		return 0, fmt.Errorf("LonghornVolumeSnapshotBytes: kubeconfig: %v", err)
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return 0, fmt.Errorf("LonghornVolumeSnapshotBytes: client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snaps, err := lhClient.LonghornV1beta2().Snapshots(longhornNamespace).List(
		ctx, metav1.ListOptions{LabelSelector: "longhornvolume=" + longhornVolumeName})
	if err != nil {
		return 0, fmt.Errorf("LonghornVolumeSnapshotBytes: list: %v", err)
	}
	return sumSnapshotBytes(snaps.Items), nil
}

// sumSnapshotBytes sums Status.Size for all non-head snapshots in the list.
// MarkRemoved snapshots are intentionally included: they remain on disk until GC
// completes, and omitting them would silently under-report disk usage if GC stalls.
func sumSnapshotBytes(snaps []lhv1beta2.Snapshot) int64 {
	var total int64
	for _, s := range snaps {
		if !strings.HasSuffix(s.Name, "-volume-head") {
			total += s.Status.Size
		}
	}
	return total
}

func min(a, b types.ServiceStatus) types.ServiceStatus {
	if a < b {
		return a
	}
	return b
}

// replicaHasNoFsBacking : No disk image created on any nodes yet
// exists only as a kubernetes object so far
func replicaHasNoFsBacking(lhReplica lhv1beta2.Replica) bool {
	// If the replica existed on some other node and accepted data in the past
	// it would have an OwnerID at a minimum.  This set of conditions marks
	// a replica which has not scheduled/started.
	return (lhReplica.Status.OwnerID == "") &&
		(lhReplica.Status.InstanceManagerName == "") &&
		(lhReplica.Status.CurrentImage == "")
}

// replicaModeProgress maps the engine's ReplicaModeMap entry for a single replica
// to the three KubeVolumeReplicaInfo fields that populateKVIFromPVCName needs to set.
// It always returns a definitive repStatus for each mode map state.
// isConsistent is true only for RW replicas that should be counted toward consistentReps.
func replicaModeProgress(
	inModeMap bool,
	mode lhv1beta2.ReplicaMode,
	hasRebuildEntry bool,
	rebuildProgress int,
) (percentage uint8, repStatus types.StorageVolumeReplicaStatus, isConsistent bool) {
	repStatus = types.StorageVolumeReplicaStatusOnline
	switch {
	case !inModeMap:
		// Running but not yet registered in the engine's ReplicaModeMap — sync
		// state is unknown; report Unknown rather than Online to avoid a false
		// healthy signal during the brief window before the engine registers the replica.
		repStatus = types.StorageVolumeReplicaStatusUnknown
	case mode == lhv1beta2.ReplicaModeRW:
		// Fully synced read-write: the only state that genuinely means 100%.
		percentage = 100
		isConsistent = true
	case mode == lhv1beta2.ReplicaModeWO:
		// Write-only: rebuild queued or in progress.
		repStatus = types.StorageVolumeReplicaStatusRebuilding
		if hasRebuildEntry {
			// rebuildProgress is the Longhorn engine's Progress field, always 0-100.
			percentage = uint8(rebuildProgress)
		}
	case mode == lhv1beta2.ReplicaModeERR:
		repStatus = types.StorageVolumeReplicaStatusFailed
	}
	return
}

// robustnessSubstate maps (robustness, onlineReps, consistentReps) → the fine-grained
// health substate reported to the controller. All inputs come from Longhorn API data;
// the function is pure so it can be unit-tested without a live cluster.
func robustnessSubstate(robustness types.StorageVolumeRobustness, onlineReps, consistentReps int) types.StorageHealthStatus {
	switch robustness {
	case types.StorageVolumeRobustnessFaulted:
		return types.StorageHealthStatusFailed
	case types.StorageVolumeRobustnessHealthy:
		// Only report Healthy when every Running replica is confirmed RW.
		// If any Running replica is absent from ReplicaModeMap or in a non-RW
		// mode, consistentReps < onlineReps and we fall through to the Degraded
		// branch so the engine-lag window cannot produce a false Healthy signal.
		// onlineReps == 0 && consistentReps == 0 satisfies this condition and
		// returns Healthy — Longhorn never marks a volume Healthy with zero
		// running replicas, so we trust that invariant rather than guarding it.
		if consistentReps == onlineReps {
			return types.StorageHealthStatusHealthy
		}
		fallthrough
	case types.StorageVolumeRobustnessDegraded:
		// The cases below cover EVE's supported replica range (1–3). For a
		// Healthy volume that falls through (unconfirmed replicas) with ≥4
		// replicas, none of the conditions match and Unknown is returned — an
		// acceptable outcome since EVE does not configure volumes with >3 replicas.
		if onlineReps == 1 {
			return types.StorageHealthStatusDegraded1ReplicaAvailableNotReplicating
		}
		if onlineReps == 2 {
			if consistentReps == 1 {
				return types.StorageHealthStatusDegraded1ReplicaAvailableReplicating
			}
			if consistentReps == 2 {
				return types.StorageHealthStatusDegraded2ReplicaAvailableNotReplicating
			}
		}
		if onlineReps == 3 {
			if consistentReps == 1 {
				return types.StorageHealthStatusDegraded1ReplicaAvailableReplicating
			}
			if consistentReps == 2 {
				return types.StorageHealthStatusDegraded2ReplicaAvailableReplicating
			}
		}
	}
	return types.StorageHealthStatusUnknown
}

// pvcGetter is a minimal subset of the k8s PVC client used by populateKVIInner.
type pvcGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.PersistentVolumeClaim, error)
}

// lhVolumeGetter is a minimal subset of the Longhorn volume client.
type lhVolumeGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*lhv1beta2.Volume, error)
}

// lhReplicaLister is a minimal subset of the Longhorn replica client.
type lhReplicaLister interface {
	List(ctx context.Context, opts metav1.ListOptions) (*lhv1beta2.ReplicaList, error)
}

// lhEngineGetter is a minimal subset of the Longhorn engine client.
type lhEngineGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*lhv1beta2.Engine, error)
}

// lhNodeGetUpdater is a minimal subset of the Longhorn node client used by
// setLonghornNodeDiskReservedInner.
type lhNodeGetUpdater interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*lhv1beta2.Node, error)
	Update(ctx context.Context, node *lhv1beta2.Node, opts metav1.UpdateOptions) (*lhv1beta2.Node, error)
}

// populateKVIInner is the testable core of populateKVIFromPVCName.
// All Longhorn and k8s I/O is injected through the four interface arguments so
// unit tests can supply hand-written mocks without a live cluster.
func populateKVIInner(
	ctx context.Context,
	kvi *types.KubeVolumeInfo,
	pvcs pvcGetter,
	lhVols lhVolumeGetter,
	lhReplicas lhReplicaLister,
	lhEngines lhEngineGetter,
	snapshotBytes func(string) (int64, error),
) (*types.KubeVolumeInfo, error) {
	pvc, err := pvcs.Get(ctx, kvi.Name, metav1.GetOptions{})
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

	lhVol, err := lhVols.Get(ctx, lhVolName, metav1.GetOptions{})
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get lh vol err:%v", err)
	}
	kvi.AllocatedBytes = uint64(lhVol.Status.ActualSize)
	if snapBytes, snapErr := snapshotBytes(lhVolName); snapErr == nil && snapBytes > 0 {
		kvi.AllocatedBytes += uint64(snapBytes)
	}

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

	replicas, err := lhReplicas.List(ctx, metav1.ListOptions{
		LabelSelector: "longhornvolume=" + lhVolName,
	})
	if err != nil {
		return kvi, fmt.Errorf("PopulateKVIFromPVCName pv:%s can't get replicas: %v", lhVolName, err)
	}

	onlineReps := 0
	consistentReps := 0
	for _, lhReplica := range replicas.Items {
		if replicaHasNoFsBacking(lhReplica) {
			// Skip this as we have no actionable status to report to
			// an end user.
			continue
		}

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

			engine, err := lhEngines.Get(ctx, replicaEngineName, metav1.GetOptions{})
			if err != nil {
				return kvi, fmt.Errorf("PopulateKVIFromPVCName can't get replica engine: %v", err)
			}

			// CurrentReplicaAddressMap values are "IP:PORT" (no tcp:// prefix).
			// RebuildStatus is keyed by "tcp://IP:PORT"
			// ReplicaModeMap is keyed by replica name.
			replicaRawAddr := net.JoinHostPort(replicaEngineIP, strconv.Itoa(replicaEnginePort))
			if addr, ok := engine.Status.CurrentReplicaAddressMap[lhReplica.Name]; ok {
				replicaRawAddr = addr
			}
			rebuildAddr := "tcp://" + replicaRawAddr

			// ReplicaModeMap is the authoritative sync oracle. RebuildStatus is
			// ephemeral: absent before transfer starts and cleared on restart —
			// only RW in ReplicaModeMap means the replica is consistent.
			replicaMode, inModeMap := engine.Status.ReplicaModeMap[lhReplica.Name]
			rebuildEntry, hasRebuildEntry := engine.Status.RebuildStatus[rebuildAddr]
			rebuildProgress := 0
			if hasRebuildEntry {
				rebuildProgress = rebuildEntry.Progress
			}
			pct, repStatus, consistent := replicaModeProgress(inModeMap, replicaMode, hasRebuildEntry, rebuildProgress)
			kviRep.RebuildProgressPercentage = pct
			kviRep.Status = repStatus
			if consistent {
				consistentReps++
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

	kvi.RobustnessSubstate = robustnessSubstate(kvi.Robustness, onlineReps, consistentReps)
	return kvi, nil
}

// populateKVIFromPVCName uses the longhorn api to retrieve volume and replica health
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

	return populateKVIInner(
		context.Background(),
		kvi,
		clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace),
		lhClient.LonghornV1beta2().Volumes(longhornNamespace),
		lhClient.LonghornV1beta2().Replicas(longhornNamespace),
		lhClient.LonghornV1beta2().Engines(longhornNamespace),
		LonghornVolumeSnapshotBytes,
	)
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

// longhornStorageUnschedulable reports whether any Longhorn node has a disk
// whose "Schedulable" condition is False. Longhorn flips that condition to
// False (reason "DiskPressure") once a disk's available space falls below its
// storage-minimal-available floor - the state a too-small /persist reaches on
// EVE-k, where the longhorn-manager pods stay Ready but no replica can be
// placed. Reported so KubeStorageInfo.Health can reflect unschedulable storage
// instead of appearing Healthy. The returned reason (node/disk/reason) is for
// logging; it is not propagated in KubeStorageInfo.
func longhornStorageUnschedulable() (bool, string) {
	config, err := GetKubeConfig()
	if err != nil {
		return false, ""
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return false, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	nodes, err := lhClient.LonghornV1beta2().Nodes(longhornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, ""
	}
	for _, node := range nodes.Items {
		for diskName, ds := range node.Status.DiskStatus {
			if ds == nil {
				continue
			}
			for _, cond := range ds.Conditions {
				if cond.Type == lhv1beta2.DiskConditionTypeSchedulable &&
					cond.Status == lhv1beta2.ConditionStatusFalse {
					return true, fmt.Sprintf("node %s disk %s unschedulable: %s",
						node.ObjectMeta.Name, diskName, cond.Reason)
				}
			}
		}
	}
	return false, ""
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

	// A too-small /persist keeps the longhorn-manager pods Ready (so the
	// daemonset check above stays Healthy) yet leaves the Longhorn disk
	// unschedulable, so no replica can be placed. Reflect that as degraded
	// storage health rather than reporting Healthy.
	if unschedulable, _ := longhornStorageUnschedulable(); unschedulable {
		ksi.Health = min(ksi.Health, types.ServiceStatusDegraded)
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

// lhVolHasHealthyReplicaWithoutNode returns true if a volume can support losing a replica on the provided node name
// and still have an online replica
func lhVolHasHealthyReplicaWithoutNode(log *base.LogObject, repList *lhv1beta2.ReplicaList, ignoreRepOnNode string) (hasHealthyReplica bool) {
	var healthyReplicas []lhv1beta2.Replica
	// filter list to replicas which are healthy
	for _, lhReplica := range repList.Items {
		if lhReplica.Spec.NodeID == ignoreRepOnNode {
			log.Warnf("replica:%s Spec.NodeID:%s", lhReplica.ObjectMeta.Name, ignoreRepOnNode)
			continue
		}
		if lhReplica.Status.OwnerID == ignoreRepOnNode {
			log.Warnf("replica:%s Status.OwnerID:%s", lhReplica.ObjectMeta.Name, ignoreRepOnNode)
			continue
		}
		if lhReplica.Spec.HealthyAt == "" {
			log.Warnf("replica:%s Spec.HealthyAt empty", lhReplica.ObjectMeta.Name)
			continue
		}
		healthyReplicas = append(healthyReplicas, lhReplica)
	}
	hasHealthyReplica = (len(healthyReplicas) > 0)
	log.Warnf("replica healthyReplicaCount:%d hasHealthyReplica:%t", len(healthyReplicas), hasHealthyReplica)
	return hasHealthyReplica
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
	lhCtx, lhCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer lhCancel()
	replicas, err := lhClient.LonghornV1beta2().Replicas(longhornNamespace).List(lhCtx, metav1.ListOptions{
		LabelSelector: strings.Join(labelSelectors, ","),
	})
	if err != nil {
		// No replicas or no replicas crd is not a reason to error:
		// eg. the server could not find the requested resource (get replicas.longhorn.io)
		// return empty list instead of error
		if k8serrors.IsNotFound(err) {
			return &lhv1beta2.ReplicaList{}, nil
		}
		return nil, fmt.Errorf("LonghornReplicaList labelSelector:%s can't get replicas: %v", strings.Join(labelSelectors, ","), err)
	}
	return replicas, nil
}

// longhornReplicaDelete deletes replicas for a given longhorn volume which is hosted on a given kubernetes node
func longhornReplicaDelete(lhRepName string) error {
	apiExists, err := longhornAPIExists()
	if err != nil {
		return err
	}
	if !apiExists {
		return nil
	}

	config, err := GetKubeConfig()
	if err != nil {
		return err
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return err
	}

	gracePeriod := int64(0)
	propagationPolicy := metav1.DeletePropagationBackground
	err = lhClient.LonghornV1beta2().Replicas(longhornNamespace).Delete(context.Background(), lhRepName, metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
		PropagationPolicy:  &propagationPolicy,
	})

	return err
}

func longhornVolumeSetNode(lhVolName string, kubeNodeName string) error {
	apiExists, err := longhornAPIExists()
	if err != nil {
		return err
	}
	if !apiExists {
		return nil
	}

	config, err := GetKubeConfig()
	if err != nil {
		return err
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return err
	}

	// First fix the logical volume object nodeID
	vol, err := lhClient.LonghornV1beta2().Volumes(longhornNamespace).Get(context.Background(), lhVolName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	vol.Spec.NodeID = kubeNodeName
	vol.Status.OwnerID = kubeNodeName
	vol.Status.CurrentNodeID = kubeNodeName
	// Volumes migrated from longhorn < v1.7 may have an empty BackupTargetName.
	// The v1.9.x webhook validator rejects any Update() with an empty BackupTargetName,
	// so set it to the well-known default if unset.
	if vol.Spec.BackupTargetName == "" {
		vol.Spec.BackupTargetName = "default"
	}
	_, err = lhClient.LonghornV1beta2().Volumes(longhornNamespace).Update(context.Background(), vol, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	// Next fix the volume's engine nodeID
	engines, err := lhClient.LonghornV1beta2().Engines(longhornNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil
	}
	for _, eng := range engines.Items {
		if eng.Spec.VolumeName != lhVolName {
			continue
		}
		eng.Spec.NodeID = kubeNodeName
		_, err := lhClient.LonghornV1beta2().Engines(longhornNamespace).Update(context.Background(), &eng, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return err
}

// SetLonghornNodeDiskReserved sets StorageReserved on every disk of the named Longhorn node.
// Returns (false, nil) if the Longhorn API is absent or the node object does not exist yet,
// so callers should retry until (true, nil) is returned.
// Returns (true, nil) for non-schedulable (tie-breaker) nodes: the reservation is not
// needed and the Longhorn admission webhook would reject any update attempt.
func SetLonghornNodeDiskReserved(nodeName string, reservedBytes int64) (bool, error) {
	apiExists, err := longhornAPIExists()
	if !apiExists && err == nil {
		// Longhorn may not yet be installed on this boot yet
		return false, nil
	}
	if err != nil {
		return false, err
	}

	config, err := GetKubeConfig()
	if err != nil {
		return false, fmt.Errorf("SetLonghornNodeDiskReserved: kubeconfig: %v", err)
	}
	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("SetLonghornNodeDiskReserved: versioned client: %v", err)
	}

	lhCtx, lhCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer lhCancel()
	return setLonghornNodeDiskReservedInner(lhCtx, nodeName, reservedBytes,
		lhClient.LonghornV1beta2().Nodes(longhornNamespace))
}

// setLonghornNodeDiskReservedInner is the testable core of SetLonghornNodeDiskReserved.
// All Longhorn node I/O is injected through the nodes interface argument so unit tests
// can supply hand-written mocks without a live cluster.
func setLonghornNodeDiskReservedInner(ctx context.Context, nodeName string,
	reservedBytes int64, nodes lhNodeGetUpdater) (bool, error) {
	node, err := nodes.Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("SetLonghornNodeDiskReserved: get node %s: %v", nodeName, err)
	}

	// Tie breaker nodes will have a non-deployed engine and the longhorn
	// validator will return an error.
	// example:
	// 'admission webhook "validator.longhorn.io" denied the request:
	// spec and status of disks on node <node> are being syncing
	// and please retry later.'
	//
	// Skip this node, the reservation isn't necessary here.
	// Return true so the caller stops retrying — the reservation is not needed.
	for _, cond := range node.Status.Conditions {
		if cond.Type == lhv1beta2.NodeConditionTypeSchedulable &&
			cond.Status != lhv1beta2.ConditionStatusTrue {
			return true, nil
		}
	}

	changed := false
	for key, disk := range node.Spec.Disks {
		if disk.StorageReserved != reservedBytes {
			disk.StorageReserved = reservedBytes
			node.Spec.Disks[key] = disk
			changed = true
		}
	}
	if !changed {
		return true, nil
	}

	_, err = nodes.Update(ctx, node, metav1.UpdateOptions{})
	if err != nil {
		return false, fmt.Errorf("SetLonghornNodeDiskReserved: update node %s: %v", nodeName, err)
	}
	return true, nil
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

	lhCtx, lhCancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer lhCancel()

	// If the longhorn-system namespace exists then we should expect the longhorn api endpoint is available.
	ns, err := cs.CoreV1().Namespaces().Get(lhCtx, longhornNamespace, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if ns == nil {
		return false, nil
	}
	return true, nil
}

func lhVolGet(lhVolName string) (*lhv1beta2.Volume, error) {
	apiExists, err := longhornAPIExists()
	if err != nil {
		return nil, err
	}
	if !apiExists {
		return nil, nil
	}

	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("lhVolGet can't get kubeconfig %v", err)
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("lhVolGet can't get versioned config: %v", err)
	}

	// Don't allow a k8s api timeout keep us waiting forever, set this one explicitly as its used in metrics path
	shortContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lhVol, err := lhClient.LonghornV1beta2().Volumes(longhornNamespace).Get(shortContext, lhVolName, metav1.GetOptions{})
	if err != nil || lhVol == nil {
		return nil, fmt.Errorf("lhVolGet can't get lh vol err:%v", err)
	}

	return lhVol, nil
}

func lhEiDeployedOnNode(lhEiName string, nodeName string) (deployed bool, err error) {
	apiExists, err := longhornAPIExists()
	if err != nil {
		return false, err
	}
	if !apiExists {
		return false, nil
	}

	config, err := GetKubeConfig()
	if err != nil {
		return false, fmt.Errorf("lhEiDeployedOnNode can't get kubeconfig %v", err)
	}

	lhClient, err := versioned.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("lhEiDeployedOnNode can't get versioned config: %v", err)
	}

	// Don't allow a k8s api timeout keep us waiting forever, set this one explicitly as its used in metrics path
	shortContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	eiList, err := lhClient.LonghornV1beta2().EngineImages(longhornNamespace).List(shortContext, metav1.ListOptions{})
	if err != nil || eiList == nil {
		return false, fmt.Errorf("lhEiDeployedOnNode can't get lh ei err:%v", err)
	}

	for _, ei := range eiList.Items {
		if ei.Spec.Image != lhEiName {
			continue
		}
		ndm := ei.Status.NodeDeploymentMap
		val, exists := ndm[nodeName]
		if !exists {
			return false, fmt.Errorf("engineimage deployment map missing node:%s", nodeName)
		}
		deployed = val
	}

	return deployed, nil
}
