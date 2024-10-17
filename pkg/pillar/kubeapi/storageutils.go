// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	longhornDevPath = "/dev/longhorn"
)

func getMajorMinorStr(stat syscall.Stat_t) string {
	major := unix.Major(stat.Rdev)
	minor := unix.Minor(stat.Rdev)
	return fmt.Sprintf("%d:%d", major, minor)
}

func isLonghornVolAttachedToThisNode(pv string) bool {
	_, err := os.Stat(longhornDevPath + "/" + pv)
	return err == nil
}
func deviceExists(dev string) bool {
	_, err := os.Stat("/dev/" + dev)
	return err == nil
}

// CleanupDetachedDiskMetrics loops over existing DiskMetric
// objects and unpublishes them if the device no longer exists.
// Clustered volumes are expected to not be static, they will
// move between nodes.
func CleanupDetachedDiskMetrics(pubDiskMetric pubsub.Publication, pvcToPvMap map[string]string) {
	existingMetrics := pubDiskMetric.GetAll()

	for id, metric := range existingMetrics {
		if id == "" {
			continue
		}

		dm, ok := metric.(types.DiskMetric)
		if ok && dm.IsDir {
			continue
		}

		if strings.Contains(id, "pvc-") {
			pvName, ok := pvcToPvMap[id]
			// Could be PVC deleted or just not attached locally
			if !ok || !isLonghornVolAttachedToThisNode(pvName) {
				pubDiskMetric.Unpublish(id)
			}
		} else {
			// Look for sdX devices which used to exist
			// These would have been the block device
			// which shared major:minor with the longhorn device
			if !deviceExists(id) {
				pubDiskMetric.Unpublish(id)
			}
		}
	}
}

// LonghornGetMajorMinorMaps builds two maps between
// device major:minor -> kube-pv-name/lh-volume-name
// and kube-pv-name/lh-volume-name -> maj:min to
// help callers find a PV/PVC in /proc/diskstats
// which only shows the sdX path.
func LonghornGetMajorMinorMaps() (map[string]string, map[string]string, error) {
	lhMajMinToNameMap := make(map[string]string) // maj:min -> kube-pv-name/lh-volume-name
	lhNameToMajMinMap := make(map[string]string) // kube-pv-name/lh-volume-name -> maj:min

	lhPvcList, err := os.ReadDir(longhornDevPath)
	for _, lhDirEnt := range lhPvcList {
		var lhStat syscall.Stat_t
		err := syscall.Stat(longhornDevPath+"/"+lhDirEnt.Name(), &lhStat)

		if err != nil {
			continue
		}
		majMinKey := getMajorMinorStr(lhStat)
		lhMajMinToNameMap[majMinKey] = lhDirEnt.Name()
		lhNameToMajMinMap[lhDirEnt.Name()] = majMinKey

	}
	return lhMajMinToNameMap, lhNameToMajMinMap, fmt.Errorf("unable to read longhorn devs: %w", err)
}

// SCSIGetMajMinMaps builds two maps to assist linking with other devices
// First map: maj:min -> sdX
// Second map: sdX -> maj:min
func SCSIGetMajMinMaps() (map[string]string, map[string]string, error) {
	sdMajMinToNameMap := make(map[string]string) // maj:min -> sdX
	sdNameToMajMinMap := make(map[string]string) // sdX -> maj:min

	blockDevs, err := os.ReadDir("/sys/class/block/")
	if err != nil {
		return sdMajMinToNameMap, sdNameToMajMinMap, fmt.Errorf("unable to read block devs")
	}

	for _, devEnt := range blockDevs {
		var blockStat syscall.Stat_t
		err := syscall.Stat("/dev/"+devEnt.Name(), &blockStat)
		if err != nil {
			continue
		}
		majMinVal := getMajorMinorStr(blockStat)
		sdMajMinToNameMap[majMinVal] = devEnt.Name()
		sdNameToMajMinMap[devEnt.Name()] = majMinVal
	}
	return sdMajMinToNameMap, sdNameToMajMinMap, nil
}

// PvPvcMaps returns two maps of pv-name/longhorn-name -> pvc-name
// and pvc-name -> pv-name/longhorn-name
func PvPvcMaps() (map[string]string, map[string]string, error) {
	pvsMap := make(map[string]string)
	pvcsMap := make(map[string]string)

	clientset, err := GetClientSet()
	if err != nil {
		return pvsMap, pvcsMap, fmt.Errorf("PvPvcMaps: can't get clientset %v", err)
	}

	pvcs, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return pvsMap, pvcsMap, fmt.Errorf("PvPvcMaps:%v", err)
	}
	for _, pvc := range pvcs.Items {
		pvsMap[pvc.Spec.VolumeName] = pvc.ObjectMeta.Name
		pvcsMap[pvc.ObjectMeta.Name] = pvc.Spec.VolumeName
	}
	return pvsMap, pvcsMap, nil
}
