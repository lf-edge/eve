// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// createOrUpdatePvcDiskMetrics creates or updates metrics for all kubevirt PVCs
// PVC mknod will match one of existing sdX devices, create copies for convenience
func createOrUpdatePvcDiskMetrics(ctx *volumemgrContext) {
	log.Functionf("createOrUpdatePvcDiskMetrics")
	var diskMetricList []*types.DiskMetric

	sdMajMinToNameMap, _, err := kubeapi.SCSIGetMajMinMaps()
	if err != nil {
		log.Errorf("Failed to get SCSI device maps: %v", err)
		return
	}
	_, pvNameToMajMin, err := kubeapi.LonghornGetMajorMinorMaps()
	if err != nil {
		log.Errorf("Failed to get Longhorn device maps: %v", err)
		return
	}
	_, pvcToPvMap, err := kubeapi.PvPvcMaps()
	if err != nil {
		log.Errorf("Failed to get PVC-PV maps: %v", err)
		return
	}

	kubeapi.CleanupDetachedDiskMetrics(ctx.pubDiskMetric, pvcToPvMap)

	for pvcName, pvName := range pvcToPvMap {
		// pv-name will be of format "pvc-<uuid>"
		// pvc-name will be of format "<uuid>-pvc-0"
		// pvc-name uuid prefix will show in VolumeStatus
		// full pvc-name will be in VolumeStatus.FileLocation

		if pvName == "" {
			continue
		}

		pvMajMinStr, ok := pvNameToMajMin[pvName]
		if !ok {
			continue
		}

		sdName, ok := sdMajMinToNameMap[pvMajMinStr]
		if !ok {
			continue
		}

		var metric *types.DiskMetric
		metric = lookupDiskMetric(ctx, sdName)
		if metric == nil {
			continue
		}

		pvcMetric := lookupDiskMetric(ctx, sdName+"-"+pvcName)
		if pvcMetric == nil {
			pvcMetric = &types.DiskMetric{DiskPath: sdName + "-" + pvcName, IsDir: false}
		}
		pvcMetric.ReadBytes = metric.ReadBytes
		pvcMetric.WriteBytes = metric.WriteBytes
		pvcMetric.ReadCount = metric.ReadCount
		pvcMetric.WriteCount = metric.WriteCount
		pvcMetric.TotalBytes = metric.TotalBytes
		pvcMetric.UsedBytes = metric.UsedBytes
		pvcMetric.FreeBytes = metric.FreeBytes
		pvcMetric.IsDir = false
		diskMetricList = append(diskMetricList, pvcMetric)
	}
	publishDiskMetrics(ctx, diskMetricList...)
}
