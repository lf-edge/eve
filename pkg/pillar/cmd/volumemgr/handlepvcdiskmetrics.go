// Copyright (c) 2024 Zededa, Inc.
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

	sdMajMinToNameMap, _, _ := kubeapi.SCSIGetMajMinMaps()
	_, pvNameToMajMin, _ := kubeapi.LonghornGetMajorMinorMaps()
	_, pvcToPvMap, _ := kubeapi.PvPvcMaps()

	kubeapi.CleanupUnmountedDiskMetrics(ctx.pubDiskMetric, pvcToPvMap)

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
