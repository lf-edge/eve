// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"time"

	libzfs "github.com/andrewd-zededa/go-libzfs"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

const (
	storageMetricsPublishInterval = 5 * time.Second // interval between publishing metrics from zfs
)

func storageMetricsPublisher(ctxPtr *zfsContext) {
	if persist.ReadPersistType() != types.PersistZFS {
		return
	}
	collectAndPublishStorageMetrics(ctxPtr)

	t := time.NewTicker(storageMetricsPublishInterval)
	for {
		select {
		case <-t.C:
			collectAndPublishStorageMetrics(ctxPtr)
		}
	}
}

func collectAndPublishStorageMetrics(ctxPtr *zfsContext) {
	log.Functionf("collectAndPublishStorageMetrics start")
	ctxPtr.zfsIterLock.Lock()
	defer ctxPtr.zfsIterLock.Unlock()
	zpoolList, err := libzfs.PoolOpenAll()
	if err != nil {
		log.Errorf("get zpool list for collect metrics failed %v", err)
	} else {
		for _, zpool := range zpoolList {
			defer zpool.Close()
			vdevs, err := zpool.VDevTree()
			if err != nil {
				log.Errorf("get vdev tree for collect metrics failed %v", err)
				continue
			}

			zfsPoolMetrics := zfs.GetZpoolMetrics(vdevs)

			if !base.IsHVTypeKube() {
				// Fill metrics for zvols
				for _, vs := range ctxPtr.subVolumeStatus.GetAll() {
					volumeStatus := vs.(types.VolumeStatus)
					if volumeStatus.State < types.CREATING_VOLUME {
						// we did not go to creating of volume, nothing to measure
						continue
					}
					if !volumeStatus.UseZVolDisk(persist.ReadPersistType()) {
						// we do not create zvol for that volumeStatus
						continue
					}
					zVolMetric, err := zfs.GetZvolMetrics(volumeStatus, zfsPoolMetrics.PoolName)
					if err != nil {
						// It is possible that the logical volume belongs to another zpool
						continue
					}
					zfsPoolMetrics.ZVols = append(zfsPoolMetrics.ZVols, zVolMetric)
				}
			}

			if err := ctxPtr.storageMetricsPub.Publish(zfsPoolMetrics.Key(), *zfsPoolMetrics); err != nil {
				log.Errorf("error in publishing of storageMetrics: %s", err)
			}
		}
	}
	log.Functionf("collectAndPublishStorageMetrics Done")
}
