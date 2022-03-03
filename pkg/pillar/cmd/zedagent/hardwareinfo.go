// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

func hardwareInfoTask(ctxPtr *zedagentContext, triggerHwInfo <-chan struct{}) {
	wdName := agentName + "hwinfo"

	stillRunning := time.NewTicker(30 * time.Second)
	ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	ctxPtr.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-triggerHwInfo:
			start := time.Now()
			log.Function("HardwareInfoTask got message")

			PublishHardwareInfoToZedCloud(ctxPtr)
			ctxPtr.iteration++
			log.Function("HardwareInfoTask done with message")
			ctxPtr.ps.CheckMaxTimeTopic(wdName, "PublishHardwareInfo", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

//PublishHardwareInfoToZedCloud send HardwareInfo message
func PublishHardwareInfoToZedCloud(ctx *zedagentContext) {
	deviceUUID := devUUID.String() + "hwinfo"
	hwInfo := new(info.HardwareInfo)
	hwInfo.CollectorErrors = false
	var errReadDisk []error
	bailOnHTTPErr := false //we sended not so ofen

	// Get information about disks
	disksInfo, err := hardware.ReadSMARTinfoForDisks()
	if err != nil {
		hwInfo.CollectorErrors = true
		errReadDisk = append(errReadDisk, err)
	} else {
		for _, disk := range disksInfo.Disks {
			stDiskInfo := new(info.StorageDiskInfo)
			stDiskInfo.DiskName = disk.DiskName
			stDiskInfo.SerialNumber = disk.SerialNumber
			stDiskInfo.Model = disk.ModelNumber
			stDiskInfo.Wwn = fmt.Sprintf("%x", disk.Wwn)
			// add smart data after finish work with NVMe

			/* diskRes, err := hardware.GetStorageDiskInfo(disk.Name)
			if err != nil {
				hwInfo.CollectorErrors = true
				errReadDisk = append(errReadDisk, err)
				continue
			} */

			hwInfo.Disks = append(hwInfo.Disks, stDiskInfo)
		}
	}

	log.Tracef("PublishHardwareInfoToZedCloud sending %v", hwInfo)
	data, err := proto.Marshal(hwInfo)
	if err != nil {
		log.Fatal("PublishHardwareInfoToZedCloud proto marshaling error: ", err)
	}

	statusUrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("PublishHardwareInfoToZedCloud malloc error")
	}
	size := int64(proto.Size(hwInfo))

	zedcloud.SetDeferred(zedcloudCtx, deviceUUID, buf, size,
		statusUrl, bailOnHTTPErr, info.ZInfoTypes_ZiHardWare)
	zedcloud.HandleDeferred(zedcloudCtx, time.Now(), 0, true)
}
