// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
)

func hardwareInfoTask(ctxPtr *zedagentContext, triggerHwInfo <-chan destinationBitset) {
	wdName := agentName + "hwinfo"

	stillRunning := time.NewTicker(30 * time.Second)
	ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	ctxPtr.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case dest := <-triggerHwInfo:
			start := time.Now()
			log.Function("HardwareInfoTask got message")

			PublishHardwareInfoToZedCloud(ctxPtr, dest)
			ctxPtr.iteration++
			log.Function("HardwareInfoTask done with message")
			ctxPtr.ps.CheckMaxTimeTopic(wdName, "PublishHardwareInfo", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// PublishHardwareInfoToZedCloud send ZInfoHardware message
func PublishHardwareInfoToZedCloud(ctx *zedagentContext, dest destinationBitset) {
	var ReportHwInfo = &info.ZInfoMsg{}
	hwInfoKey := devUUID.String() + "hwinfo"
	bailOnHTTPErr := true
	hwType := new(info.ZInfoTypes)
	*hwType = info.ZInfoTypes_ZiHardware
	ReportHwInfo.Ztype = *hwType
	ReportHwInfo.DevId = *proto.String(devUUID.String())
	ReportHwInfo.AtTimeStamp = ptypes.TimestampNow()
	log.Functionf("PublishHardwareInfoToZedCloud uuid %s", hwInfoKey)

	hwInfo := new(info.ZInfoHardware)

	// Get information about disks
	disksInfo, err := hardware.ReadSMARTinfoForDisks()
	if err != nil {
		log.Fatal("PublishHardwareInfoToZedCloud get information about disks failed. Error: ", err)
		return
	}

	for _, disk := range disksInfo.Disks {
		stDiskInfo := new(info.StorageDiskInfo)
		if disk.CollectingStatus != types.SmartCollectingStatusSuccess {
			stDiskInfo.DiskName = *proto.String(disk.DiskName)
			stDiskInfo.CollectorErrors = *proto.String(disk.Errors.Error())
			hwInfo.Disks = append(hwInfo.Disks, stDiskInfo)
			continue
		}

		stDiskInfo.DiskName = *proto.String(disk.DiskName)
		stDiskInfo.SerialNumber = *proto.String(disk.SerialNumber)
		stDiskInfo.Model = *proto.String(disk.ModelNumber)
		stDiskInfo.Wwn = *proto.String(fmt.Sprintf("%x", disk.Wwn))

		attrSmart := new(info.SmartMetric)
		attrSmart.ReallocatedSectorCt = getSmartAttr(types.SmartAttrIDRealLocatedSectorCt, disk.SmartAttrs)
		attrSmart.PowerOnHours = getSmartAttr(types.SmartAttrIDPowerOnHours, disk.SmartAttrs)
		attrSmart.PowerCycleCount = getSmartAttr(types.SmartAttrIDPowerCycleCount, disk.SmartAttrs)
		attrSmart.ReallocatedEventCount = getSmartAttr(types.SmartAttrIDRealLocatedEventCount, disk.SmartAttrs)
		attrSmart.CurrentPendingSector = getSmartAttr(types.SmartAttrIDCurrentPendingSectorCt, disk.SmartAttrs)
		attrSmart.Temperature = getSmartAttr(types.SmartAttrIDTemperatureCelsius, disk.SmartAttrs)
		stDiskInfo.SmartData = append(stDiskInfo.SmartData, attrSmart)

		hwInfo.Disks = append(hwInfo.Disks, stDiskInfo)
	}

	ReportHwInfo.InfoContent = new(info.ZInfoMsg_Hwinfo)
	if x, ok := ReportHwInfo.GetInfoContent().(*info.ZInfoMsg_Hwinfo); ok {
		x.Hwinfo = hwInfo
	}

	log.Tracef("PublishHardwareInfoToZedCloud sending %v", ReportHwInfo)
	data, err := proto.Marshal(ReportHwInfo)
	if err != nil {
		log.Fatal("PublishHardwareInfoToZedCloud proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("PublishHardwareInfoToZedCloud malloc error")
	}
	size := int64(proto.Size(ReportHwInfo))

	queueInfoToDest(ctx, dest, hwInfoKey, buf, size, bailOnHTTPErr, false, false,
		info.ZInfoTypes_ZiHardware)
}

func getSmartAttr(id int, diskData []*types.DAttrTable) *info.SmartAttr {
	attrResult := new(info.SmartAttr)
	for _, attr := range diskData {
		if attr.ID == id {
			attrResult.Id = uint32(id)
			attrResult.RawValue = uint64(attr.RawValue)
			attrResult.Worst = uint64(attr.Worst)
			attrResult.Value = uint64(attr.Value)
			return attrResult
		}
	}

	return nil
}
