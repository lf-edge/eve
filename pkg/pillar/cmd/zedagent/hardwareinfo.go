// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"fmt"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func hardwareInfoTask(ctxPtr *zedagentContext, triggerHwInfo <-chan destinationBitset) {
	wdName := agentName + "hwinfo"

	ticker := time.NewTicker(10 * time.Second)

	stillRunning := time.NewTicker(30 * time.Second)
	ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	ctxPtr.ps.RegisterFileWatchdog(wdName)

	ts := time.Now()
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
		case <-ticker.C: // even if no trigger comes, publish hardware info periodically
			if time.Now().Sub(ts) > getHardwareInfoInterval(ctxPtr) {
				ts = time.Now()
				triggerPublishHwInfo(ctxPtr)
			}
		case <-stillRunning.C:
		}
		ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func getHardwareInfoInterval(ctx *zedagentContext) time.Duration {
	interval := ctx.globalConfig.GlobalValueInt(types.HardwareInfoInterval)
	return time.Duration(interval) * time.Second
}

func triggerPublishHwInfoToDest(ctxPtr *zedagentContext, dest destinationBitset) {
	log.Function("Triggered PublishHardwareInfo")
	select {
	case ctxPtr.triggerHwInfo <- dest:
		// Do nothing more
	default:
		// This occurs if we are already trying to send a hardware info
		// and we get a second and third trigger before that is complete.
		log.Warnf("Failed to send on PublishHardwareInfo")
	}
}

func triggerPublishHwInfo(ctxPtr *zedagentContext) {
	triggerPublishHwInfoToDest(ctxPtr, AllDest)
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
	ReportHwInfo.AtTimeStamp = timestamppb.Now()
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

		stDiskInfo.SmartAttr = getSmartAttr(disk.SmartAttrs)

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

	queueInfoToDest(ctx, dest, hwInfoKey, buf, bailOnHTTPErr, false, false,
		info.ZInfoTypes_ZiHardware)
}

func getSmartAttr(diskData []*types.DAttrTable) []*info.SmartAttr {
	attrResults := []*info.SmartAttr{} // Store pointers instead of structs

	for _, attr := range diskData {
		attrResult := &info.SmartAttr{ // Allocate on heap
			Id:            uint32(attr.ID),
			AttributeName: attr.AttributeName,
			RawValue:      uint64(attr.RawValue),
			Thresh:        uint64(attr.Threshold),
			Worst:         uint64(attr.Worst),
			Value:         uint64(attr.Value),
			Type:          attr.Type,
		}

		attrResults = append(attrResults, attrResult) // Append pointer
	}

	return attrResults
}
