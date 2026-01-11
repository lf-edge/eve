// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	hwInfo.EveRelease = agentlog.EveVersion()
	hwInfo.EvePlatform = hardware.GetHardwareModel(log)
	hwInfo.Partition = agentlog.EveCurrentPartition()
	hwInfo.KernelVersion = hardware.GetKernelVersion()
	hwInfo.KernelCmdline = hardware.GetKernelCmdline()
	hwInfo.KernelFlavor = hardware.GetKernelFlavor()

	err := hardware.AddInventoryInfo(log, hwInfo)
	if err != nil {
		log.Warnf("could not add inventory info: %v", err)
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
