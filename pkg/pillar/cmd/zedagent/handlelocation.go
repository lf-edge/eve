// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Run a periodic post of the location information.
func locationTimerTask(ctx *zedagentContext, handleChannel chan interface{},
	triggerLocationInfo chan destinationBitset) {
	var cloudIteration int

	// Ticker for periodic publishing to the controller.
	cloudInterval := ctx.globalConfig.GlobalValueInt(types.LocationCloudInterval)
	interval := time.Duration(cloudInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	cloudTicker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Ticker for periodic publishing to the Local profile server.
	appInterval := ctx.globalConfig.GlobalValueInt(types.LocationAppInterval)
	interval = time.Duration(appInterval) * time.Second
	max = float64(interval)
	min = max * 0.3
	appTicker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Return handles to the caller.
	handleChannel <- cloudTicker
	handleChannel <- appTicker

	wdName := agentName + "-location"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-cloudTicker.C:
			publishLocation(ctx, &cloudIteration, wdName, ControllerDest)
		case dest := <-triggerLocationInfo:
			publishLocation(ctx, &cloudIteration, wdName, dest)
		case <-appTicker.C:
			publishLocation(ctx, &cloudIteration, wdName, LPSDest)
		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// Called when globalConfig changes.
// Assumes that the caller has verifier that the interval has changed.
func updateLocationCloudTimer(ctx *getconfigContext, cloudInterval uint32) {
	if ctx.locationCloudTickerHandle == nil {
		log.Warnf("updateLocationCloudTimer: locationCloudTickerHandle is still nil")
		return
	}
	interval := time.Duration(cloudInterval) * time.Second
	log.Functionf("updateLocationCloudTimer: cloudInterval change to %v", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(ctx.locationCloudTickerHandle,
		time.Duration(min), time.Duration(max))
	// Force an immediate timeout since timer could have decreased.
	flextimer.TickNow(ctx.locationCloudTickerHandle)
}

// Called when globalConfig changes.
// Assumes that the caller has verifier that the interval has changed.
func updateLocationAppTimer(ctx *getconfigContext, appInterval uint32) {
	if ctx.locationAppTickerHandle == nil {
		log.Warnf("updateLocationAppTimer: locationAppTickerHandle is still nil")
		return
	}
	interval := time.Duration(appInterval) * time.Second
	log.Functionf("updateLocationAppTimer: appInterval change to %v", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(ctx.locationAppTickerHandle,
		time.Duration(min), time.Duration(max))
	// Force an immediate timeout since timer could have decreased.
	flextimer.TickNow(ctx.locationAppTickerHandle)
}

func publishLocation(ctx *zedagentContext, iter *int, wdName string,
	dest destinationBitset) {
	locationInfo := getLocationInfo(ctx)
	if locationInfo == nil {
		// Not available.
		return
	}
	if dest&(ControllerDest|LOCDest) != 0 {
		*iter++
		start := time.Now()
		publishLocationToDest(ctx, locationInfo, *iter, dest)
		ctx.ps.CheckMaxTimeTopic(wdName, "publishLocationToDest", start,
			warningTime, errorTime)
	}
	if dest&LPSDest != 0 {
		start := time.Now()
		ctx.getconfigCtx.localCmdAgent.PublishLocationToLps(locationInfo)
		ctx.ps.CheckMaxTimeTopic(wdName, "publishLocationToLocalServer", start,
			warningTime, errorTime)
	}
}

func publishLocationToDest(ctx *zedagentContext, locInfo *info.ZInfoLocation,
	iteration int, dest destinationBitset) {
	log.Functionf("publishLocationToDest: iteration %d", iteration)
	infoMsg := &info.ZInfoMsg{
		Ztype: info.ZInfoTypes_ZiLocation,
		DevId: devUUID.String(),
		InfoContent: &info.ZInfoMsg_Locinfo{
			Locinfo: locInfo,
		},
		AtTimeStamp: timestamppb.Now(),
	}

	log.Functionf("publishLocationToDest: sending %v", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishLocationToDest: proto marshaling error: ", err)
	}
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}

	const bailOnHTTPErr = false
	const withNetTrace = false
	key := "location:" + devUUID.String()

	// Even for the controller destination we can't stall the queue on error,
	// because this is recurring call, so set @forcePeriodic to true
	forcePeriodic := true
	queueInfoToDest(ctx, dest, key, buf, bailOnHTTPErr, withNetTrace,
		forcePeriodic, info.ZInfoTypes_ZiLocation)
}

func getLocationInfo(ctx *zedagentContext) *info.ZInfoLocation {
	m, err := ctx.subLocationInfo.Get("global")
	if err != nil {
		// Location info is not available.
		return nil
	}
	locInfo, ok := m.(types.WwanLocationInfo)
	if !ok {
		log.Error("unexpected type of wwan location info")
		return nil
	}
	unixSec := int64(locInfo.UTCTimestamp / 1000)
	unixNano := int64((locInfo.UTCTimestamp % 1000) * 1000000)
	timestamp := time.Unix(unixSec, unixNano)
	return &info.ZInfoLocation{
		Logicallabel:          locInfo.LogicalLabel,
		Latitude:              locInfo.Latitude,
		Longitude:             locInfo.Longitude,
		Altitude:              locInfo.Altitude,
		UtcTimestamp:          timestamppb.New(timestamp),
		HorizontalReliability: locationReliabilityToProto(locInfo.HorizontalReliability),
		VerticalReliability:   locationReliabilityToProto(locInfo.VerticalReliability),
		HorizontalUncertainty: locInfo.HorizontalUncertainty,
		VerticalUncertainty:   locInfo.VerticalUncertainty,
	}
}

func locationReliabilityToProto(reliability types.LocReliability) info.LocReliability {
	switch reliability {
	case types.LocReliabilityUnspecified:
		return info.LocReliability_LOC_RELIABILITY_UNSPECIFIED
	case types.LocReliabilityVeryLow:
		return info.LocReliability_LOC_RELIABILITY_VERY_LOW
	case types.LocReliabilityLow:
		return info.LocReliability_LOC_RELIABILITY_LOW
	case types.LocReliabilityMedium:
		return info.LocReliability_LOC_RELIABILITY_MEDIUM
	case types.LocReliabilityHigh:
		return info.LocReliability_LOC_RELIABILITY_HIGH
	default:
		return info.LocReliability_LOC_RELIABILITY_UNSPECIFIED
	}
}
