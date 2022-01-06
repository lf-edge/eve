// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lf-edge/eve/api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

const (
	localAppInfoURLPath               = "/api/v1/appinfo"
	localAppInfoPOSTInterval          = time.Minute
	localAppInfoPOSTThrottledInterval = time.Hour
)

var (
	lastLocalAppInfoSentHash []byte
	throttledLocalAppInfo    bool
)

//updateLocalAppInfoTicker sets ticker options to the initial value
//if throttle set, will use localAppInfoPOSTThrottledInterval as interval
func updateLocalAppInfoTicker(ctx *getconfigContext, throttle bool) {
	interval := float64(localAppInfoPOSTInterval)
	if throttle {
		interval = float64(localAppInfoPOSTThrottledInterval)
	}
	max := 1.1 * interval
	min := 0.8 * max
	throttledLocalAppInfo = throttle
	ctx.localAppInfoPOSTTicker.UpdateRangeTicker(time.Duration(min), time.Duration(max))
}

func initializeLocalAppInfo(ctx *getconfigContext) {
	max := 1.1 * float64(localAppInfoPOSTInterval)
	min := 0.8 * max
	ctx.localAppInfoPOSTTicker = flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
}

func triggerLocalAppInfoPOST(ctx *getconfigContext) {
	log.Functionf("Triggering POST for %s to local server", localAppInfoURLPath)
	if throttledLocalAppInfo {
		log.Functionln("throttledLocalAppInfo flag set")
		return
	}
	ctx.localAppInfoPOSTTicker.TickNow()
}

// Run a periodic POST request to send information message about apps to local server.
func localAppInfoPOSTTask(ctx *getconfigContext) {

	log.Functionf("localAppInfoPOSTTask: waiting for localAppInfoPOSTTicker")
	// wait for the first trigger
	<-ctx.localAppInfoPOSTTicker.C
	log.Functionln("localAppInfoPOSTTask: waiting for localAppInfoPOSTTicker done")
	// trigger again to pass into the loop
	triggerLocalAppInfoPOST(ctx)

	wdName := agentName + "-localappinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.zedagentCtx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-ctx.localAppInfoPOSTTicker.C:
			start := time.Now()

			sendLocalAppInfo(ctx)

			ctx.zedagentCtx.ps.CheckMaxTimeTopic(wdName, "localAppInfoPOSTTask", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func sendLocalAppInfo(ctx *getconfigContext) {
	localProfileServer := ctx.localProfileServer
	if localProfileServer == "" {
		return
	}
	localServerURL, err := makeLocalServerBaseURL(localProfileServer)
	if err != nil {
		log.Errorf("sendLocalAppInfo: makeLocalServerBaseURL: %v", err)
		return
	}
	if !ctx.localServerMap.upToDate {
		err := updateLocalServerMap(ctx, localServerURL)
		if err != nil {
			log.Errorf("sendLocalAppInfo: updateLocalServerMap: %v", err)
			return
		}
	}
	srvMap := ctx.localServerMap.servers
	if len(srvMap) == 0 {
		log.Functionf("sendLocalAppInfo: cannot find any configured apps for localServerURL: %s",
			localServerURL)
		return
	}

	localInfo := prepareLocalInfo(ctx)

	h := sha256.New()
	computeConfigElementSha(h, localInfo)
	newHash := h.Sum(nil)

	if bytes.Equal(lastLocalAppInfoSentHash, newHash) {
		log.Functionln("sendLocalAppInfo: no update")
		return
	}

	var errList []string
	for bridgeName, servers := range srvMap {
		for _, srv := range servers {
			fullURL := srv.localServerAddr + localAppInfoURLPath
			resp, err := zedcloud.SendLocalProto(
				zedcloudCtx, fullURL, bridgeName, srv.bridgeIP, localInfo, nil)
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			if resp.StatusCode == http.StatusNotFound {
				//throttle sending to be about once per hour
				updateLocalAppInfoTicker(ctx, true)
			}
			if resp.StatusCode != http.StatusOK {
				errList = append(errList, fmt.Sprintf("SendLocal: wrong response status code: %d",
					resp.StatusCode))
				continue
			}
			updateLocalAppInfoTicker(ctx, false)
			lastLocalAppInfoSentHash = newHash
			return
		}
	}
	log.Errorf("sendLocalAppInfo: all attempts failed: %s", strings.Join(errList, ";"))
}

func prepareLocalInfo(ctx *getconfigContext) *profile.LocalAppInfoList {
	msg := profile.LocalAppInfoList{}
	addAppInstanceFunc := func(key string, value interface{}) bool {
		ais := value.(types.AppInstanceStatus)
		zinfoAppInst := new(profile.LocalAppInfo)
		zinfoAppInst.Id = ais.UUIDandVersion.UUID.String()
		zinfoAppInst.Version = ais.UUIDandVersion.Version
		zinfoAppInst.Name = ais.DisplayName
		zinfoAppInst.Err = encodeErrorInfo(ais.ErrorAndTimeWithSource.ErrorDescription)
		zinfoAppInst.State = ais.State.ZSwState()
		msg.AppsInfo = append(msg.AppsInfo, zinfoAppInst)
		return true
	}
	ctx.subAppInstanceStatus.Iterate(addAppInstanceFunc)
	return &msg
}
