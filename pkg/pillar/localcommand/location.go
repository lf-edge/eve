// Copyright (c) 2017-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/info"
)

const (
	// lpsLocationURLPath is the endpoint on the Local Profile Server (LPS)
	// where EVE publishes location updates.
	lpsLocationURLPath = "/api/v1/location"
	// lpsLocationThrottledInterval defines the minimum interval (5 minutes)
	// enforced when the LPS responds with HTTP 404 to a location update request.
	// This serves as a backoff signal to reduce the reporting rate.
	lpsLocationThrottledInterval = 5 * time.Minute
)

// PublishLocationToLps sends the current device location to the Local Profile
// Server (LPS). Unlike periodic tasks, this method is not scheduled by
// LocalCmdAgent itself — instead, zedagent is responsible for triggering
// a publish whenever the device location changes.
//
// The method ensures:
//   - No overlapping or concurrent location publishing.
//   - Throttling is respected if the LPS signals backoff via HTTP 404.
//   - Location updates are only attempted if LPS is configured and reachable.
//   - Errors and unexpected responses are collected and logged.
func (lc *LocalCmdAgent) PublishLocationToLps(locInfo *info.ZInfoLocation) {
	if paused := lc.tc.startTask(); paused {
		return
	}
	defer lc.tc.endTask()

	// Prevent concurrent calls and enforce throttling policy.
	lc.locationMx.Lock()
	defer lc.locationMx.Unlock()
	if lc.throttledLocation {
		if time.Since(lc.lastPublishedLocation) < lpsLocationThrottledInterval {
			return
		}
	}

	if lc.CtrlClient == nil {
		lc.Log.Warnf("%s: PublishLocationToLps called too early, "+
			"CtrlClient is not yet available", logPrefix)
		return
	}
	if lc.lpsURL == nil {
		// No LPS configured.
		return
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf("%s: publishLocationToLps: cannot find any configured "+
			"apps for LPS URL: %s", logPrefix, lc.lpsURL)
		return
	}

	var (
		err     error
		resp    *http.Response
		errList []string
	)
	for intf, srvAddrs := range lc.lpsAddresses.addrsByIface {
		for _, srvAddr := range srvAddrs {
			fullURL := srvAddr.destURL.String() + lpsLocationURLPath
			wasPaused := lc.tc.runInterruptible(func() {
				resp, err = lc.CtrlClient.SendLocalProto(
					fullURL, intf, srvAddr.sourceIP, locInfo, nil)
			})
			if wasPaused {
				lc.Log.Functionf("%s: publishLocationToLps: exiting early "+
					"due to task pause", logPrefix)
				return
			}
			lc.lastPublishedLocation = time.Now()
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				if resp == nil {
					continue
				}
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				lc.throttledLocation = true
				return
			case http.StatusOK, http.StatusCreated, http.StatusNoContent:
				lc.throttledLocation = false
				return
			default:
				if err == nil {
					errList = append(errList,
						fmt.Sprintf("SendLocalProto: wrong response status code: %d",
							resp.StatusCode))
				}
				continue
			}
		}
	}
	lc.Log.Errorf("%s: publishLocationToLps: all attempts failed: %s",
		logPrefix, strings.Join(errList, ";"))
	return
}
