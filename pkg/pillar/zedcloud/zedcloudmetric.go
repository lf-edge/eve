// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Functions to maintain metrics about the connectivity to zedcloud.
// Just success and failures.
// Reported as device metrics

package zedcloud

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

var metrics = make(types.MetricsMap)
var mutex = &sync.Mutex{}

func maybeInit(ifname string) {
	if metrics == nil {
		log.Fatal("no zedcloudmetric map\n")
	}
	if _, ok := metrics[ifname]; !ok {
		log.Debugf("create zedcloudmetric for %s\n", ifname)
		metrics[ifname] = types.ZedcloudMetric{
			URLCounters: make(map[string]types.UrlcloudMetrics),
		}
	}
}

func ZedCloudFailure(ifname string, url string, reqLen int64, respLen int64, authenFail bool) {
	mutex.Lock()
	maybeInit(ifname)
	m := metrics[ifname]
	// if we have authen verify failure, the network part is success
	if authenFail {
		m.AuthFailCount++
	} else {
		m.FailureCount++
		m.LastFailure = time.Now()

		var u types.UrlcloudMetrics
		var ok bool
		if u, ok = m.URLCounters[url]; !ok {
			u = types.UrlcloudMetrics{}
		}
		u.TryMsgCount++
		u.TryByteCount += reqLen
		if respLen != 0 {
			u.RecvMsgCount++
			u.RecvByteCount += respLen
		}
		u.LastUse = time.Now()
		m.URLCounters[url] = u
	}
	metrics[ifname] = m
	mutex.Unlock()
}

func ZedCloudSuccess(ifname string, url string, reqLen int64, respLen int64) {
	mutex.Lock()
	maybeInit(ifname)
	m := metrics[ifname]
	m.SuccessCount += 1
	m.LastSuccess = time.Now()
	var u types.UrlcloudMetrics
	var ok bool
	if u, ok = m.URLCounters[url]; !ok {
		u = types.UrlcloudMetrics{}
	}
	u.SentMsgCount += 1
	u.SentByteCount += reqLen
	u.RecvMsgCount += 1
	u.RecvByteCount += respLen
	u.LastUse = time.Now()
	m.URLCounters[url] = u
	metrics[ifname] = m
	mutex.Unlock()
}

func GetCloudMetrics() types.MetricsMap {
	return metrics
}

// SetCloudMetrics is used on agent startups e.g., to preserve
// the metrics from a previous run of the agent/device
func SetCloudMetrics(m types.MetricsMap) {
	metrics = m
}

// Concatenate different interfaces and URLs into a union map
func Append(cms types.MetricsMap, cms1 types.MetricsMap) types.MetricsMap {
	for ifname, cm1 := range cms1 {
		cm, ok := cms[ifname]
		if !ok {
			// New ifname; take all
			cms[ifname] = cm
			continue
		}
		if cm.LastFailure.IsZero() {
			// Don't care if cm1 is zero
			cm.LastFailure = cm1.LastFailure
		} else if !cm1.LastFailure.IsZero() &&
			cm1.LastFailure.Sub(cm.LastFailure) > 0 {
			cm.LastFailure = cm1.LastFailure
		}
		if cm.LastSuccess.IsZero() {
			// Don't care if cm1 is zero
			cm.LastSuccess = cm1.LastSuccess
		} else if !cm1.LastSuccess.IsZero() &&
			cm1.LastSuccess.Sub(cm.LastSuccess) > 0 {
			cm.LastSuccess = cm1.LastSuccess
		}
		cm.FailureCount += cm1.FailureCount
		cm.SuccessCount += cm1.SuccessCount
		cm.AuthFailCount += cm1.AuthFailCount
		if cm.URLCounters == nil {
			cm.URLCounters = make(map[string]types.UrlcloudMetrics)
		}
		cmu := cm.URLCounters // A pointer to the map
		for url, um1 := range cm1.URLCounters {
			um, ok := cmu[url]
			if !ok {
				// New url; take all
				cmu[url] = um1
				continue
			}
			um.TryMsgCount += um1.TryMsgCount
			um.TryMsgCount += um1.TryMsgCount
			um.TryByteCount += um1.TryByteCount
			um.SentMsgCount += um1.SentMsgCount
			um.SentByteCount += um1.SentByteCount
			um.RecvMsgCount += um1.RecvMsgCount
			um.RecvByteCount += um1.RecvByteCount
			cmu[url] = um
		}
		cms[ifname] = cm
	}
	return cms
}
