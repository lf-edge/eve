// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Functions to maintain metrics about the connectivity to zedcloud.
// Just success and failures.
// Reported as device metrics

package zedcloud

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus" // OK for logrus.Fatal
	"sync"
	"time"
)

// agentMetrics has one entry per agentName aka LogObject
// Makes it usable when multiple agents are running in the same process aka zedbox
type agentMetrics struct {
	metrics types.MetricsMap
}

type allMetricsMap map[*base.LogObject]agentMetrics

var allMetrics = make(allMetricsMap)
var mutex = &sync.Mutex{}

// getAgentIfnameMetrics assumes the caller is holding the mutex
// The caller needs to call updateAgentIfnameMetrics after any update
func getAgentIfnameMetrics(log *base.LogObject, ifname string) types.ZedcloudMetric {
	if allMetrics == nil {
		logrus.Fatal("no allMetrics")
	}
	if _, ok := allMetrics[log]; !ok {
		allMetrics[log] = agentMetrics{metrics: make(types.MetricsMap)}
	}
	metrics := allMetrics[log].metrics
	if _, ok := metrics[ifname]; !ok {
		metrics[ifname] = types.ZedcloudMetric{
			URLCounters: make(map[string]types.UrlcloudMetrics),
		}
		allMetrics[log] = agentMetrics{metrics: metrics}
	}
	return metrics[ifname]
}

func updateAgentIfnameMetrics(log *base.LogObject, ifname string, m types.ZedcloudMetric) {
	if allMetrics == nil {
		logrus.Fatal("no allMetrics")
	}
	if _, ok := allMetrics[log]; !ok {
		logrus.Fatal("allMetrics not initialized")
	}
	metrics := allMetrics[log].metrics
	metrics[ifname] = m
	allMetrics[log] = agentMetrics{metrics: metrics}
}

func ZedCloudFailure(log *base.LogObject, ifname string, url string, reqLen int64, respLen int64, authenFail bool) {
	log.Debugf("ZedCloudFailure(%s, %s) %d %d",
		ifname, url, reqLen, respLen)
	mutex.Lock()
	m := getAgentIfnameMetrics(log, ifname)
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
		m.URLCounters[url] = u
	}
	updateAgentIfnameMetrics(log, ifname, m)
	mutex.Unlock()
}

func ZedCloudSuccess(log *base.LogObject, ifname string, url string, reqLen int64, respLen int64, timeSpent int64) {
	log.Debugf("ZedCloudSuccess(%s, %s) %d %d",
		ifname, url, reqLen, respLen)
	mutex.Lock()
	m := getAgentIfnameMetrics(log, ifname)
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
	u.TotalTimeSpent += timeSpent
	m.URLCounters[url] = u
	updateAgentIfnameMetrics(log, ifname, m)
	mutex.Unlock()
}

func GetCloudMetrics(log *base.LogObject) types.MetricsMap {
	if allMetrics == nil {
		logrus.Fatal("no allMetrics")
	}
	if _, ok := allMetrics[log]; !ok {
		allMetrics[log] = agentMetrics{metrics: make(types.MetricsMap)}
	}
	return allMetrics[log].metrics
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
