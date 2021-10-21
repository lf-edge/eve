// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// AgentMetrics is used to maintain metrics about the connectivity to zedcloud.
// Just success and failures.
// Reported as device metrics.

package zedcloud

import (
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// AgentMetrics stores zedcloud related metrics for one agent (microservice).
// Able to properly handle concurrent access.
type AgentMetrics struct {
	sync.Mutex
	metrics types.MetricsMap
}

// NewAgentMetrics creates instance of AgentMetrics.
func NewAgentMetrics() *AgentMetrics {
	return &AgentMetrics{
		metrics: make(types.MetricsMap),
	}
}

func (am *AgentMetrics) acquire(log *base.LogObject) (release func()) {
	if am == nil {
		log.Fatal("undefined AgentMetrics")
	}
	am.Lock()
	return func() { am.Unlock() }
}

// getInterfaceMetrics is an internal function returning metrics corresponding
// to a given interface. It assumes that the caller has acquired metrics using AgentMetrics.acquire().
func (am *AgentMetrics) getInterfaceMetrics(ifname string) types.ZedcloudMetric {
	if _, ok := am.metrics[ifname]; !ok {
		am.metrics[ifname] = types.ZedcloudMetric{
			URLCounters: make(map[string]types.UrlcloudMetrics),
		}
	}
	return am.metrics[ifname]
}

// RecordFailure records failed zedcloud API request.
func (am *AgentMetrics) RecordFailure(log *base.LogObject, ifname, url string, reqLen, respLen int64, authenFail bool) {
	release := am.acquire(log)
	defer release()
	log.Tracef("RecordFailure(%s, %s, %d, %d, %t)",
		ifname, url, reqLen, respLen, authenFail)
	m := am.getInterfaceMetrics(ifname)

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
	am.metrics[ifname] = m
}

// RecordSuccess records successful zedcloud API request.
func (am *AgentMetrics) RecordSuccess(log *base.LogObject, ifname, url string, reqLen, respLen, timeSpent int64, resume bool) {
	release := am.acquire(log)
	defer release()
	log.Tracef("RecordSuccess(%s, %s, %d, %d, %d, %t)",
		ifname, url, reqLen, respLen, timeSpent, resume)
	m := am.getInterfaceMetrics(ifname)

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
	if resume {
		u.SessionResume++
	}
	m.URLCounters[url] = u
	am.metrics[ifname] = m
}

// Publish the recorded metrics through the given publisher.
func (am *AgentMetrics) Publish(log *base.LogObject, publication pubsub.Publication, key string) error {
	release := am.acquire(log)
	defer release()
	return publication.Publish(key, am.metrics)
}

// GetURLsWithSubstr returns URLs containing the given substring.
func (am *AgentMetrics) GetURLsWithSubstr(log *base.LogObject, substr string) (set []string) {
	release := am.acquire(log)
	defer release()
	for _, cm := range am.metrics {
		for k := range cm.URLCounters {
			if strings.Contains(k, substr) {
				set = append(set, k)
			}
		}
	}
	return getUniqueValues(set)
}

// RemoveURLMetrics removes all metrics recorded for the given URL.
func (am *AgentMetrics) RemoveURLMetrics(log *base.LogObject, url string) {
	release := am.acquire(log)
	defer release()
	for intf, m := range am.metrics {
		if _, ok := m.URLCounters[url]; ok {
			delete(m.URLCounters, url)
			log.Tracef("RemoveURLMetrics: on interface %s deleted metrics for url %s", intf, url)
			continue
		}
	}
}

// AddInto adds metrics from this instance of AgentMetrics
// into the metrics map referenced by toMap.
func (am *AgentMetrics) AddInto(log *base.LogObject, toMap types.MetricsMap) {
	release := am.acquire(log)
	defer release()
	am.metrics.AddInto(toMap)
}

func getUniqueValues(inSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range inSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
