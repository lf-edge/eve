// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// AgentMetrics is used to maintain metrics about the connectivity to the controller.
// Just successes and failures.
// Reported as device metrics.

package controllerconn

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// urlCountersWiggle is headroom above types.MaxURLCounters: once the total
// reaches MaxURLCounters+urlCountersWiggle, that many oldest entries are
// evicted at once, amortizing the eviction scan across several new URLs.
const urlCountersWiggle = 15

// AgentMetrics stores controller related metrics for one agent (microservice).
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
// to a given interface. It assumes that the caller has acquired metrics using
// AgentMetrics.acquire().
func (am *AgentMetrics) getInterfaceMetrics(ifname string) types.ControllerConnMetrics {
	if _, ok := am.metrics[ifname]; !ok {
		am.metrics[ifname] = types.ControllerConnMetrics{
			URLCounters: make(map[string]types.URLMetrics),
		}
	}
	return am.metrics[ifname]
}

// RecordFailure records failed controller API request.
func (am *AgentMetrics) RecordFailure(log *base.LogObject, ifname, url string,
	reqLen, respLen int64, authenFail bool) {
	release := am.acquire(log)
	defer release()
	log.Tracef("RecordFailure(%s, %s, %d, %d, %t)",
		ifname, url, reqLen, respLen, authenFail)

	// if we have authen verify failure, the network part is success
	if authenFail {
		m := am.getInterfaceMetrics(ifname)
		m.AuthFailCount++
		am.metrics[ifname] = m
		return
	}

	if _, ok := am.getInterfaceMetrics(ifname).URLCounters[url]; !ok {
		// Re-fetch below: eviction may update this ifname's entry too.
		am.makeRoomForNewURL(log)
	}
	m := am.getInterfaceMetrics(ifname)
	m.FailureCount++
	m.LastFailure = time.Now()
	u := m.URLCounters[url]
	u.TryMsgCount++
	u.TryByteCount += reqLen
	if respLen != 0 {
		u.RecvMsgCount++
		u.RecvByteCount += respLen
	}
	u.LastUpdated = time.Now()
	m.URLCounters[url] = u
	am.metrics[ifname] = m
}

// RecordSuccess records successful controller API request.
func (am *AgentMetrics) RecordSuccess(log *base.LogObject, ifname, url string,
	reqLen, respLen, timeSpent int64, resume bool) {
	release := am.acquire(log)
	defer release()
	log.Tracef("RecordSuccess(%s, %s, %d, %d, %d, %t)",
		ifname, url, reqLen, respLen, timeSpent, resume)

	if _, ok := am.getInterfaceMetrics(ifname).URLCounters[url]; !ok {
		// Re-fetch below: eviction may update this ifname's entry too.
		am.makeRoomForNewURL(log)
	}
	m := am.getInterfaceMetrics(ifname)
	m.SuccessCount++
	m.LastSuccess = time.Now()
	u := m.URLCounters[url]
	u.SentMsgCount++
	u.SentByteCount += reqLen
	u.RecvMsgCount++
	u.RecvByteCount += respLen
	u.TotalTimeSpent += timeSpent
	if resume {
		u.SessionResume++
	}
	u.LastUpdated = time.Now()
	m.URLCounters[url] = u
	am.metrics[ifname] = m
}

// deliveredHTTPStatus tells whether an answer with this status code accepted
// the payload. It is the set of status codes the send paths treat as success.
func deliveredHTTPStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNotModified,
		http.StatusNoContent:
		return true
	}
	return false
}

// RecordAnswer records what the controller's answer said about the payload:
// accepted, refused with a status which may not repeat, or rejected outright.
// The refusal classification is the one the deferred queue retries on, so the
// counters explain what became of the message.
//
// This complements RecordSuccess and RecordFailure, which count whether the
// controller was reached at all - an answered request is a success there even
// when the answer is a 404. Call it for a url one of those was called for, so
// that the entry is already accounted for against MaxURLCounters.
func (am *AgentMetrics) RecordAnswer(log *base.LogObject, ifname, url string,
	statusCode int) {
	release := am.acquire(log)
	defer release()

	m := am.getInterfaceMetrics(ifname)
	u := m.URLCounters[url]
	switch {
	case deliveredHTTPStatus(statusCode):
		u.DeliveredMsgCount++
	case statusCode < 400 || statusCode >= 600:
		// Neither an acceptance nor a refusal of the payload.
		return
	case retriableHTTPStatus(statusCode):
		u.RetriableErrCount++
	default:
		u.RejectedErrCount++
	}
	u.LastUpdated = time.Now()
	m.URLCounters[url] = u
	am.metrics[ifname] = m
}

// makeRoomForNewURL evicts urlCountersWiggle least recently used
// URLMetrics entries, combined across all interfaces, once the high
// watermark is reached. Caller must hold the AgentMetrics lock.
func (am *AgentMetrics) makeRoomForNewURL(log *base.LogObject) {
	var total int
	for _, m := range am.metrics {
		total += len(m.URLCounters)
	}
	if total < types.MaxURLCounters+urlCountersWiggle {
		return
	}

	type urlEntry struct {
		ifname, url string
		lastUpdated time.Time
	}
	entries := make([]urlEntry, 0, total)
	for ifname, m := range am.metrics {
		for url, u := range m.URLCounters {
			entries = append(entries, urlEntry{ifname, url, u.LastUpdated})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastUpdated.Before(entries[j].lastUpdated)
	})

	for _, e := range entries[:urlCountersWiggle] {
		m := am.metrics[e.ifname]
		delete(m.URLCounters, e.url)
		m.URLCounterRedactedCount++
		am.metrics[e.ifname] = m
	}
	log.Warnf("AgentMetrics: URLCounters limit of %d reached; "+
		"evicted %d least recently used entries",
		types.MaxURLCounters, urlCountersWiggle)
}

// Publish the recorded metrics through the given publisher.
func (am *AgentMetrics) Publish(
	log *base.LogObject, publication pubsub.Publication, key string) error {
	release := am.acquire(log)
	defer release()
	return publication.Publish(key, am.metrics)
}

// GetURLsWithSubstr returns URLs containing the given substring.
func (am *AgentMetrics) GetURLsWithSubstr(
	log *base.LogObject, substr string) (set []string) {
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
			log.Tracef("RemoveURLMetrics: on interface %s deleted metrics for url %s",
				intf, url)
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
