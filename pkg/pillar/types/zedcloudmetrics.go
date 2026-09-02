// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"
)

// MetricsMap maps from an ifname string to some metrics
// Note that there are no LogCreate etc functions for this type
// since it is published by logmanager and we don't want to cause logs
// when logging
type MetricsMap map[string]ControllerConnMetrics

// MaxURLCounters limits URLMetrics entries per MetricsMap (combined across
// interfaces): agents like downloader/mgmtproxy can otherwise grow
// URLCounters without bound and exceed the pubsub message size limit.
// The actual count may transiently exceed this; see AgentMetrics.
//
// The cap counts entries, but what it defends is a byte budget: pubsub
// base64-encodes the serialized value before measuring it against its 64KB
// socket message limit, which leaves about 48KB for the JSON. Eviction also
// runs in batches once the cap is passed, so the peak is
// MaxURLCounters+urlCountersWiggle (115 entries today), not MaxURLCounters.
// A long URL key can cost more than all the counters stored under it, so
// counters which stay zero for the agents that reach the cap are omitted from
// the encoding rather than written out as zeroes.
const MaxURLCounters = 100

// ControllerConnMetrics holds communication statistics with the controller
// for a single interface.
// It tracks successes, failures, authentication failures, and per-URL metrics.
type ControllerConnMetrics struct {
	FailureCount  uint64
	SuccessCount  uint64
	LastFailure   time.Time
	LastSuccess   time.Time
	URLCounters   map[string]URLMetrics
	AuthFailCount uint64
	// URLCounterRedactedCount counts URLMetrics entries evicted to stay
	// within MaxURLCounters.
	URLCounterRedactedCount uint64
}

// URLMetrics are metrics for a particular URL
type URLMetrics struct {
	TryMsgCount    int64
	TryByteCount   int64
	SentMsgCount   int64
	SentByteCount  int64
	RecvMsgCount   int64
	RecvByteCount  int64 // Based on content-length which could be off
	TotalTimeSpent int64
	SessionResume  int64
	// DeliveredMsgCount counts the answers which accepted the payload. It is
	// narrower than SentMsgCount, which counts every answer received.
	DeliveredMsgCount int64 `json:",omitempty"`
	// RetriableErrCount counts the answers which refused the payload with a
	// status that may not repeat, so that offering it again is worthwhile.
	RetriableErrCount int64 `json:",omitempty"`
	// RejectedErrCount counts the answers which refused the payload itself,
	// so that offering it again would be answered the same way.
	RejectedErrCount int64 `json:",omitempty"`
	// LastUpdated determines which entries to evict once MaxURLCounters
	// is reached.
	LastUpdated time.Time
}

// AddInto adds metrics from this instance of MetricsMap
// into the metrics map referenced by toMap.
func (m MetricsMap) AddInto(toMap MetricsMap) {
	if m == nil {
		return
	}
	for ifname, src := range m {
		dst, ok := toMap[ifname]
		if !ok {
			// New ifname; take all but need to deepcopy
			dst = ControllerConnMetrics{}
		}
		if dst.LastFailure.IsZero() {
			// Don't care if src is zero
			dst.LastFailure = src.LastFailure
		} else if !src.LastFailure.IsZero() &&
			src.LastFailure.Sub(dst.LastFailure) > 0 {
			dst.LastFailure = src.LastFailure
		}
		if dst.LastSuccess.IsZero() {
			// Don't care if src is zero
			dst.LastSuccess = src.LastSuccess
		} else if !src.LastSuccess.IsZero() &&
			src.LastSuccess.Sub(dst.LastSuccess) > 0 {
			dst.LastSuccess = src.LastSuccess
		}
		dst.FailureCount += src.FailureCount
		dst.SuccessCount += src.SuccessCount
		dst.AuthFailCount += src.AuthFailCount
		dst.URLCounterRedactedCount += src.URLCounterRedactedCount
		if dst.URLCounters == nil {
			dst.URLCounters = make(map[string]URLMetrics)
		}
		dstURLs := dst.URLCounters // A pointer to the map
		for url, srcURL := range src.URLCounters {
			dstURL, ok := dstURLs[url]
			if !ok {
				// New url; take all
				dstURLs[url] = srcURL
				continue
			}
			dstURL.TryMsgCount += srcURL.TryMsgCount
			dstURL.TryByteCount += srcURL.TryByteCount
			dstURL.SentMsgCount += srcURL.SentMsgCount
			dstURL.SentByteCount += srcURL.SentByteCount
			dstURL.RecvMsgCount += srcURL.RecvMsgCount
			dstURL.RecvByteCount += srcURL.RecvByteCount
			dstURL.TotalTimeSpent += srcURL.TotalTimeSpent
			dstURL.SessionResume += srcURL.SessionResume
			dstURL.DeliveredMsgCount += srcURL.DeliveredMsgCount
			dstURL.RetriableErrCount += srcURL.RetriableErrCount
			dstURL.RejectedErrCount += srcURL.RejectedErrCount
			if srcURL.LastUpdated.After(dstURL.LastUpdated) {
				dstURL.LastUpdated = srcURL.LastUpdated
			}
			dstURLs[url] = dstURL
		}
		toMap[ifname] = dst
	}
}
