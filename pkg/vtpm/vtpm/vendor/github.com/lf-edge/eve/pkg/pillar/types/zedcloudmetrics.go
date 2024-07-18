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
type MetricsMap map[string]ZedcloudMetric

// ZedcloudMetric are metrics for one interface
type ZedcloudMetric struct {
	FailureCount  uint64
	SuccessCount  uint64
	LastFailure   time.Time
	LastSuccess   time.Time
	URLCounters   map[string]UrlcloudMetrics
	AuthFailCount uint64
}

// UrlcloudMetrics are metrics for a particular URL
type UrlcloudMetrics struct {
	TryMsgCount    int64
	TryByteCount   int64
	SentMsgCount   int64
	SentByteCount  int64
	RecvMsgCount   int64
	RecvByteCount  int64 // Based on content-length which could be off
	TotalTimeSpent int64
	SessionResume  int64
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
			dst = ZedcloudMetric{}
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
		if dst.URLCounters == nil {
			dst.URLCounters = make(map[string]UrlcloudMetrics)
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
			dstURLs[url] = dstURL
		}
		toMap[ifname] = dst
	}
}
