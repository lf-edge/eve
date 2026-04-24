// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// MetricsMap.AddInto

func TestMetricsMapAddInto(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Minute)

	src := MetricsMap{
		"eth0": ControllerConnMetrics{
			FailureCount: 2,
			SuccessCount: 5,
			LastFailure:  now,
			LastSuccess:  now,
			URLCounters: map[string]URLMetrics{
				"/v1/config": {TryMsgCount: 3, SentMsgCount: 3},
			},
		},
	}

	dst := MetricsMap{
		"eth0": ControllerConnMetrics{
			FailureCount: 1,
			SuccessCount: 2,
			LastFailure:  earlier,
			LastSuccess:  earlier,
		},
	}

	src.AddInto(dst)

	got := dst["eth0"]
	assert.Equal(t, uint64(3), got.FailureCount)
	assert.Equal(t, uint64(7), got.SuccessCount)
	// LastFailure should be updated to the more recent value
	assert.Equal(t, now, got.LastFailure)
	assert.Equal(t, now, got.LastSuccess)
	// URL counters merged
	assert.Equal(t, int64(3), got.URLCounters["/v1/config"].TryMsgCount)
}

func TestMetricsMapAddIntoNilSource(t *testing.T) {
	// Nil source → no-op
	var src MetricsMap
	dst := MetricsMap{"eth0": {FailureCount: 1}}
	src.AddInto(dst)
	assert.Equal(t, uint64(1), dst["eth0"].FailureCount)
}

func TestMetricsMapAddIntoNewIfname(t *testing.T) {
	src := MetricsMap{
		"eth1": ControllerConnMetrics{SuccessCount: 10},
	}
	dst := MetricsMap{}
	src.AddInto(dst)
	assert.Equal(t, uint64(10), dst["eth1"].SuccessCount)
}

// AddInto — dst timestamp newer than src (else-if false path)

func TestMetricsMapAddIntoDstNewerTimestamp(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Minute)

	src := MetricsMap{
		"eth0": ControllerConnMetrics{
			LastFailure: older,
			LastSuccess: older,
		},
	}
	dst := MetricsMap{
		"eth0": ControllerConnMetrics{
			LastFailure: now,
			LastSuccess: now,
		},
	}

	src.AddInto(dst)

	got := dst["eth0"]
	// dst timestamps should be preserved (src is older)
	assert.Equal(t, now, got.LastFailure)
	assert.Equal(t, now, got.LastSuccess)
}

// AddInto — URL already in dst map (merge path)

func TestMetricsMapAddIntoURLMerge(t *testing.T) {
	src := MetricsMap{
		"eth0": ControllerConnMetrics{
			URLCounters: map[string]URLMetrics{
				"/v1/config": {TryMsgCount: 5, SentMsgCount: 3, SessionResume: 1},
			},
		},
	}
	dst := MetricsMap{
		"eth0": ControllerConnMetrics{
			URLCounters: map[string]URLMetrics{
				"/v1/config": {TryMsgCount: 2, SentMsgCount: 1},
			},
		},
	}

	src.AddInto(dst)

	got := dst["eth0"].URLCounters["/v1/config"]
	assert.Equal(t, int64(7), got.TryMsgCount)
	assert.Equal(t, int64(4), got.SentMsgCount)
	assert.Equal(t, int64(1), got.SessionResume)
}
