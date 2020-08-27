// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"
)

// LogMetrics Metrics from logmanager
type LogMetrics struct {
	NumDeviceEventsSent           uint64
	NumDeviceBundlesSent          uint64
	NumDeviceBundleProtoBytesSent uint64
	NumAppBundleProtoBytesSent    uint64
	NumAppEventsSent              uint64
	NumAppBundlesSent             uint64
	Num4xxResponses               uint64
	NumAppEventErrors             uint64
	NumDeviceEventErrors          uint64
	LastDeviceBundleSendTime      time.Time
	LastAppBundleSendTime         time.Time

	IsLogProcessingDeferred bool
	NumTimesDeferred        uint64
	LastLogDeferTime        time.Time

	TotalDeviceLogInput uint64
	TotalAppLogInput    uint64
	DeviceLogInput      map[string]uint64 // map from source
}
