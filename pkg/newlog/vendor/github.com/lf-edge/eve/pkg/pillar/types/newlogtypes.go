// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"
)

type logfileMetrics struct {
	// from newlogd
	NumEventsWrite    uint64 // total log evert, device
	NumGZipFilesSent  uint64 // total gzip files uploaded, device
	NumGZipBytesWrite uint64 // total gzip log in bytes, device
	NumBytesWrite     uint64 // total log bytes write to file before gzip, device
	NumEventErrors    uint64 // total log event can not process, device
	NumGzipFileInDir  uint32 // current number of gzip files remain, device

	// from loguploader
	NumGZipFileRetry     uint64    // total gzip file upload retries, device
	LastGZipFileSendTime time.Time // last upload gzip file time, device
}

// NewlogMetrics - Metrics from newlogd and loguploader
type NewlogMetrics struct {
	// from loguploader
	TotalBytesUpload   uint64 // total number of bytes uploaded to cloud
	Num4xxResponses    uint32 // total 4xx response received
	MinDelayUploadMsec uint32 // min upload to cloud delay in msec
	MaxDelayUploadMsec uint32 // max upload to cloud delay in msec
	AvgDelayUploadMsec uint32 // avg upload to cloud delay in msec
	// from newlogd
	NumBreakGZipFile uint32 // total number of gzip file too large needs breakup

	// Dev and App file metrics
	DevMetrics logfileMetrics // Device metrics
	AppMetrics logfileMetrics // App metrics
}
