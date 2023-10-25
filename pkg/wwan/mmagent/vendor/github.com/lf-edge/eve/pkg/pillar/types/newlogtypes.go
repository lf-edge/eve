// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"
)

const (
	// DevPrefix - device log file prefix string
	DevPrefix = "dev.log."
	// AppPrefix - app log file prefix string
	AppPrefix = "app."
	// AppSuffix - app log file suffix string, the appuuid is between the AppPrefix and AppSuffix
	AppSuffix = ".log."
)

type logfileMetrics struct {
	// from newlogd
	NumGZipFilesSent  uint64 // total gzip files uploaded
	NumGZipBytesWrite uint64 // total gzip log in bytes
	NumBytesWrite     uint64 // total log bytes write to file before gzip
	NumGzipFileInDir  uint32 // current number of gzip files remain
	NumInputEvent     uint64 // total event input from log source
	// from loguploader
	NumGZipFileRetry      uint64    // total gzip file upload retries
	NumGZipFileKeptLocal  uint32    // total gzip file upload 4xx failure and kept on device
	RecentUploadTimestamp time.Time // uploaded to cloud the most recent log timestamp
	LastGZipFileSendTime  time.Time // last upload gzip file time
}

type serverStats struct {
	CurrCPULoadPCT  float32 // newlog server CPU percentage usage
	AvgCPULoadPCT   float32 // newlog server CPU average load percentage
	CurrProcessMsec uint32  // newlog server process log duration in msec
	AvgProcessMsec  uint32  // newlog server avg process log duration in msec
}

type cloudDelay struct {
	MinUploadMsec  uint32 // min upload to cloud delay in msec
	MaxUploadMsec  uint32 // max upload to cloud delay in msec
	AvgUploadMsec  uint32 // avg upload to cloud delay in msec
	CurrUploadMsec uint32 // current upload to cloud delay in msec
}

// NewlogMetrics - Metrics from newlogd and loguploader
type NewlogMetrics struct {
	// logupload signal to newlogd
	FailedToSend       bool      // loguploader failed to send to cloud
	FailSentStartTime  time.Time // failed to send start time
	LastTooManyReqTime time.Time // last response of status 429
	// from loguploader
	TotalBytesUpload  uint64 // total number of bytes uploaded to cloud
	Num4xxResponses   uint32 // total 4xx response received
	NumTooManyRequest uint32 // total 429 response received
	CurrUploadIntvSec uint32 // current upload interval in second
	LogfileTimeoutSec uint32 // logfile delay time in second
	MaxGzipSize       uint32 // largest gzip file size created
	AvgGzipSize       uint32 // average gzip file size
	// from newlogd
	NumGZipFileRemoved    uint32            // number of gzip file removed due to exceeding quota
	NumBreakGZipFile      uint32            // total number of gzip file too large needs breakup
	NumSkipUploadAppFile  uint32            // total number of gzip app file skipped upload
	NumKmessages          uint64            // total input kmessages
	NumSyslogMessages     uint64            // total input syslog message
	DevTop10InputBytesPCT map[string]uint32 // top 10 sources device log input in percentage

	// upload latency
	Latency cloudDelay
	// server side
	ServerStats serverStats

	// Dev and App file metrics
	DevMetrics logfileMetrics // Device metrics
	AppMetrics logfileMetrics // App metrics
}
