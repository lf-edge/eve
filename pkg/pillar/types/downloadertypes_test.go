// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// DownloaderStatus.HandleDownloadFail

func TestHandleDownloadFailWithRetry(t *testing.T) {
	status := DownloaderStatus{RetryCount: 2}
	status.HandleDownloadFail("download timed out", 30*time.Second, false)

	assert.True(t, status.HasError())
	assert.Equal(t, "download timed out", status.Error)
	assert.NotEmpty(t, status.ErrorRetryCondition)
}

func TestHandleDownloadFailCancelled(t *testing.T) {
	status := DownloaderStatus{RetryCount: 5}
	status.HandleDownloadFail("cancelled", 30*time.Second, true)

	assert.True(t, status.HasError())
	assert.Equal(t, "cancelled", status.Error)
	// Cancelled errors have no retry condition
	assert.Empty(t, status.ErrorRetryCondition)
}

func TestHandleDownloadFailNoRetry(t *testing.T) {
	status := DownloaderStatus{}
	status.HandleDownloadFail("fatal error", 0, false)

	assert.True(t, status.HasError())
	assert.Equal(t, "fatal error", status.Error)
	// Zero retryTime → no retry condition
	assert.Empty(t, status.ErrorRetryCondition)
}

// DownloaderConfig.Key / LogKey

func TestDownloaderConfigLogKey(t *testing.T) {
	cfg := DownloaderConfig{ImageSha256: "sha256cfg"}
	assert.Equal(t, "sha256cfg", cfg.Key())
	assert.Contains(t, cfg.LogKey(), "sha256cfg")
}

// DownloaderStatus.Key / LogKey

func TestDownloaderStatusLogKey(t *testing.T) {
	status := DownloaderStatus{ImageSha256: "sha256status"}
	assert.Equal(t, "sha256status", status.Key())
	assert.Contains(t, status.LogKey(), "sha256status")
}
