// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// DownloaderStatus is the progress of an in-flight image/content download.
type DownloaderStatus struct {
	Name        string `json:"name"`
	State       string `json:"state"` // human-readable download state
	ContentType string `json:"contentType"`
	// Progress is the completion percentage, 0-100.
	Progress    uint32 `json:"progress"`
	CurrentSize int64  `json:"currentSize"`
	TotalSize   int64  `json:"totalSize"`
	// Error is the last download error, empty if none.
	Error string `json:"error"`
}
