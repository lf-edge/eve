// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Status provides a struct that can be called to update download progress
type Status interface {
	// Progress report progress; returns false if no change
	Progress(uint, int64, int64) bool
}

// PublishStatus practical implementation of Status
// that knows how to update the progress to pubsub
// requires a context and status
type PublishStatus struct {
	ctx    *downloaderContext
	status *types.DownloaderStatus
}

// Progress report progress as a percentage of completeness
// Returns true if there was a change to the recorded values
func (d *PublishStatus) Progress(p uint, currentSize, totalSize int64) bool {
	if d.status.Progress == p && d.status.CurrentSize == currentSize &&
		d.status.TotalSize == totalSize {
		return false
	}
	d.status.Progress = p
	d.status.CurrentSize = currentSize
	if (d.status.TotalSize == 0) && (d.status.TotalSize != totalSize) {
		log.Warnf("Progress: TotalSize changed from %d to %d", d.status.TotalSize, totalSize)
	}
	d.status.TotalSize = totalSize
	publishDownloaderStatus(d.ctx, d.status)
	return true
}
