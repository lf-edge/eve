// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Status provides a struct that can be called to update download progress
type Status interface {
	Progress(uint, int64, int64)
}

// PublishStatus practical implementation of Status
// that knows how to update the progress to pubsub
// requires a context and status
type PublishStatus struct {
	ctx    *downloaderContext
	status *types.DownloaderStatus
}

// Progress report progress as a percentage of completeness
func (d *PublishStatus) Progress(p uint, currentSize, totalSize int64) {
	d.status.Progress = p
	d.status.CurrentSize = currentSize
	d.status.TotalSize = totalSize
	publishDownloaderStatus(d.ctx, d.status)
}
