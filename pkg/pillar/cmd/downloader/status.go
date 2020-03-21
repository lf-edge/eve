package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Status provides a struct that can be called to update download progress
type Status interface {
	Progress(uint)
}

// PublishStatus practical implementation of Status
// that knows how to update the progress to pubsub
// requires a context and status
type PublishStatus struct {
	ctx    *downloaderContext
	status *types.DownloaderStatus
}

// Progress report progress as a percentage of completeness
func (d *PublishStatus) Progress(p uint) {
	d.status.Progress = p
	publishDownloaderStatus(d.ctx, d.status)
}
