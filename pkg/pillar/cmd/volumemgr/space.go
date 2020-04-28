package volumemgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func initSpace(ctx *volumemgrContext, kb uint64) {
	ctx.globalDownloadStatusLock.Lock()
	ctx.globalDownloadStatus.UsedSpace = 0
	ctx.globalDownloadStatus.ReservedSpace = 0
	updateRemainingSpace(ctx)

	ctx.globalDownloadStatus.UsedSpace = kb
	// Note that the UsedSpace calculated during initialization can
	// exceed MaxSpace, and RemainingSpace is a uint!
	if ctx.globalDownloadStatus.UsedSpace > ctx.globalDownloadConfig.MaxSpace {
		ctx.globalDownloadStatus.UsedSpace = ctx.globalDownloadConfig.MaxSpace
	}
	updateRemainingSpace(ctx)
	ctx.globalDownloadStatusLock.Unlock()

	publishGlobalDownloadStatus(ctx)
}

func publishGlobalDownloadStatus(ctx *volumemgrContext) {
	ctx.pubGlobalDownloadStatus.Publish("global", ctx.globalDownloadStatus)
}

// Returns true if there was space
func tryReserveSpace(ctx *volumemgrContext, status *types.VolumeStatus,
	kb uint64, name string) (bool, string) {
	errStr := ""
	if status.ReservedSpace != 0 {
		log.Errorf("%s, space is already reserved", name)
		return true, errStr
	}

	ctx.globalDownloadStatusLock.Lock()
	if kb >= ctx.globalDownloadStatus.RemainingSpace {
		ctx.globalDownloadStatusLock.Unlock()
		errStr = fmt.Sprintf("Would exceed remaining space. ObjectSize: %d, RemainingSpace: %d\n",
			kb, ctx.globalDownloadStatus.RemainingSpace)
		return false, errStr
	}
	ctx.globalDownloadStatus.ReservedSpace += kb
	updateRemainingSpace(ctx)
	ctx.globalDownloadStatusLock.Unlock()

	publishGlobalDownloadStatus(ctx)
	status.ReservedSpace = kb
	return true, errStr
}

func unreserveSpace(ctx *volumemgrContext, status *types.VolumeStatus, name string) {
	if status.ReservedSpace == 0 {
		log.Errorf("%s, reserved space is already freed", name)
		return
	}
	ctx.globalDownloadStatusLock.Lock()
	ctx.globalDownloadStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	updateRemainingSpace(ctx)
	ctx.globalDownloadStatusLock.Unlock()

	publishGlobalDownloadStatus(ctx)
}

// convert reserved storage to used storage
func allocateSpace(ctx *volumemgrContext, status *types.VolumeStatus,
	size uint64, name string) {
	if status.Size != 0 {
		log.Errorf("%s, request for duplicate storage allocation", name)
		return
	}
	kb := types.RoundupToKB(size)
	ctx.globalDownloadStatusLock.Lock()
	ctx.globalDownloadStatus.ReservedSpace -= status.ReservedSpace
	ctx.globalDownloadStatus.UsedSpace += kb
	updateRemainingSpace(ctx)
	ctx.globalDownloadStatusLock.Unlock()
	status.ReservedSpace = 0
	status.Size = size
	publishGlobalDownloadStatus(ctx)
}

func deleteSpace(ctx *volumemgrContext, status *types.VolumeStatus, name string) {
	if status.Size == 0 {
		log.Errorf("%s, storage is already freed", name)
		return
	}
	kb := types.RoundupToKB(status.Size)
	ctx.globalDownloadStatusLock.Lock()
	ctx.globalDownloadStatus.UsedSpace -= kb
	updateRemainingSpace(ctx)
	ctx.globalDownloadStatusLock.Unlock()
	status.Size = 0
	publishGlobalDownloadStatus(ctx)
}

// Caller must hold ctx.globalDownloadStatusLock.Lock() but no way to assert in go
func updateRemainingSpace(ctx *volumemgrContext) {

	ctx.globalDownloadStatus.RemainingSpace = ctx.globalDownloadConfig.MaxSpace -
		ctx.globalDownloadStatus.UsedSpace - ctx.globalDownloadStatus.ReservedSpace

	log.Infof("RemainingSpace %d, maxspace %d, usedspace %d, reserved %d",
		ctx.globalDownloadStatus.RemainingSpace, ctx.globalDownloadConfig.MaxSpace,
		ctx.globalDownloadStatus.UsedSpace, ctx.globalDownloadStatus.ReservedSpace)
}
