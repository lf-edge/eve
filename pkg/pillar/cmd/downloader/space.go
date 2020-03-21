package downloader

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func initSpace(ctx *downloaderContext, kb uint64) {
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.UsedSpace = 0
	ctx.globalStatus.ReservedSpace = 0
	updateRemainingSpace(ctx)

	ctx.globalStatus.UsedSpace = kb
	// Note that the UsedSpace calculated during initialization can
	// exceed MaxSpace, and RemainingSpace is a uint!
	if ctx.globalStatus.UsedSpace > ctx.globalConfig.MaxSpace {
		ctx.globalStatus.UsedSpace = ctx.globalConfig.MaxSpace
	}
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
}

// Returns true if there was space
func tryReserveSpace(ctx *downloaderContext, status *types.DownloaderStatus,
	kb uint64) (bool, string) {
	errStr := ""
	if status.ReservedSpace != 0 {
		log.Errorf("%s, space is already reserved\n", status.Name)
		return true, errStr
	}

	ctx.globalStatusLock.Lock()
	if kb >= ctx.globalStatus.RemainingSpace {
		ctx.globalStatusLock.Unlock()
		errStr = fmt.Sprintf("Would exceed remaining space. ObjectSize: %d, RemainingSpace: %d\n",
			kb, ctx.globalStatus.RemainingSpace)
		return false, errStr
	}
	ctx.globalStatus.ReservedSpace += kb
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
	status.ReservedSpace = kb
	return true, errStr
}

func unreserveSpace(ctx *downloaderContext, status *types.DownloaderStatus) {
	if status.ReservedSpace == 0 {
		log.Errorf("%s, reserved space is already freed\n", status.Name)
		return
	}
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
}

// convert reserved storage to used storage
func allocateSpace(ctx *downloaderContext, status *types.DownloaderStatus,
	size uint64) {
	if status.Size != 0 {
		log.Errorf("%s, request for duplicate storage allocation\n", status.Name)
		return
	}
	kb := types.RoundupToKB(size)
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.ReservedSpace -= status.ReservedSpace
	ctx.globalStatus.UsedSpace += kb
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()
	status.ReservedSpace = 0
	status.Size = size
	publishGlobalStatus(ctx)
}

func deleteSpace(ctx *downloaderContext, status *types.DownloaderStatus) {
	if status.Size == 0 {
		log.Errorf("%s, storage is already freed\n", status.Name)
		return
	}
	kb := types.RoundupToKB(status.Size)
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.UsedSpace -= kb
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()
	status.Size = 0
	publishGlobalStatus(ctx)
}

// Caller must hold ctx.globalStatusLock.Lock() but no way to assert in go
func updateRemainingSpace(ctx *downloaderContext) {

	ctx.globalStatus.RemainingSpace = ctx.globalConfig.MaxSpace -
		ctx.globalStatus.UsedSpace - ctx.globalStatus.ReservedSpace

	log.Infof("RemainingSpace %d, maxspace %d, usedspace %d, reserved %d\n",
		ctx.globalStatus.RemainingSpace, ctx.globalConfig.MaxSpace,
		ctx.globalStatus.UsedSpace, ctx.globalStatus.ReservedSpace)
}
