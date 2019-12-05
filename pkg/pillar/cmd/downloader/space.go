package downloader

import (
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
	kb uint64) bool {

	ctx.globalStatusLock.Lock()
	if kb >= ctx.globalStatus.RemainingSpace {
		ctx.globalStatusLock.Unlock()
		return false
	}
	ctx.globalStatus.ReservedSpace += kb
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
	status.ReservedSpace = kb
	return true
}

func unreserveSpace(ctx *downloaderContext, status *types.DownloaderStatus) {
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	ctx.globalStatus.UsedSpace += types.RoundupToKB(status.Size)

	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
}

func deleteSpace(ctx *downloaderContext, kb uint64) {
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.UsedSpace -= kb
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

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
