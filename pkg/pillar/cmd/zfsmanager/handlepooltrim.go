// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// refreshTrimConfig caches the current ZFSPoolTrimCron and ZFSPoolTrimRate
// from globalConfig under trimMu. Called from the main goroutine on every
// global config update so the pool trim goroutine picks up changes at runtime.
func (ctx *zfsContext) refreshTrimConfig() {
	ctx.trimMu.Lock()
	ctx.trimCron = ctx.globalConfig.GlobalValueString(types.ZFSPoolTrimCron)
	ctx.trimRate = ctx.globalConfig.GlobalValueInt(types.ZFSPoolTrimRate)
	ctx.trimMu.Unlock()
}

// getTrimRate returns the cached per-disk pool trim rate in bytes/s under
// trimMu.
func (ctx *zfsContext) getTrimRate() uint32 {
	ctx.trimMu.Lock()
	defer ctx.trimMu.Unlock()
	return ctx.trimRate
}

// getTrimCron returns the cached pool trim cron spec under trimMu.
func (ctx *zfsContext) getTrimCron() string {
	ctx.trimMu.Lock()
	defer ctx.trimMu.Unlock()
	return ctx.trimCron
}

// setTrimStart records the start time of the most recent pool trim under
// trimMu.
func (ctx *zfsContext) setTrimStart(t time.Time) {
	ctx.trimMu.Lock()
	ctx.trimStatus.LastStartTime = t
	ctx.trimMu.Unlock()
}

// getTrimStatus returns a copy of the latest pool trim status under trimMu.
func (ctx *zfsContext) getTrimStatus() types.PoolTrimStatus {
	ctx.trimMu.Lock()
	defer ctx.trimMu.Unlock()
	return ctx.trimStatus
}

const (
	// poolTrimExtentMax is the zfs_trim_extent_bytes_max value that
	// 000-mod-params in pkg/dom0-ztools sets at boot.
	poolTrimExtentMax  = 16 * 1024 * 1024
	trimExtentMaxParam = "/hostfs/sys/module/zfs/parameters/zfs_trim_extent_bytes_max"

	// libzfs messages for EBUSY on a trim start and ESRCH on a suspend.
	trimBusyMsg     = "currently trimming"
	noActiveTrimMsg = "there is no active trim"
)

// runPoolTrimSchedule runs a zpool trim limited to ZFSPoolTrimRate on the
// ZFSPoolTrimCron schedule, asynchronously. There is no boot-time trim: a full trim re-trims
// all free space, and on a device that reboots often it keeps the disk busy
// for most of each boot. zpool trim returns immediately; progress is visible
// via `zpool status -t persist`. Only applies to EVE-k ZFS nodes; a no-op
// otherwise.
//
// The cron spec and rate are re-read from the cached global config on every
// tick, so a controller can retune or disable (empty spec) the schedule at
// runtime; the ticker keeps running while the spec is empty so it can be
// re-enabled. A rate change is applied to a trim in progress.
func runPoolTrimSchedule(ctx *zfsContext) {
	if !base.IsHVTypeKube() {
		return
	}
	checkTrimExtentMax()
	go func() {
		rate := ctx.getTrimRate()
		resumeTrimAtRate(rate)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		var lastFired time.Time
		for t := range ticker.C {
			if newRate := ctx.getTrimRate(); newRate != rate {
				rate = newRate
				resumeTrimAtRate(rate)
			}
			cronSpec := ctx.getTrimCron()
			if cronSpec == "" {
				continue
			}
			if types.CronShouldFire(cronSpec, t, &lastFired) {
				log.Noticef("runPoolTrimSchedule: scheduled trim starting")
				runZpoolTrim(ctx, rate)
			}
		}
	}()
}

func runZpoolTrim(ctx *zfsContext, rate uint32) {
	out, err := zpoolTrimAtRate(rate)
	if err != nil {
		if strings.Contains(string(out), trimBusyMsg) {
			log.Noticef("runPoolTrimSchedule: zpool trim %s already in progress",
				types.PersistPool)
			return
		}
		log.Errorf("runPoolTrimSchedule: zpool trim %s: %v (%s)",
			types.PersistPool, err, out)
		return
	}
	ctx.setTrimStart(time.Now())
	collectAndPublishStorageStatus(ctx)
	log.Noticef("runPoolTrimSchedule: zpool trim %s initiated", types.PersistPool)
}

// resumeTrimAtRate re-issues a trim in progress at rate bytes/s per disk. A
// trim resumed at pool import keeps the rate it was started with, which is
// unlimited for a trim started by an older EVE, and zpool status exposes no
// rate to check, so every active trim is re-issued at startup. A suspend
// waits for the trim thread to exit and keeps the trim's progress, but resets
// the start time that `zpool status -t` reports.
func resumeTrimAtRate(rate uint32) {
	out, err := base.Exec(log, types.ZPoolBinary, "trim", "-s",
		types.PersistPool).CombinedOutput()
	if err != nil {
		if !strings.Contains(string(out), noActiveTrimMsg) {
			log.Errorf("runPoolTrimSchedule: zpool trim -s %s: %v (%s)",
				types.PersistPool, err, out)
		}
		return
	}
	out, err = zpoolTrimAtRate(rate)
	if err != nil {
		log.Errorf("runPoolTrimSchedule: resuming trim of %s: %v (%s)",
			types.PersistPool, err, out)
		return
	}
	log.Noticef("runPoolTrimSchedule: resumed trim of %s at %d bytes/s",
		types.PersistPool, rate)
}

func zpoolTrimAtRate(rate uint32) ([]byte, error) {
	return base.Exec(log, types.ZPoolBinary, "trim",
		"-r", fmt.Sprintf("%d", rate), types.PersistPool).
		CombinedOutput()
}

// checkTrimExtentMax logs an error if zfs_trim_extent_bytes_max is not
// poolTrimExtentMax, i.e. if each TRIM command is not bounded as expected.
func checkTrimExtentMax() {
	val, err := os.ReadFile(trimExtentMaxParam)
	if err != nil {
		log.Errorf("checkTrimExtentMax: reading %s: %v", trimExtentMaxParam, err)
		return
	}
	if got := strings.TrimSpace(string(val)); got != fmt.Sprintf("%d", poolTrimExtentMax) {
		log.Errorf("checkTrimExtentMax: %s is %s, expected %d",
			trimExtentMaxParam, got, poolTrimExtentMax)
	}
}
