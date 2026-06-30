// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// refreshTrimConfig caches the current ZFSPoolTrimCron from globalConfig under
// trimMu. Called from the main goroutine on every global config update so the
// pool trim goroutine picks up schedule changes at runtime.
func (ctx *zfsContext) refreshTrimConfig() {
	ctx.trimMu.Lock()
	ctx.trimCron = ctx.globalConfig.GlobalValueString(types.ZFSPoolTrimCron)
	ctx.trimMu.Unlock()
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

// runPoolTrimSchedule issues a boot-time zpool trim immediately on start, then
// continues on the ZFSPoolTrimCron schedule. Both run fully async and do not
// gate any startup path. zpool trim initiates background NVMe I/O and returns
// immediately; progress is visible via `zpool status persist`. Only applies to
// EVE-k ZFS nodes; a no-op otherwise.
//
// The cron spec is re-read from the cached global config on every tick, so a
// controller can retune or disable (empty spec) the schedule at runtime; the
// ticker keeps running while the spec is empty so it can be re-enabled.
func runPoolTrimSchedule(ctx *zfsContext) {
	if !base.IsHVTypeKube() {
		return
	}
	go func() {
		log.Noticef("runPoolTrimSchedule: boot-time demand trim starting")
		runZpoolTrim(ctx)

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		var lastFired time.Time
		for t := range ticker.C {
			cronSpec := ctx.getTrimCron()
			if cronSpec == "" {
				continue
			}
			if types.CronShouldFire(cronSpec, t, &lastFired) {
				log.Noticef("runPoolTrimSchedule: scheduled trim starting")
				runZpoolTrim(ctx)
			}
		}
	}()
}

func runZpoolTrim(ctx *zfsContext) {
	ctx.setTrimStart(time.Now())
	collectAndPublishStorageStatus(ctx)
	out, err := base.Exec(log, types.ZPoolBinary, "trim", types.PersistPool).
		CombinedOutput()
	if err != nil {
		log.Errorf("runPoolTrimSchedule: zpool trim %s: %v (%s)",
			types.PersistPool, err, out)
		return
	}
	log.Noticef("runPoolTrimSchedule: zpool trim %s initiated", types.PersistPool)
}
