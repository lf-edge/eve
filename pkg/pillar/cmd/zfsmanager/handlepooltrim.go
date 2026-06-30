// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// runPoolTrimSchedule issues a boot-time zpool trim immediately on start, then
// continues on the ZFSPoolTrimCron schedule. Both run fully async and do not
// gate any startup path. zpool trim initiates background NVMe I/O and returns
// immediately; progress is visible via `zpool status persist`. Only applies to
// EVE-k ZFS nodes; a no-op otherwise.
func runPoolTrimSchedule(ctx *zfsContext) {
	if !base.IsHVTypeKube() {
		return
	}
	go func() {
		log.Noticef("runPoolTrimSchedule: boot-time demand trim starting")
		runZpoolTrim(ctx)

		cronSpec := ctx.globalConfig.GlobalValueString(types.ZFSPoolTrimCron)
		if cronSpec == "" {
			return
		}
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		var lastFired time.Time
		for t := range ticker.C {
			if types.CronShouldFire(cronSpec, t, &lastFired) {
				log.Noticef("runPoolTrimSchedule: scheduled trim starting")
				runZpoolTrim(ctx)
			}
		}
	}()
}

func runZpoolTrim(ctx *zfsContext) {
	ctx.trimStatus.LastStartTime = time.Now()
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
