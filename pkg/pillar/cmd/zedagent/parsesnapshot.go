// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"crypto/sha256"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var snapshotsHash []byte

// parseSnapshotConfig parsing snapshots routine
func parseSnapshotConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing snapshots config")
	cfgSnapshots := config.GetSnapshots()

	h := sha256.New()
	for _, snapshot := range cfgSnapshots {
		computeConfigElementSha(h, snapshot)
	}

	configHash := h.Sum(nil)
	if bytes.Equal(configHash, snapshotsHash) {
		return
	}

	log.Functionf("parseSnapshotsConfig: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"Snapshots: %v",
		snapshotsHash, configHash, cfgSnapshots)

	snapshotsHash = configHash

	// First look for deleted ones
	checkSnapshotUpdates(ctx, cfgSnapshots)

	// Next check to create a new snapshot configuration
	checkNewSnapshots(ctx, cfgSnapshots)

	log.Traceln("Parsing snapshots config done")
}

func checkNewSnapshots(ctx *getconfigContext, configSnapList []*zconfig.SnapshotConfig) {
	snapshotList := ctx.pubSnapshotConfig.GetAll()
	for _, cfgSnapshot := range configSnapList {
		var foundSnapshot bool
		for _, vc := range snapshotList {
			snap := vc.(types.ZfsSnapshotConfig)
			if cfgSnapshot.Uuid == snap.UUID {
				foundSnapshot = true
				break
			}
		}
		if !foundSnapshot {
			newConfig := types.ZfsSnapshotConfig{}
			newConfig.UUID = cfgSnapshot.Uuid
			newConfig.VolumeUUID = cfgSnapshot.VolumeUuid
			newConfig.DisplayName = cfgSnapshot.DisplayName
			if cfgSnapshot.Rollback != nil {
				newConfig.RollbackCounter = cfgSnapshot.Rollback.Counter
			}
			publishSnapshotConfig(ctx, newConfig)
		}
	}
	log.Traceln("Checking for new snapshots done")
}

func checkSnapshotUpdates(ctx *getconfigContext, configSnapList []*zconfig.SnapshotConfig) {
	snapshotList := ctx.pubSnapshotConfig.GetAll()
	for _, vc := range snapshotList {
		snap := vc.(types.ZfsSnapshotConfig)
		var foundSnapshot, updateConfig bool
		for _, cfgSnapshot := range configSnapList {
			// Search by UUID
			if cfgSnapshot.Uuid == snap.UUID {
				foundSnapshot = true
				// check change name cmd
				if snap.DisplayName != cfgSnapshot.DisplayName {
					log.Functionf("checkSnapshotUpdates: update DisplayName for %s on %s\n",
						snap.Key(), cfgSnapshot.DisplayName)
					snap.DisplayName = cfgSnapshot.DisplayName
					updateConfig = true
				}
				// check rollback cmd
				if cfgSnapshot.Rollback != nil &&
					snap.RollbackCounter != cfgSnapshot.Rollback.Counter {
					log.Functionf("checkSnapshotUpdates: update rollback cmd for %s on %s\n",
						snap.Key(), cfgSnapshot.DisplayName)
					snap.RollbackCounter = cfgSnapshot.Rollback.Counter
					updateConfig = true
				}
				break
			}
		}
		if !foundSnapshot {
			unpublishSnapshotConfig(ctx, snap.Key())
		}
		if updateConfig {
			publishSnapshotConfig(ctx, snap)
		}
	}
}

func publishSnapshotConfig(ctx *getconfigContext,
	config types.ZfsSnapshotConfig) {

	key := config.Key()
	log.Tracef("publishSnapshotConfig(%s)\n", key)
	pub := ctx.pubSnapshotConfig
	pub.Publish(key, config)
	log.Tracef("publishSnapshotConfig(%s) done\n", key)
}

func unpublishSnapshotConfig(ctx *getconfigContext, key string) {
	log.Tracef("unpublishSnapshotConfig(%s)\n", key)
	pub := ctx.pubSnapshotConfig
	config, _ := pub.Get(key)
	if config == nil {
		log.Errorf("unpublishSnapshotConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishSnapshotConfig(%s) done\n", key)
}
