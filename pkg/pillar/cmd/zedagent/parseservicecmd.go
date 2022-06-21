// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"crypto/sha256"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var storageServiceCmdHash []byte

// parseStorageCmdConfig parsing StorageCmdConfig routine
func parseStorageCmdConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing snapshots config")
	cfgServiceCmd := config.GetStorageServiceCmd()

	h := sha256.New()
	for _, snapshot := range cfgServiceCmd {
		computeConfigElementSha(h, snapshot)
	}

	configHash := h.Sum(nil)
	if bytes.Equal(configHash, storageServiceCmdHash) {
		return
	}

	log.Functionf("parse StorageCmdConfig: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"StorageCmd: %v",
		storageServiceCmdHash, configHash, cfgServiceCmd)

	storageServiceCmdHash = configHash

	// There should never be more configurations coming from a controller
	// than the current existing number of command types.
	checkStorageCmdUpdates(ctx, cfgServiceCmd)

	// Next check to create a new StorageCmd configuration
	checkNewStorageCmdUpdates(ctx, cfgServiceCmd)

	log.Traceln("Parsing StorageCmdConfig config done")
}

func checkStorageCmdUpdates(ctx *getconfigContext,
	StorageCmdList []*zconfig.StorageCmdConfig) {
	cmdList := ctx.pubStorageCmdConfig.GetAll()

	for _, vc := range cmdList {
		cmd := vc.(types.StorageServiceCmdConfig)
		var updateConfig, foundCfg bool
		for _, cfgCmd := range StorageCmdList {
			// Search by type
			if cfgCmd.CmdType == zconfig.StorageCmdType(cmd.CmdType) &&
				cfgCmd.PoolName == cmd.PoolName {
				foundCfg = true
				// check change run time
				if cfgCmd.RunType != zconfig.StorageCmdRunType(cmd.CmdRunType) {
					log.Functionf(
						"checkStorageCmdUpdates: update Run type for %s cmd on %v\n",
						cmd.Key(), cfgCmd.RunType)
					cmd.CmdRunType = types.StorageCmdRunType(cfgCmd.RunType)
					updateConfig = true
				}
				break
			}
		}

		if !foundCfg {
			unpublishStorageCmdConfig(ctx, cmd.Key())
		}
		if updateConfig {
			publishStorageCmdConfig(ctx, cmd)
		}
	}
}

func checkNewStorageCmdUpdates(ctx *getconfigContext,
	StorageCmdList []*zconfig.StorageCmdConfig) {
	localCmdListCfg := ctx.pubStorageCmdConfig.GetAll()

	for _, cfgCmd := range StorageCmdList {
		var foundCmdConfig bool
		for _, vc := range localCmdListCfg {
			cmd := vc.(types.StorageServiceCmdConfig)
			if cfgCmd.CmdType == zconfig.StorageCmdType(cmd.CmdType) &&
				cfgCmd.PoolName == cmd.PoolName {
				foundCmdConfig = true
				break
			}
		}

		if !foundCmdConfig {
			newConfig := types.StorageServiceCmdConfig{}
			newConfig.PoolName = cfgCmd.PoolName
			newConfig.CmdType = types.StorageCmdType(cfgCmd.CmdType)
			newConfig.CmdRunType = types.StorageCmdRunType(cfgCmd.RunType)
			publishStorageCmdConfig(ctx, newConfig)
		}
	}
	log.Traceln("Checking for new snapshots done")
}

func publishStorageCmdConfig(ctx *getconfigContext,
	config types.StorageServiceCmdConfig) {
	key := config.Key()
	log.Tracef("publishStorageCmdConfig(%s)\n", key)
	pub := ctx.pubStorageCmdConfig
	pub.Publish(key, config)
	log.Tracef("publishStorageCmdConfig(%s) done\n", key)
}

func unpublishStorageCmdConfig(ctx *getconfigContext, key string) {
	log.Tracef("unpublishStorageCmdConfig(%s)\n", key)
	pub := ctx.pubStorageCmdConfig
	config, _ := pub.Get(key)
	if config == nil {
		log.Errorf("unpublishStorageCmdConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishStorageCmdConfig(%s) done\n", key)
}
