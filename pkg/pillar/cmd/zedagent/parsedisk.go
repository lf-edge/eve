// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"crypto/sha256"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var disksHash []byte

// disks parsing routine
func parseDisksConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing disks config")
	cfgDisks := config.GetDisks()
	if cfgDisks == nil {
		return
	}
	cfgDisksList := cfgDisks.GetDisks()
	h := sha256.New()
	computeConfigElementSha(h, cfgDisks)
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, disksHash) {
		return
	}
	log.Functionf("parseDisksConfig: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgDisksList: %d",
		disksHash, newHash, len(cfgDisksList))

	disksHash = newHash

	edgeNodeDisks := parseEdgeNodeDisks(cfgDisks)

	publishDisksConfig(ctx, edgeNodeDisks)

	log.Traceln("parsing disks config done")
}

func parseEdgeNodeDisks(config *zconfig.DisksConfig) types.EdgeNodeDisks {
	disks := types.EdgeNodeDisks{}
	disks.ArrayType = types.EdgeNodeDiskArrayType(config.ArrayType)
	for _, el := range config.Disks {
		diskConfig := new(types.EdgeNodeDiskConfig)
		if el.Disk != nil {
			diskConfig.Disk = types.EdgeNodeDiskDescription{Name: el.Disk.Name, LogicalName: el.Disk.LogicalName, Serial: el.Disk.Serial}
		}
		if el.OldDisk != nil {
			diskConfig.OldDisk = &types.EdgeNodeDiskDescription{Name: el.OldDisk.Name, LogicalName: el.OldDisk.LogicalName, Serial: el.OldDisk.Serial}
		}
		diskConfig.Config = types.EdgeNodeDiskConfigType(el.DiskConfig)
		disks.Disks = append(disks.Disks, *diskConfig)
	}
	for _, el := range config.Children {
		disks.Children = append(disks.Children, parseEdgeNodeDisks(el))
	}
	return disks
}

func publishDisksConfig(ctx *getconfigContext,
	config types.EdgeNodeDisks) {

	key := config.Key()
	log.Tracef("publishDisksConfig(%s)\n", key)
	pub := ctx.pubDisksConfig
	pub.Publish(key, config)
	log.Tracef("publishDisksConfig(%s) done\n", key)
}
