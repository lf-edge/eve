// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Routines which operate on types.GlobalConfig

package utils

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// ReadAndUpdateGCFile does the work of getting a sane or default
// GlobalConfig based on the current definition of GlobalConfig which
// might be different than the file stored on disk if we did an update
// of EVE.
// Returns the existing GlobalConfig otherwise the created default one
func ReadAndUpdateGCFile(log *base.LogObject, pub pubsub.Publication) types.ConfigItemValueMap {
	var gc types.ConfigItemValueMap
	key := "global"
	item, err := pub.Get(key)
	if err == nil {
		gc = item.(types.ConfigItemValueMap)
	} else {
		log.Warn("No globalConfig in /persist; creating it with defaults")
		gc = *types.DefaultConfigItemValueMap()
	}
	err = pub.Publish(key, gc)
	if err != nil {
		log.Errorf("Publish for globalConfig failed %s", err)
	}
	return gc
}

// RoundToMbytes - Byts convert to Mbytes with round-off
func RoundToMbytes(byteCount uint64) uint64 {
	const mbyte = 1 << 20

	return (byteCount + mbyte/2) / mbyte
}
