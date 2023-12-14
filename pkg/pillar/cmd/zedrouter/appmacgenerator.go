// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Back-ported code for persisting of MAC address generator ID per app.
// This code is adjusted specifically for 9.4. In newer EVE versions,
// this is implemented using objtonum package which is not yet in 9.4.
// We have to be careful here and replicate the format of persisted data
// to match newer EVE versions and enable seamless upgrades.

package zedrouter

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func getAppMacGeneratorID(ctx *zedrouterContext, appUUID uuid.UUID) (int, error) {
	rawItem, err := ctx.pubAppMACGenerator.Get(appUUID.String())
	if err != nil {
		log.Errorf("failed to get published MAC generator ID for app %v: %v",
			appUUID, err)
		return 0, err
	}
	item, ok := rawItem.(types.AppMACGenerator)
	if !ok {
		return 0, fmt.Errorf("invalid item type: %T, expected AppMACGenerator", rawItem)
	}
	return item.Number, nil
}

func publishAppMacGeneratorID(ctx *zedrouterContext, appUUID uuid.UUID, macGenID int) error {
	now := time.Now()
	item := types.AppMACGenerator{
		UuidToNum: types.UuidToNum{
			UUID:        appUUID,
			CreateTime:  now,
			LastUseTime: now,
			InUse:       true,
			NumType:     "appMACGenerator",
			Number:      macGenID,
		},
	}
	err := ctx.pubAppMACGenerator.Publish(item.Key(), item)
	if err != nil {
		log.Errorf("failed to publish MAC generator ID for app %v: %v",
			appUUID, err)
	}
	return err
}

func unpublishAppMacGeneratorID(ctx *zedrouterContext, appUUID uuid.UUID) error {
	err := ctx.pubAppMACGenerator.Unpublish(appUUID.String())
	if err != nil {
		log.Errorf("failed to un-publish MAC generator ID for app %v: %v",
			appUUID, err)
	}
	return err
}
