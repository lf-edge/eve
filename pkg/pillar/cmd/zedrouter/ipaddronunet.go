// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Network Instance underlay network Application Number Management

package zedrouter

import (
	"errors"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func appNumsOnUNetAllocate(ctx *zedrouterContext,
	config *types.AppNetworkConfig) error {

	log.Functionf("appNumsOnUNetAllocate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)
	for _, ulConfig := range config.UnderlayNetworkList {
		isStatic := (ulConfig.AppIPAddr != nil)
		appID := config.UUIDandVersion.UUID
		networkID := ulConfig.Network
		appNum, err := appNumOnUNetAllocate(ctx, networkID, appID,
			isStatic, false)
		if err != nil {
			errStr := fmt.Sprintf("App Num get fail :%s", err)
			log.Errorf("appNumsOnUNetAllocate(%s, %s): fail: %s",
				networkID.String(), appID.String(), errStr)
			return errors.New(errStr)
		}
		log.Functionf("appNumsOnUNetAllocate(%s, %s): allocated %d",
			networkID.String(), appID.String(), appNum)
	}
	return nil
}

func appNumsOnUNetFree(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	log.Functionf("appNumsOnUNetFree(%v) for %s",
		status.UUIDandVersion, status.DisplayName)
	appID := status.UUIDandVersion.UUID
	for ulNum := 0; ulNum < len(status.UnderlayNetworkList); ulNum++ {
		ulStatus := &status.UnderlayNetworkList[ulNum]
		networkID := ulStatus.Network
		// release the app number
		_, err := appNumOnUNetGet(ctx, networkID, appID)
		if err == nil {
			appNumOnUNetFree(ctx, networkID, appID)
		}
	}
}
