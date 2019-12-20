// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const (
	ledConfigKey = "ledconfig"
)

// UpdateLedManagerConfig is used by callers to change the behavior or the LED
func UpdateLedManagerConfig(count int) {
	blinkCount := types.LedBlinkCounter{
		BlinkCounter: count,
	}
	pub, err := pubsub.Publish("", types.LedBlinkCounter{})
	if err != nil {
		log.Fatal("Publish LedBlinkCounter")
	}
	item, err := pub.Get(ledConfigKey)
	if err == nil {
		bc := item.(types.LedBlinkCounter)
		if bc.BlinkCounter == count {
			log.Debugf("UpdateLedManagerConfig: unchanged at %d",
				count)
			return
		}
		log.Infof("UpdateLedManagerConfig: set %d was %d", count,
			bc.BlinkCounter)
	} else {
		log.Infof("UpdateLedManagerConfig: set to %d", count)
	}
	err = pub.Publish(ledConfigKey, blinkCount)
	if err != nil {
		log.Errorf("Publish failed: %s", err)
	}
}
