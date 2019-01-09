// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package types

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/pubsub"
)

type LedBlinkCounter struct {
	BlinkCounter int
}

const (
	tmpDirName   = "/var/tmp/zededa/"
	ledConfigKey = "ledconfig"
)

// Global variable to supress log messages when nothing changes from this
// agent. Since other agents might have changed we still update the config.
var lastCount = 0

// Used by callers to change the behavior or the LED
func UpdateLedManagerConfig(count int) {
	blinkCount := LedBlinkCounter{
		BlinkCounter: count,
	}
	err := pubsub.PublishToDir(tmpDirName, ledConfigKey, &blinkCount)
	if err != nil {
		log.Errorln("err: ", err, tmpDirName)
	} else {
		if count != lastCount {
			log.Infof("UpdateLedManagerConfig: set %d\n", count)
			lastCount = count
		}
	}
}
