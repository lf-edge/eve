// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package types

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type LedBlinkCounter struct {
	BlinkCounter int
}

const (
	ledConfigDirName  = "/var/tmp/ledmanager/config"
	ledConfigFileName = ledConfigDirName + "/ledconfig.json"
)

// Used by callers to change the behavior or the LED
func UpdateLedManagerConfig(count int) {
	blinkCount := LedBlinkCounter{
		BlinkCounter: count,
	}
	b, err := json.Marshal(blinkCount)
	if err != nil {
		log.Fatal(err, "json Marshal blinkCount")
	}
	err = ioutil.WriteFile(ledConfigFileName, b, 0644)
	if err != nil {
		log.Println("err: ", err, ledConfigFileName)
	} else {
		log.Printf("UpdateLedManagerConfig: set %d\n", count)
	}
}
