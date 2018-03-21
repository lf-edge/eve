// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package agentlog

import (
	"fmt"
	"github.com/zededa/go-provision/zboot"
	"log"
	"os"
)

func Init(agentName string) (*os.File, error) {
	logdir := GetCurrentLogdir()
	logfile := fmt.Sprintf("%s/%s.log", logdir, agentName)
	logf, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND,
		0666)
	if err != nil {
		return nil, err
	}
	log.SetOutput(logf)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	return logf, nil
}

const baseLogdir = "/persist"

// Return a logdir for agents and logmanager to use by default
func GetCurrentLogdir() string {
	var partName string
	if !zboot.IsAvailable() {
		partName = "IMGA"
	} else {
		partName = zboot.GetCurrentPartition()
	}
	logdir := fmt.Sprintf("%s/%s/log", baseLogdir, partName)
	return logdir
}

// If the other partition is not inprogress we return the empty string
func GetOtherLogdir() string {
	if !zboot.IsAvailable() {
		return ""
	}
	if !zboot.IsOtherPartitionStateInProgress() {
		return ""
	}
	partName := zboot.GetOtherPartition()
	logdir := fmt.Sprintf("%s/%s/log", baseLogdir, partName)
	return logdir
}
