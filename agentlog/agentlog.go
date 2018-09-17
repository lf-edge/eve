// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package agentlog

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/zboot"
	"os"
	runtimedebug "runtime/debug"
	"time"
)

func initImpl(agentName string, logdir string, redirect bool) (*os.File, error) {
	logfile := fmt.Sprintf("%s/%s.log", logdir, agentName)
	logf, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND,
		0666)
	if err != nil {
		return nil, err
	}
	if redirect {
		log.SetOutput(logf)
		// Report nano timestamps
		formatter := log.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		}
		log.SetFormatter(&formatter)
		log.RegisterExitHandler(printStack)
		log.SetLevel(log.DebugLevel)
	}
	return logf, nil
}

func printStack() {
	st := runtimedebug.Stack()
	log.Error("fatal stack trace:\n%v\n", string(st))
}

func Init(agentName string) (*os.File, error) {
	logdir := GetCurrentLogdir()
	return initImpl(agentName, logdir, true)
}

func InitWithDir(agentName string, logdir string) (*os.File, error) {
	return initImpl(agentName, logdir, true)
}

// Setup and return a logf, but don't redirect our log.*
func InitChild(agentName string) (*os.File, error) {
	logdir := GetCurrentLogdir()
	return initImpl(agentName, logdir, false)
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
