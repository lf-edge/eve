// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, make it available for zedmanager
// publish AppInstanceStatus to ZedCloud.

package main

import (
	"flag"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"log"
	"os"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	zedagentConfigDirname   = "/var/tmp/zedagent/config"
	zedmanagerConfigDirname = "/var/tmp/zedmanager/config"
	zedmanagerStatusDirname = "/var/run/zedmanager/status"
	downloaderConfigDirname = "/var/tmp/downloader/config"
	downloaderStatusDirname = "/var/run/downloader/status"
)

// Set from Makefile
var Version = "No version specified"

var globalConfig types.DeviceNetworkConfig
var globalStatus types.DeviceNetworkStatus

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	log.Printf("Starting zedagent\n")
	watch.CleanupRestarted("zedagent")

	dirs := []string{
		zedagentConfigDirname,
		zedmanagerConfigDirname,
		zedmanagerStatusDirname,
		downloaderConfigDirname,
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}

	// Retrieve the uplink interfaces and their IP addresses
	globalNetworkConfigFilename := "/var/tmp/zedrouter/config/global"
	var err error
	globalConfig, err = types.GetGlobalNetworkConfig(globalNetworkConfigFilename)
	if err != nil {
		log.Printf("%s for %s\n", err, globalNetworkConfigFilename)
		log.Fatal(err)
	}
	globalStatus, err = types.MakeGlobalNetworkStatus(globalConfig)
	if err != nil {
		log.Printf("%s from MakeGlobalNetworkStatus\n", err)
		log.Fatal(err)
	}

	// Tell ourselves to go ahead
	watch.SignalRestart("zedagent")

	getCloudUrls()
	go metricsTimerTask()
	go configTimerTask()

	zedmanagerChanges := make(chan string)
	go watch.WatchStatus(zedmanagerStatusDirname, zedmanagerChanges)
	for {
		select {
		case change := <-zedmanagerChanges:
			{
				watch.HandleStatusEvent(change,
					zedmanagerStatusDirname,
					&types.AppInstanceStatus{},
					handleStatusModify,
					handleStatusDelete, nil)
				continue
			}
		}
	}
}

var publishIteration = 0

func handleStatusModify(statusFilename string, statusArg interface{}) {
	var status *types.AppInstanceStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceStatus")
	case *types.AppInstanceStatus:
		status = statusArg.(*types.AppInstanceStatus)
	}
	PublishDeviceInfoToZedCloud(publishIteration)
	PublishHypervisorInfoToZedCloud(publishIteration)
	PublishAppInfoToZedCloud(statusFilename, status, publishIteration)
	publishIteration += 1
}

func handleStatusDelete(statusFilename string) {
	PublishDeviceInfoToZedCloud(publishIteration)
	PublishHypervisorInfoToZedCloud(publishIteration)
	PublishAppInfoToZedCloud(statusFilename, nil, publishIteration)
	publishIteration += 1
}
