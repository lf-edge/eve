// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, make it available for zedmanager
// publish AppInstanceStatus to ZedCloud.

package main

import (
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"log"
	"os"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	zedmanagerConfigDirname  = "/var/tmp/zedmanager/config"
	zedmanagerStatusDirname  = "/var/run/zedmanager/status"
	downloaderConfigDirname  = "/var/tmp/downloader/config"
	downloaderStatusDirname = "/var/run/downloader/status"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Printf("Starting zedagent\n")
	watch.CleanupRestarted("zedagent")

	dirs := []string{
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

	// Tell ourselves to go ahead
	watch.SignalRestart("zedagent")

	getCloudUrls ()
	go metricsTimerTask()
	go configTimerTask()

	configChanges := make(chan string)
	go watch.WatchConfigStatus(zedmanagerConfigDirname,
		zedmanagerStatusDirname, configChanges)
	for {
		select {
		case change := <-configChanges:
			{
				watch.HandleConfigStatusEvent(change,
					zedmanagerConfigDirname,
					zedmanagerStatusDirname,
					&types.AppInstanceConfig{},
					&types.AppInstanceStatus{},
					handleStatusCreate, handleStatusModify,
					handleStatusDelete, nil)
				continue
			}
		}
	}
}

func handleStatusCreate(statusFilename string, configArg interface{}) {
	var config *types.AppInstanceConfig

	switch configArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceConfig")
	case *types.AppInstanceConfig:
		config = configArg.(*types.AppInstanceConfig)
	}
	log.Printf("handleCreate for %s\n", config.DisplayName)
}

func handleStatusModify(statusFilename string, configArg interface{},
	statusArg interface{}) {
	var status *types.AppInstanceStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceStatus")
	case *types.AppInstanceStatus:
		status = statusArg.(*types.AppInstanceStatus)
	}
	MakeDeviceInfoProtobufStructure()
	MakeHypervisorInfoProtobufStructure()
	publishAiInfoToCloud(status)
}

func handleStatusDelete(statusFilename string, statusArg interface{}) {
	var status *types.AppInstanceStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceStatus")
	case *types.AppInstanceStatus:
		status = statusArg.(*types.AppInstanceStatus)
	}
	MakeDeviceInfoProtobufStructure()
	MakeHypervisorInfoProtobufStructure()
	publishAiInfoToCloud(status)
}
