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
	DNSDirname              = "/var/run/zedrouter/DeviceNetworkStatus"
	domainStatusDirname     = "/var/run/domainmgr/status"
)

// Set from Makefile
var Version = "No version specified"

var deviceNetworkStatus types.DeviceNetworkStatus

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

	// Tell ourselves to go ahead
	watch.SignalRestart("zedagent")

	getCloudUrls()
	go metricsTimerTask()
	go configTimerTask()

	zedmanagerChanges := make(chan string)
	go watch.WatchStatus(zedmanagerStatusDirname, zedmanagerChanges)
	deviceStatusChanges := make(chan string)
	go watch.WatchStatus(DNSDirname, deviceStatusChanges)
	domainStatusChanges := make(chan string)
	go watch.WatchStatus(domainStatusDirname, domainStatusChanges)
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
		case change := <-deviceStatusChanges:
			watch.HandleStatusEvent(change,
				DNSDirname,
				&types.DeviceNetworkStatus{},
				handleDNSModify, handleDNSDelete,
				nil)
		case change := <-domainStatusChanges:
			watch.HandleStatusEvent(change,
				domainStatusDirname,
				&types.DomainStatus{},
				handleDomainStatusModify, handleDomainStatusDelete,
				nil)
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

func handleDNSModify(statusFilename string,
	statusArg interface{}) {
	var status *types.DeviceNetworkStatus

	if statusFilename != "global" {
		fmt.Printf("handleDNSModify: ignoring %s\n", statusFilename)
		return
	}
	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle DeviceNetworkStatus")
	case *types.DeviceNetworkStatus:
		status = statusArg.(*types.DeviceNetworkStatus)
	}

	log.Printf("handleDNSModify for %s\n", statusFilename)
	deviceNetworkStatus = *status
	log.Printf("handleDNSModify done for %s\n", statusFilename)
}

func handleDNSDelete(statusFilename string) {
	log.Printf("handleDNSDelete for %s\n", statusFilename)

	if statusFilename != "global" {
		fmt.Printf("handleDNSDelete: ignoring %s\n", statusFilename)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Printf("handleDNSDelete done for %s\n", statusFilename)
}
