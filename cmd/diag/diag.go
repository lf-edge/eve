// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Utility to dump diagnostic information about connectivity

package diag

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/hardware"
	// XXX	"github.com/zededa/go-provision/pubsub"
	// XXX	"github.com/zededa/go-provision/types"
	"os"
)

const (
	agentName       = "diag"
	tmpDirname      = "/var/tmp/zededa"
	AADirname       = tmpDirname + "/AssignableAdapters"
	DNCDirname      = tmpDirname + "/DeviceNetworkConfig"
	identityDirname = "/config"
	selfRegFile     = identityDirname + "/self-register-failed"
)

type diagContext struct {
	devicenetwork.DeviceNetworkContext
}

// Set from Makefile
var Version = "No version specified"

var debug = false
var debugOverride bool // From command line arg

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	savedHardwareModel := hardware.GetHardwareModelOverride()
	hardwareModel := hardware.GetHardwareModelNoOverride()
	if savedHardwareModel != hardwareModel {
		fmt.Printf("INFO: dmidecode model string %s overridden as %s\n",
			hardwareModel, savedHardwareModel)
	}
	if !DNCExists(savedHardwareModel) {
		fmt.Printf("ERROR: /config/hardwaremodel %s does not exist in /var/tmp/zededa/DeviceNetworkConfig\n",
			savedHardwareModel)
		fmt.Printf("NOTE: Device is using /var/tmp/zededa/DeviceNetworkConfig/default.json\n")
	}
	if !AAExists(savedHardwareModel) {
		fmt.Printf("ERROR: /config/hardwaremodel %s does not exist in /var/tmp/zededa/AssignableAdapters\n",
			savedHardwareModel)
		fmt.Printf("NOTE: Device is using /var/tmp/zededa/AssignableAdapters/default.json\n")
	}
	if !DNCExists(hardwareModel) {
		fmt.Printf("INFO: dmidecode model %s does not exist in /var/tmp/zededa/DeviceNetworkConfig\n",
			hardwareModel)
	}
	if !AAExists(hardwareModel) {
		fmt.Printf("INFO: dmidecode model %s does not exist in /var/tmp/zededa/AssignableAdapters\n",
			hardwareModel)
	}
	// XXX device.cert? self-register-failed?
	// XXX certificate fingerprints? What does zedcloud use?
	if fileExists(selfRegFile) {
		fmt.Printf("INFO: selfRegister is still in progress\n")
		// XXX print onboarding cert
	}
	// XXX subscribe to Ledmanager config and print it; need Initialized
	// flag or after first wait? Print on each ledmanager update? Default to once i.e., current value?

	// XXX subscribe to DeviceNetworkStatus
	// XXX track/print based on updated separately if -w flag?
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func DNCExists(model string) bool {
	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	return fileExists(DNCFilename)
}

func AAExists(model string) bool {
	AAFilename := fmt.Sprintf("%s/%s.json", AADirname, model)
	return fileExists(AAFilename)
}
