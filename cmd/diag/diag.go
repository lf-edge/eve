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
// XXX	"github.com/zededa/go-provision/hardware"
// XXX	"github.com/zededa/go-provision/pubsub"
// XXX	"github.com/zededa/go-provision/types"
	"os"
)

const (
	agentName       = "diag"
	tmpDirname      = "/var/tmp/zededa"
	identityDirname = "/config"
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

	// XXX should we check whether model exists first?? Separately look
	// at override and dmidecode?
	// NOTE: dmidecode hardware model %s overridden by zedcloud to %s
	// ERROR: zedcloud/dmidecode hardware model %s not in /var/tmp/zededa/DeviceNetworkConfig/
	// NOTE: Device is using /var/tmp/zededa/DeviceNetworkConfig/default.json

	// ERROR: zedcloud/dmidecode hardware model %s not in /var/tmp/zededa/AssignableAdapters/
	// NOTE: Device is using /var/tmp/zededa/AssignableAdapters/default.json

	// NOTE: /config/DevicePortConfig/%s.json overrides /var/tmp/zededa/DeviceNetworkConfig/


	// XXX device.cert? self-register-failed?

	// XXX subscribe to Ledmanager config and print it; need Initialized
	// flag or after first wait?

	// XXX subscribe to DeviceNetworkStatus
	// XXX track/print based on updated separately if -w flag?
}