// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A application which exists solely to inject faults

package faultinjection

import (
	"flag"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "faultinjection"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Any state used by handlers goes here
type faultContext struct {
	subGlobalConfig pubsub.Subscription
	GCInitialized   bool

	// CLI args
	debug         bool
	debugOverride bool // From command line arg
	timeLimit     uint // In seconds
}

var logger *logrus.Logger
var log *base.LogObject

// Run is the main aka only entrypoint
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg
	ctx := faultContext{}
	flagSet := flag.NewFlagSet(agentName, flag.ExitOnError)
	debugPtr := flagSet.Bool("d", false, "Debug flag")
	fatalPtr := flagSet.Bool("F", false, "Cause log.Fatal fault injection")
	panicPtr := flagSet.Bool("P", false, "Cause golang panic fault injection")
	hangPtr := flagSet.Bool("H", false, "Cause watchdog .touch fault injection")
	hwPtr := flagSet.Bool("W", false, "Cause hardware watchdog fault injection")
	if err := flagSet.Parse(arguments); err != nil {
		log.Fatal(err)
	}
	fatalFlag := *fatalPtr
	panicFlag := *panicPtr
	hangFlag := *hangPtr
	hwFlag := *hwPtr
	ctx.debug = *debugPtr
	ctx.debugOverride = *debugPtr
	if ctx.debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}
	log.Functionf("Starting %s", agentName)

	// Sanity checks
	if hwFlag {
		if _, err := os.Stat("/dev/watchdog"); os.IsNotExist(err) {
			log.Fatal("Asked for hardware watchdog but no /dev/watchdog")
		}
	}
	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	ps.RegisterFileWatchdog(agentName)

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Ctx:           &ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			} else if panicFlag {
				log.Warnf("Requested fault injection panic to cause watchdog")
				var panicBuf []int
				panicBuf[99] = 1
			}
		}
		if hangFlag {
			log.Warnf("Requested to not touch to cause watchdog")
		} else {
			ps.StillRunning(agentName, warningTime, errorTime)
		}
		// Repeat each time in case it was restarted during boot
		if hwFlag {
			procName := "/usr/sbin/watchdog"
			log.Noticef("Killing %s", procName)
			utils.PkillArgs(log, procName, true, true)
		}
	}
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*faultContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	var gcp *types.ConfigItemValueMap
	ctx.debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.debugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*faultContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	ctx.debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.debugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}
