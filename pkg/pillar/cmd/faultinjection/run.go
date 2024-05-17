// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A application which exists solely to inject faults

package faultinjection

import (
	"flag"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
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
	agentbase.AgentBase
	subGlobalConfig pubsub.Subscription
	GCInitialized   bool

	timeLimit uint // In seconds

	// CLI args
	fatalPtr *bool
	panicPtr *bool
	hangPtr  *bool
	hwPtr    *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *faultContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.fatalPtr = flagSet.Bool("F", false, "Cause log.Fatal fault injection")
	ctxPtr.panicPtr = flagSet.Bool("P", false, "Cause golang panic fault injection")
	ctxPtr.hangPtr = flagSet.Bool("H", false, "Cause watchdog .touch fault injection")
	ctxPtr.hwPtr = flagSet.Bool("W", false, "Cause hardware watchdog fault injection")
}

var logger *logrus.Logger
var log *base.LogObject

// Run is the main aka only entrypoint
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg
	ctx := faultContext{}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	fatalFlag := *ctx.fatalPtr
	panicFlag := *ctx.panicPtr
	hangFlag := *ctx.hangPtr
	hwFlag := *ctx.hwPtr

	// Sanity checks
	if hwFlag {
		if _, err := os.Stat("/dev/watchdog"); os.IsNotExist(err) {
			log.Fatal("Asked for hardware watchdog but no /dev/watchdog")
		}
	}
	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)

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
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
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
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}
