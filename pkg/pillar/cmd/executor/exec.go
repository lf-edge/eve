// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A single-threaded way to have other microservices request exec of a command
// in a different container or VM where this executor runs

package executor

import (
	"context"
	"flag"
	"os/exec"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "executor"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Any state used by handlers goes here
type executorContext struct {
	agentbase.AgentBase
	subTmpConfig      pubsub.Subscription
	subCommandConfig  pubsub.Subscription
	subVerifierConfig pubsub.Subscription
	subDomainConfig   pubsub.Subscription
	pubExecStatus     pubsub.Publication

	subGlobalConfig pubsub.Subscription
	GCInitialized   bool

	timeLimit uint // In seconds

	// CLI args
	timeLimitPtr *uint // In seconds
	fatalPtr     *bool
	panicPtr     *bool
	hangPtr      *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *executorContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.timeLimitPtr = flagSet.Uint("t", 120, "Maximum time to wait for command")
	ctxPtr.fatalPtr = flagSet.Bool("F", false, "Cause log.Fatal fault injection")
	ctxPtr.panicPtr = flagSet.Bool("P", false, "Cause golang panic fault injection")
	ctxPtr.hangPtr = flagSet.Bool("H", false, "Cause watchdog .touch fault injection")
}

var logger *logrus.Logger
var log *base.LogObject

// Run is the main aka only entrypoint
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg
	execCtx := executorContext{}
	agentbase.Init(&execCtx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	fatalFlag := *execCtx.fatalPtr
	panicFlag := *execCtx.panicPtr
	hangFlag := *execCtx.hangPtr
	execCtx.timeLimit = *execCtx.timeLimitPtr

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Add .pid and .touch file to watchdog config
	ps.RegisterPidWatchdog(agentName)
	ps.RegisterFileWatchdog(agentName)

	pubExecStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ExecStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	execCtx.pubExecStatus = pubExecStatus

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Ctx:           &execCtx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	execCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Pick up debug aka log level before we start real work
	for !execCtx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	subTmpConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		MyAgentName:   agentName,
		TopicImpl:     types.ExecConfig{},
		Ctx:           &execCtx,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	execCtx.subTmpConfig = subTmpConfig
	subTmpConfig.Activate()

	subCommandConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "command",
		MyAgentName:   agentName,
		Ctx:           &execCtx,
		TopicImpl:     types.ExecConfig{},
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	execCtx.subCommandConfig = subCommandConfig
	subCommandConfig.Activate()

	subVerifierConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "verifier",
		MyAgentName:   agentName,
		Ctx:           &execCtx,
		TopicImpl:     types.ExecConfig{},
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	execCtx.subVerifierConfig = subVerifierConfig
	subVerifierConfig.Activate()

	subDomainConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		Ctx:           &execCtx,
		TopicImpl:     types.ExecConfig{},
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	execCtx.subDomainConfig = subDomainConfig
	subDomainConfig.Activate()

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-execCtx.subTmpConfig.MsgChan():
			execCtx.subTmpConfig.ProcessChange(change)
		case change := <-execCtx.subCommandConfig.MsgChan():
			execCtx.subCommandConfig.ProcessChange(change)
		case change := <-execCtx.subVerifierConfig.MsgChan():
			execCtx.subVerifierConfig.ProcessChange(change)
		case change := <-execCtx.subDomainConfig.MsgChan():
			execCtx.subDomainConfig.ProcessChange(change)

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
	}
}

func handleCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	config := configArg.(types.ExecConfig)
	log.Functionf("handleCreate(%s.%d) %s",
		config.Caller, config.Sequence, config.Command)
	status := launchCmd(execCtx, config)
	if status != nil {
		execCtx.pubExecStatus.Publish(status.Key(), *status)
		log.Functionf("handleCreate(%s.%d) Done",
			config.Caller, config.Sequence)
	} else {
		log.Warnf("handleCreate(%s.%d) No status",
			config.Caller, config.Sequence)
	}
}

func handleModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	config := configArg.(types.ExecConfig)
	status := lookupExecStatus(execCtx, key)
	if config.Sequence == status.Sequence {
		log.Functionf("handleModify(%s.%d) no change",
			config.Caller, config.Sequence)
		return
	}
	log.Functionf("handleModify(%s.%d) %s",
		config.Caller, config.Sequence, config.Command)
	status = launchCmd(execCtx, config)
	if status != nil {
		if config.DontWait {
			log.Functionf("handleModify(%s.%d) Done with DontWait",
				config.Caller, config.Sequence)
		} else {
			execCtx.pubExecStatus.Publish(status.Key(), *status)
			log.Functionf("handleModify(%s.%d) Done",
				config.Caller, config.Sequence)
		}
	} else {
		log.Functionf("handleModify(%s.%d) No status",
			config.Caller, config.Sequence)
	}
}

func handleDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	config := configArg.(types.ExecConfig)
	log.Functionf("handleDelete(%s.%d) %s",
		config.Caller, config.Sequence, config.Command)
	status := lookupExecStatus(execCtx, key)
	if status != nil {
		execCtx.pubExecStatus.Unpublish(status.Key())
		log.Functionf("handleDelete(%s.%d) Done",
			config.Caller, config.Sequence)
	} else {
		log.Warnf("handleDelete(%s.%d) No status",
			config.Caller, config.Sequence)
	}
}

func lookupExecStatus(execCtx *executorContext, key string) *types.ExecStatus {
	s, _ := execCtx.pubExecStatus.Get(key)
	if s == nil {
		return nil
	}
	status := s.(types.ExecStatus)
	return &status
}

func launchCmd(execCtx *executorContext, config types.ExecConfig) *types.ExecStatus {
	log.Functionf("launchCmd %+v", config)
	status := types.ExecStatus{
		Caller:   config.Caller,
		Sequence: config.Sequence,
	}
	timeLimit := execCtx.timeLimit
	if config.TimeLimit != 0 && config.TimeLimit < timeLimit {
		timeLimit = config.TimeLimit
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeLimit)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, config.Command, config.Args...)
	cmd.Env = config.Environ
	var out []byte
	var err error
	if config.Combined {
		out, err = cmd.CombinedOutput()
	} else {
		out, err = cmd.Output()
	}
	if ctx.Err() == context.DeadlineExceeded {
		log.Warnf("Exceeded time limit %d", timeLimit)
		status.TimedOut = true
		status.Output = string(out)
		return &status
	}
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			if exitStatus, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				log.Functionf("Exit code: %d", exitStatus.ExitStatus())
				status.ExitValue = exitStatus.ExitStatus()
			} else {
				log.Warnf("No exitStatus but %T: %s",
					exiterr.Sys(), exiterr.Sys())
				if config.Combined {
					status.Output = err.Error()
				}
				status.ExitValue = -2
			}
		} else {
			log.Warnf("No exitError but %T: %s", err, err)
			if config.Combined {
				status.Output = err.Error()
			}
			status.ExitValue = -1
		}
		status.Output = string(out)
		return &status
	}
	status.Output = string(out)
	log.Functionf("Succeeded %+v", status)
	return &status
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

	execCtx := ctxArg.(*executorContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, execCtx.subGlobalConfig, agentName,
		execCtx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		execCtx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, execCtx.subGlobalConfig, agentName,
		execCtx.CLIParams().DebugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}
