// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A single-threaded way to have other microservices request exec of a command
// in a different container or VM where this executor runs

package executor

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const (
	agentName = "executor"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Version can be set from Makefile
var Version = "No version specified"

// Any state used by handlers goes here
type executorContext struct {
	subTmpConfig      pubsub.Subscription
	subCommandConfig  pubsub.Subscription
	subVerifierConfig pubsub.Subscription
	subDomainConfig   pubsub.Subscription
	pubExecStatus     pubsub.Publication

	subGlobalConfig pubsub.Subscription
	GCInitialized   bool

	// CLI args
	debug         bool
	debugOverride bool // From command line arg
	timeLimit     uint // In seconds
}

// Run is the main aka only entrypoint
func Run(ps *pubsub.PubSub) {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	timeLimitPtr := flag.Uint("t", 120, "Maximum time to wait for command")
	flag.Parse()
	execCtx := executorContext{}
	execCtx.debug = *debugPtr
	execCtx.debugOverride = execCtx.debug
	if execCtx.debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	execCtx.timeLimit = *timeLimitPtr
	err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}

	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

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
		TopicImpl:     types.GlobalConfig{},
		Ctx:           &execCtx,
		CreateHandler: handleGlobalConfigModify,
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
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	subTmpConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
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
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	config := configArg.(types.ExecConfig)
	log.Infof("handleCreate(%s.%d) %s",
		config.Caller, config.Sequence, config.Command)
	status := launchCmd(execCtx, config)
	if status != nil {
		execCtx.pubExecStatus.Publish(status.Key(), *status)
		log.Infof("handleCreate(%s.%d) Done",
			config.Caller, config.Sequence)
	} else {
		log.Warnf("handleCreate(%s.%d) No status",
			config.Caller, config.Sequence)
	}
}

func handleModify(ctxArg interface{}, key string,
	configArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	config := configArg.(types.ExecConfig)
	status := lookupExecStatus(execCtx, key)
	if config.Sequence == status.Sequence {
		log.Infof("handleModify(%s.%d) no change",
			config.Caller, config.Sequence)
		return
	}
	log.Infof("handleModify(%s.%d) %s",
		config.Caller, config.Sequence, config.Command)
	status = launchCmd(execCtx, config)
	if status != nil {
		if config.DontWait {
			log.Infof("handleModify(%s.%d) Done with DontWait",
				config.Caller, config.Sequence)
		} else {
			execCtx.pubExecStatus.Publish(status.Key(), *status)
			log.Infof("handleModify(%s.%d) Done",
				config.Caller, config.Sequence)
		}
	} else {
		log.Infof("handleModify(%s.%d) No status",
			config.Caller, config.Sequence)
	}
}

func handleDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	config := configArg.(types.ExecConfig)
	log.Infof("handleDelete(%s.%d) %s",
		config.Caller, config.Sequence, config.Command)
	status := lookupExecStatus(execCtx, key)
	if status != nil {
		execCtx.pubExecStatus.Unpublish(status.Key())
		log.Infof("handleDelete(%s.%d) Done",
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
	log.Infof("launchCmd %+v", config)
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
				log.Infof("Exit code: %d", exitStatus.ExitStatus())
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
	log.Infof("Succeeded %+v", status)
	return &status
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.GlobalConfig
	execCtx.debug, gcp = agentlog.HandleGlobalConfig(execCtx.subGlobalConfig, agentName,
		execCtx.debugOverride)
	if gcp != nil {
		execCtx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	execCtx := ctxArg.(*executorContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	execCtx.debug, _ = agentlog.HandleGlobalConfig(execCtx.subGlobalConfig, agentName,
		execCtx.debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}
