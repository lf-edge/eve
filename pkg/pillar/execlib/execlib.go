// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A client package which talks to the executor service
// Call init first to set up pubsub
// Note that the executor must be setup to subscribe to us for the commands.

package execlib

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// ExecuteHandle is returned by New and passed to the Execute function
type ExecuteHandle struct {
	// Private fields
	caller        string
	executor      string
	pubExecConfig pubsub.Publication
	subExecStatus pubsub.Subscription
	sequence      int
	matchedStatus types.ExecStatus
	log           *base.LogObject
}

// ExecuteArgs is passed for each command
type ExecuteArgs struct {
	Command        string
	Args           []string
	Environ        []string
	TimeLimit      uint // In seconds
	CombinedOutput bool // If set stderr and stdout are in output
	DontWait       bool // Do not wait for response
}

// New returns the handle to use with Execute
func New(ps *pubsub.PubSub, log *base.LogObject, agentName string, executor string) (*ExecuteHandle, error) {

	pubExecConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ExecConfig{},
	})
	pubExecConfig.Unpublish(agentName)

	// No need to use rand.Seed() any more
	sequence := rand.Int()

	handle := ExecuteHandle{
		caller:        agentName,
		executor:      executor,
		pubExecConfig: pubExecConfig,
		sequence:      sequence,
	}
	subExecStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "executor",
		MyAgentName:   agentName,
		TopicImpl:     types.ExecStatus{},
		Ctx:           &handle,
		CreateHandler: handleStatusCreate,
		ModifyHandler: handleStatusModify,
	})
	if err != nil {
		return nil, err
	}
	handle.subExecStatus = subExecStatus
	subExecStatus.Activate()

	return &handle, nil
}

// Execute runs a command and waits for response unless DontWait is set
func (hdl *ExecuteHandle) Execute(args ExecuteArgs) (string, error) {

	config := types.ExecConfig{
		Caller:    hdl.caller,
		Sequence:  hdl.sequence,
		Command:   args.Command,
		Args:      args.Args,
		Environ:   args.Environ,
		TimeLimit: args.TimeLimit,
		Combined:  args.CombinedOutput,
		DontWait:  args.DontWait,
	}
	hdl.log.Functionf("publish %+v", config)
	hdl.pubExecConfig.Publish(config.Key(), config)
	if args.DontWait {
		return "", nil
	}
	// wait for result
	// Fixed local timer; remote should honor timeLimit
	duration := 10 * time.Minute
	maxTimer := time.NewTimer(duration)
	for hdl.matchedStatus.Sequence != hdl.sequence {
		select {
		case change := <-hdl.subExecStatus.MsgChan():
			hdl.subExecStatus.ProcessChange(change)

		case <-maxTimer.C:
			err := errors.New("Local time out; is server broken?")
			return "", err
		}
	}
	status := hdl.matchedStatus
	if status.TimedOut {
		err := fmt.Errorf("Timed out by server")
		return status.Output, err
	}
	if status.ExitValue != 0 {
		err := fmt.Errorf("Failed with exit code %d", status.ExitValue)
		return status.Output, err
	}
	return status.Output, nil
}

func handleStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleStatusImpl(ctxArg, key, statusArg)
}

func handleStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleStatusImpl(ctxArg, key, statusArg)
}

func handleStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	hdl := ctxArg.(*ExecuteHandle)
	hdl.log.Functionf("handleStatusImpl %s", key)
	if key != hdl.caller {
		hdl.log.Functionf("Mismatched key %s vs %s\n", key, hdl.caller)
		return
	}
	status := statusArg.(types.ExecStatus)
	if status.Sequence != hdl.sequence {
		hdl.log.Functionf("Mismatched sequence %d vs %d\n",
			status.Sequence, hdl.sequence)
		return
	}
	hdl.matchedStatus = status
}
