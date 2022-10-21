// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardwaremodel

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "hardwaremodel"
)

// Set from Makefile
var Version = "No version specified"

// Any state used by handlers goes here
type hardwareModelAgentState struct {
	agentbase.AgentBase
	// cli options
	versionPtr    *bool
	cPtr          *bool
	outputFilePtr *string
}

// AddAgentSpecificCLIFlags adds CLI options
func (state *hardwareModelAgentState) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	state.versionPtr = flagSet.Bool("v", false, "Version")
	state.cPtr = flagSet.Bool("c", false, "No CRLF")
	state.outputFilePtr = flagSet.String("o", "/dev/tty", "file or device for output")
}

var logger *logrus.Logger
var log *base.LogObject

func Run(_ *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	state := hardwareModelAgentState{}
	agentbase.Init(&state, logger, log, agentName,
		agentbase.WithArguments(arguments))

	outputFile := *state.outputFilePtr
	if *state.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	model := hardware.GetHardwareModelNoOverride(log)
	if *state.cPtr {
		b := []byte(fmt.Sprintf("%s", model))
		err := ioutil.WriteFile(outputFile, b, 0644)
		if err != nil {
			log.Fatal("WriteFile", err, outputFile)
		}

	} else {
		b := []byte(fmt.Sprintf("%s\n", model))
		err := ioutil.WriteFile(outputFile, b, 0644)
		if err != nil {
			log.Fatal("WriteFile", err, outputFile)
		}
	}
	return 0
}
