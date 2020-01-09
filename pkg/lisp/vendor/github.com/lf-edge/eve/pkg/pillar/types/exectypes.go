// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types for a remote exec (in different container or VM) pubsub service

package types

import (
	log "github.com/sirupsen/logrus"
)

// ExecConfig contains a command to be executed
// The Caller+Sequence is assumed to be unique. When an item is added or
// modified in Caller or Sequence, the command is executed.
type ExecConfig struct {
	Caller    string // Typically agentName
	Sequence  int    // To be able to repeat same command
	Command   string
	Args      []string
	Environ   []string
	TimeLimit uint // In seconds; zero means server default
	Combined  bool // Combined Ouput - stdout and stderr
	DontWait  bool // Caller doesn't want result
}

// Key returns the pubsub key
func (config ExecConfig) Key() string {
	return config.Caller
}

// VerifyFilename returns a json filename
func (config ExecConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained Key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// ExecStatus contains the results of executing a command
// The Caller+Sequence is the unique Key
type ExecStatus struct {
	Caller    string // Typically agentName
	Sequence  int    // To be able to repeat same command
	ExitValue int
	Output    string
	TimedOut  bool // Exceeded timeout
}

// Key returns the pubsub key
func (status ExecStatus) Key() string {
	return status.Caller
}

// VerifyFilename returns a json filename
func (status ExecStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained Key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}
