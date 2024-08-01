// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types for a remote exec (in different container or VM) pubsub service

package types

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
	Combined  bool // Combined Output - stdout and stderr
	DontWait  bool // Caller doesn't want result
}

// Key returns the pubsub key
func (config ExecConfig) Key() string {
	return config.Caller
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
