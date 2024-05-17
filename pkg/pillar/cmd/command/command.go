// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A test application for the executor microservice
// Reads commands and arguments from stdin and prints the output

// Example usage:
// # echo 'ls -l -R /config' | dist/amd64/command -q
// /config:
// total 212
// -rw-r--r-- 1 nordmark nordmark    664 Aug 21 05:04 device.cert.pem
// -rw------- 1 nordmark nordmark    227 Aug 21 05:04 device.key.pem
// -rw-r--r-- 1 root     root       2134 Jan 30 20:04 root-certificate.pem
// -rw-r--r-- 1 root     root         26 Jan 30 20:03 server
// -rw-r--r-- 1 root     root     200061 Sep 24 02:45 v2tlsbaseroot-certificates.pem
//
// # echo 'ls /x' | dist/amd64/command -q
// Failed with exit code 2
// Output:
//
// # echo 'ls /x' | dist/amd64/command -c -q
// Failed with exit code 2
// Output:
// ls: cannot access '/x': No such file or directory
//
// # echo date | dist/amd64/command -e TZ=CET -q
// Output:
// Sat Feb 15 07:51:05 CET 2020
//
// # echo 'sleep 5' | dist/amd64/command -t 2 -q
// Timed out by server. Output:
//
// # echo 'ls /x' |  dist/amd64/command -W
// requested DontWait: no output

package command

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/execlib"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

const agentName = "command"

var (
	timeLimit      uint
	combinedOutput bool
	environ        []string
	dontWait       bool
	logger         *logrus.Logger
	log            *base.LogObject
)

type commandAgentState struct {
	agentbase.AgentBase
	// cli options
	quietPtr     *bool
	timeLimitPtr *uint
	combinedPtr  *bool
	environPtr   *string
	dontWaitPtr  *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *commandAgentState) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctx.quietPtr = flagSet.Bool("q", false, "Quiet flag")
	ctx.timeLimitPtr = flagSet.Uint("t", 200, "Maximum time to wait for command")
	ctx.combinedPtr = flagSet.Bool("c", false, "Combine stdout and stderr")
	ctx.environPtr = flagSet.String("e", "", "set single environment variable with name=val syntax")
	ctx.dontWaitPtr = flagSet.Bool("W", false, "don't wait for result")
}

// Run is the main aka only entrypoint
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int { //nolint:gocyclo
	logger = loggerArg
	log = logArg
	// Report nano timestamps
	formatter := logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	logger.SetFormatter(&formatter)

	// Context to pass around
	ctx := commandAgentState{}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithArguments(arguments), agentbase.WithBaseDir(baseDir))

	timeLimit = *ctx.timeLimitPtr
	combinedOutput = *ctx.combinedPtr
	dontWait = *ctx.dontWaitPtr
	if *ctx.environPtr != "" {
		// XXX Syntax to add multiple? This is just for testing
		environ = append(environ, *ctx.environPtr)
	}
	if *ctx.quietPtr {
		loggerArg.SetLevel(logrus.WarnLevel)
	}

	hdl, err := execlib.New(ps, log, agentName, "executor")
	if err != nil {
		log.Fatal(err)
	}

	r := bufio.NewReader(os.Stdin)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Read failed: %s\n", err)
			}
			break
		}
		tokens := strings.Split(strings.TrimSpace(line), " ")
		if len(tokens) == 0 {
			continue
		}
		execute(hdl, tokens[0], tokens[1:])
	}
	return 0
}

func execute(hdl *execlib.ExecuteHandle, command string, args []string) {
	out, err := hdl.Execute(execlib.ExecuteArgs{
		Command:        command,
		Args:           args,
		Environ:        environ,
		TimeLimit:      timeLimit,
		CombinedOutput: combinedOutput,
		DontWait:       dontWait,
	})
	if err != nil {
		fmt.Printf("Failed: %s\n", err)
		fmt.Printf("Failed output: %s\n", out)
		return
	}
	if dontWait {
		fmt.Printf("requested DontWait: no output\n")
	} else {
		fmt.Printf("Output:\n%s\n", out)
	}
}
