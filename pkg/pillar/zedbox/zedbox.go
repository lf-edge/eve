// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cmd/baseosmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/client"
	"github.com/lf-edge/eve/pkg/pillar/cmd/command"
	"github.com/lf-edge/eve/pkg/pillar/cmd/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/cmd/diag"
	"github.com/lf-edge/eve/pkg/pillar/cmd/domainmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/downloader"
	"github.com/lf-edge/eve/pkg/pillar/cmd/executor"
	"github.com/lf-edge/eve/pkg/pillar/cmd/faultinjection"
	"github.com/lf-edge/eve/pkg/pillar/cmd/hardwaremodel"
	"github.com/lf-edge/eve/pkg/pillar/cmd/ipcmonitor"
	"github.com/lf-edge/eve/pkg/pillar/cmd/ledmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/loguploader"
	"github.com/lf-edge/eve/pkg/pillar/cmd/nim"
	"github.com/lf-edge/eve/pkg/pillar/cmd/nodeagent"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/upgradeconverter"
	"github.com/lf-edge/eve/pkg/pillar/cmd/vaultmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/verifier"
	"github.com/lf-edge/eve/pkg/pillar/cmd/volumemgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/waitforaddr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/watcher"
	"github.com/lf-edge/eve/pkg/pillar/cmd/wstunnelclient"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedagent"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedrouter"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zfsmanager"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/reverse"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName   = "zedbox"
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

type zedboxInline uint8

const (
	inlineNone          zedboxInline = iota
	inlineUnlessService              // Unless "runAsService" in args
	inlineAlways
)

// The function returns an exit value
type entrypoint struct {
	f      func(*pubsub.PubSub, *logrus.Logger, *base.LogObject) int
	inline zedboxInline
}

var (
	entrypoints = map[string]entrypoint{
		"client":           {f: client.Run, inline: inlineAlways},
		"command":          {f: command.Run},
		"diag":             {f: diag.Run, inline: inlineUnlessService},
		"domainmgr":        {f: domainmgr.Run},
		"downloader":       {f: downloader.Run},
		"executor":         {f: executor.Run},
		"faultinjection":   {f: faultinjection.Run},
		"hardwaremodel":    {f: hardwaremodel.Run, inline: inlineAlways},
		"ledmanager":       {f: ledmanager.Run},
		"loguploader":      {f: loguploader.Run},
		"nim":              {f: nim.Run},
		"nodeagent":        {f: nodeagent.Run},
		"verifier":         {f: verifier.Run},
		"volumemgr":        {f: volumemgr.Run},
		"waitforaddr":      {f: waitforaddr.Run, inline: inlineAlways},
		"zedagent":         {f: zedagent.Run},
		"zedmanager":       {f: zedmanager.Run},
		"zedrouter":        {f: zedrouter.Run},
		"ipcmonitor":       {f: ipcmonitor.Run, inline: inlineAlways},
		"baseosmgr":        {f: baseosmgr.Run},
		"wstunnelclient":   {f: wstunnelclient.Run},
		"conntrack":        {f: conntrack.Run, inline: inlineAlways},
		"tpmmgr":           {f: tpmmgr.Run, inline: inlineUnlessService},
		"vaultmgr":         {f: vaultmgr.Run, inline: inlineUnlessService},
		"upgradeconverter": {f: upgradeconverter.Run, inline: inlineAlways},
		"watcher":          {f: watcher.Run},
		"zfsmanager":       {f: zfsmanager.Run},
	}
	logger *logrus.Logger
	log    *base.LogObject
)

func main() {
	// Check what service we are intending to start.
	basename := filepath.Base(os.Args[0])
	if sep, ok := entrypoints[basename]; ok {
		logger, log = agentlog.Init(basename)
		inline := false
		if sep.inline == inlineAlways {
			inline = true
		} else if sep.inline == inlineUnlessService {
			inline = true
			for _, arg := range os.Args {
				if arg == "runAsService" {
					log.Functionf("Found runAsService for %s",
						basename)
					inline = false
					break
				}
			}
		}
		retval := runService(basename, sep, inline)
		os.Exit(retval)
	}
	// If this zedbox?
	if basename == agentName {
		sep := entrypoint{f: runZedbox, inline: inlineAlways}
		logger, log = agentlog.Init(basename)
		inline := true
		retval := runService(basename, sep, inline)
		// Not likely to ever return, but for uniformity ...
		os.Exit(retval)
	}
	fmt.Printf("zedbox: Unknown package: %s\n", basename)
	os.Exit(1)
}

func runService(serviceName string, sep entrypoint, inline bool) int {
	if inline {
		log.Functionf("Running inline command %s args: %+v",
			serviceName, os.Args[1:])
		ps := pubsub.New(
			&socketdriver.SocketDriver{Logger: logger, Log: log},
			logger, log)
		return sep.f(ps, logger, log)
	}
	// Notify zedbox binary to start the agent/service
	sericeInitStatus := types.ServiceInitStatus{
		ServiceName: serviceName,
		CmdArgs:     os.Args,
	}
	log.Functionf("Notifying zedbox to start service %s with args %v",
		sericeInitStatus.ServiceName, sericeInitStatus.CmdArgs)
	if err := reverse.Publish(log, agentName, &sericeInitStatus); err != nil {
		// When we hit this it is most likely due to zedbox having hit a panic
		// or fatal. Don't hide that as the reboot reason.
		// If that is not the case, then watchdog will soon detect that this service
		// is not running.
		log.Errorf(err.Error())
		return 1
	}
	return 0
}

// runZedbox is the built-in starting of the main process
func runZedbox(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject) int {
	//Start zedbox
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug := *debugPtr
	if debug {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	stillRunning := time.NewTicker(15 * time.Second)

	log.Functionf("Starting %s", agentName)
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	subChan := reverse.NewSubscriber(log, agentName,
		types.ServiceInitStatus{})
	for {
		select {
		case subData := <-subChan:
			subData = strings.TrimSpace(subData)
			var serviceInitStatus types.ServiceInitStatus
			if err := json.Unmarshal([]byte(subData), &serviceInitStatus); err != nil {
				err := fmt.Errorf("zedbox: exception while unmarshalling data %s. %s",
					subData, err.Error())
				log.Errorf(err.Error())
				break
			}
			// Kick off the command in a goroutine
			handleService(serviceInitStatus.ServiceName,
				serviceInitStatus.CmdArgs)

		case <-stillRunning.C:
			ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

// handleService starts the service in a goroutine using a logger/log with
// that serviceName
func handleService(serviceName string, cmdArgs []string) {

	log.Functionf("zedbox: Received command = %s args = %v", serviceName, cmdArgs)
	srvLogger, srvLog := agentlog.Init(serviceName)
	srvPs := pubsub.New(
		&socketdriver.SocketDriver{
			Logger: srvLogger,
			Log:    srvLog,
		},
		srvLogger, srvLog)
	sep, ok := entrypoints[serviceName]
	if !ok {
		log.Fatalf("zedbox: Unknown package: %s",
			serviceName)
	}
	log.Functionf("zedbox: Starting %s", serviceName)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = cmdArgs
	go startAgentAndDone(sep, serviceName, srvPs, srvLogger, srvLog)
	log.Functionf("zedbox: Started %s",
		serviceName)
}

// startAgentAndDone starts the given agent. Writes the return/exit value to
// <agentName>.done file should the agent return.
func startAgentAndDone(sep entrypoint, agentName string, srvPs *pubsub.PubSub,
	srvLogger *logrus.Logger, srvLog *base.LogObject) {

	retval := sep.f(srvPs, srvLogger, srvLog)

	ret := strconv.Itoa(retval)
	if err := ioutil.WriteFile(fmt.Sprintf("/run/%s.done", agentName),
		[]byte(ret), 0700); err != nil {
		log.Fatalf("Error write done file: %v", err)
	}
}
