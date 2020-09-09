// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
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
	"github.com/lf-edge/eve/pkg/pillar/cmd/hardwaremodel"
	"github.com/lf-edge/eve/pkg/pillar/cmd/ipcmonitor"
	"github.com/lf-edge/eve/pkg/pillar/cmd/ledmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/logmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/nim"
	"github.com/lf-edge/eve/pkg/pillar/cmd/nodeagent"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/upgradeconverter"
	"github.com/lf-edge/eve/pkg/pillar/cmd/vaultmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/verifier"
	"github.com/lf-edge/eve/pkg/pillar/cmd/volumemgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/waitforaddr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/wstunnelclient"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedagent"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedmanager"
	"github.com/lf-edge/eve/pkg/pillar/cmd/zedrouter"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName        = "zedbox"
	agentRunBasePath = "/var/run"
	errorTime        = 3 * time.Minute
	warningTime      = 40 * time.Second
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
		"diag":             {f: diag.Run},
		"domainmgr":        {f: domainmgr.Run},
		"downloader":       {f: downloader.Run},
		"executor":         {f: executor.Run},
		"hardwaremodel":    {f: hardwaremodel.Run, inline: inlineAlways},
		"ledmanager":       {f: ledmanager.Run},
		"logmanager":       {f: logmanager.Run},
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
					log.Infof("Found runAsService for %s",
						basename)
					inline = false
					break
				}
			}
		}
		if inline {
			log.Infof("Running inline command %s args: %+v",
				basename, os.Args[1:])
			ps := pubsub.New(
				&socketdriver.SocketDriver{Logger: logger, Log: log},
				logger, log)
			retval := sep.f(ps, logger, log)
			os.Exit(retval)
		}
		// If its a known child service, the notify zedbox binary to start that
		sericeInitStatus := types.ServiceInitStatus{
			ServiceName: basename,
			CmdArgs:     os.Args,
		}
		log.Infof("Notifying zedbox to start service %s with args %v",
			sericeInitStatus.ServiceName, sericeInitStatus.CmdArgs)
		if err := publish(agentName, &sericeInitStatus); err != nil {
			log.Fatalf(err.Error())
		}
		return
	} else if basename != agentName { // If its unknown child service, check if we intend to start zedbox
		fmt.Printf("zedbox: Unknown package: %s\n", basename)
		os.Exit(1)
	}

	//Start zedbox
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug := *debugPtr
	logger, log = agentlog.Init(agentName)
	if debug {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	var sktData string
	sktChan := make(chan string)
	stillRunning := time.NewTicker(15 * time.Second)
	ps := pubsub.New(
		&socketdriver.SocketDriver{Logger: logger, Log: log},
		logger, log)

	log.Infof("Starting %s", agentName)
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	go startSubscriber(agentName, types.ServiceInitStatus{}, sktChan)
	for {
		select {
		case sktData = <-sktChan:
			sktData = strings.TrimSpace(sktData)
			var serviceInitStatus types.ServiceInitStatus
			if err := json.Unmarshal([]byte(sktData), &serviceInitStatus); err != nil {
				err := fmt.Errorf("zedbox: exception while unmarshalling data %s. %s",
					sktData, err.Error())
				log.Errorf(err.Error())
				break
			}

			log.Infof("zedbox: Received command = %s args = %v",
				serviceInitStatus.ServiceName, serviceInitStatus.CmdArgs)
			srvLogger, srvLog := agentlog.Init(serviceInitStatus.ServiceName)
			srvPs := pubsub.New(
				&socketdriver.SocketDriver{
					Logger: srvLogger,
					Log:    srvLog,
				},
				srvLogger, srvLog)
			if _, ok := entrypoints[serviceInitStatus.ServiceName]; ok {
				log.Infof("zedbox: Starting %s", serviceInitStatus.ServiceName)
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
				os.Args = serviceInitStatus.CmdArgs
				go startAgentAndDone(serviceInitStatus.ServiceName, srvPs, srvLogger, srvLog)
				log.Infof("zedbox: Started %s", serviceInitStatus.ServiceName)
			} else {
				log.Fatalf("zedbox: Unknown package: %s", serviceInitStatus.ServiceName)
			}
		case <-stillRunning.C:
			ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

//startSubscriber Creates a socket for he agent and start listening
func startSubscriber(agent string, topic interface{}, subSkt chan string) {
	log.Infof("startSubscriber(%s)", agent)
	sockName := getSocketName(agent, topic)
	dir := path.Dir(sockName)
	if _, err := os.Stat(dir); err != nil {
		log.Infof("startSubscriber(%s): Create %s\n", agent, dir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatalf("startSubscriber(%s): Exception while creating %s. %s",
				agent, dir, err)
		}
	}
	if _, err := os.Stat(sockName); err == nil {
		// This could either be a left-over in the filesystem
		// or some other process (or ourselves) using the same
		// name to publish. Try connect to see if it is the latter.
		_, err := net.Dial("unix", sockName)
		if err == nil {
			log.Fatalf("connectAndRead(%s): Can not publish %s since its already used",
				agent, sockName)
		}
		if err := os.Remove(sockName); err != nil {
			log.Fatalf("connectAndRead(%s): Exception while removing pre-existing sock %s. %s",
				agent, sockName, err)
		}
	}
	listener, err := net.Listen("unix", sockName)
	if err != nil {
		log.Fatalf("connectAndRead(%s): Exception while listening at sock %s. %s",
			agent, sockName, err)
	}
	defer listener.Close()
	for {
		c, err := listener.Accept()
		if err != nil {
			log.Errorf("connectAndRead(%s) failed %s\n", sockName, err)
			continue
		}
		go serveConnection(c, subSkt)
	}
}

//publish publishes data to an already opened socket.
func publish(agent string, data interface{}) error {
	log.Infof("publish(%s)", agent)
	sockName := getSocketName(agent, data)

	if _, err := os.Stat(sockName); err != nil {
		err := fmt.Errorf("publish(%s): exception while check socket. %s", sockName, err.Error())
		log.Errorf(err.Error())
		return err
	}

	byteData, err := json.Marshal(data)
	if err != nil {
		err := fmt.Errorf("publish(%s): exception while marshalling data. %s",
			sockName, err.Error())
		log.Errorf(err.Error())
		return err
	}

	conn, err := net.Dial("unix", sockName)
	if err != nil {
		err := fmt.Errorf("publish(%s): exception while dialing socket. %s",
			sockName, err.Error())
		log.Errorf(err.Error())
		return err
	}
	defer conn.Close()

	if _, err := conn.Write(byteData); err != nil {
		err := fmt.Errorf("publish(%s): exception while writing data to the socket. %s",
			sockName, err.Error())
		log.Errorf(err.Error())
		return err
	}
	return nil
}

func serveConnection(conn net.Conn, retChan chan string) {

	for {
		buf := make([]byte, 2048)
		count, err := conn.Read(buf)
		if err != nil {
			log.Errorf("serveConnection: Error on read: %s", err)
			break
		}
		retChan <- string(buf[:count])

	}
	conn.Close()
}

func getSocketName(agent string, topic interface{}) string {
	return path.Join(agentRunBasePath, agent, fmt.Sprintf("%s.sock", pubsub.TypeToName(topic)))
}

//startAgentAndDone start the given agent. Writes the return/exit value to
// <agentName>.done file should the agent return.
func startAgentAndDone(agentName string, srvPs *pubsub.PubSub,
	srvLogger *logrus.Logger, srvLog *base.LogObject) {

	serviceEntrypoint, _ := entrypoints[agentName]
	retval := serviceEntrypoint.f(srvPs, srvLogger, srvLog)

	ret := strconv.Itoa(retval)
	if err := ioutil.WriteFile(fmt.Sprintf("/var/run/%s.done", agentName),
		[]byte(ret), 0700); err != nil {
		log.Fatalf("Error write done file: %v", err)
	}
}
