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

var (
	debugOverride = false
	//Version Set from Makefile
	Version     = "No version specified"
	entrypoints = map[string]func(*pubsub.PubSub){
		"client":           client.Run,
		"command":          command.Run,
		"diag":             diag.Run,
		"domainmgr":        domainmgr.Run,
		"downloader":       downloader.Run,
		"executor":         executor.Run,
		"hardwaremodel":    hardwaremodel.Run,
		"ledmanager":       ledmanager.Run,
		"logmanager":       logmanager.Run,
		"nim":              nim.Run,
		"nodeagent":        nodeagent.Run,
		"verifier":         verifier.Run,
		"volumemgr":        volumemgr.Run,
		"waitforaddr":      waitforaddr.Run,
		"zedagent":         zedagent.Run,
		"zedmanager":       zedmanager.Run,
		"zedrouter":        zedrouter.Run,
		"ipcmonitor":       ipcmonitor.Run,
		"baseosmgr":        baseosmgr.Run,
		"wstunnelclient":   wstunnelclient.Run,
		"conntrack":        conntrack.Run,
		"tpmmgr":           tpmmgr.Run,
		"vaultmgr":         vaultmgr.Run,
		"upgradeconverter": upgradeconverter.Run,
	}
	log *base.LogObject
)

func main() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	debugOverride = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	log = agentlog.Init(agentName)

	if debugOverride {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// Check what service we are intending to start.
	basename := filepath.Base(os.Args[0])
	if _, ok := entrypoints[basename]; ok {
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
	var sktData string
	sktChan := make(chan string)
	stillRunning := time.NewTicker(15 * time.Second)
	pid := os.Getpid()
	logObj := base.NewSourceLogObject(agentName, pid)
	ps := pubsub.New(&socketdriver.SocketDriver{Log: logObj}, logObj)

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

			log.Infof("zedbox: Received command = %s agrs = %v",
				serviceInitStatus.ServiceName, serviceInitStatus.CmdArgs)
			srvLogObj := base.NewSourceLogObject(serviceInitStatus.ServiceName, pid)
			srvPs := pubsub.New(&socketdriver.SocketDriver{Log: srvLogObj}, srvLogObj)
			if _, ok := entrypoints[serviceInitStatus.ServiceName]; ok {
				log.Infof("zedbox: Starting %s", serviceInitStatus.ServiceName)
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
				os.Args = serviceInitStatus.CmdArgs
				go startAgentAndDone(serviceInitStatus.ServiceName, srvPs)
				log.Infof("zedbox: Started %s", serviceInitStatus.ServiceName)
			} else {
				fmt.Printf("zedbox: Unknown package: %s\n", serviceInitStatus.ServiceName)
				os.Exit(1)
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
}

func getSocketName(agent string, topic interface{}) string {
	return path.Join(agentRunBasePath, agent, fmt.Sprintf("%s.sock", pubsub.TypeToName(topic)))
}

//startAgentAndDone start the given agent. Touches a <agentName>.done file once the agent returns.
func startAgentAndDone(agentName string, srvPs *pubsub.PubSub) {
	serviceEntrypoint, _ := entrypoints[agentName]
	serviceEntrypoint(srvPs)

	if err := ioutil.WriteFile(fmt.Sprintf("%s/%s.done", agentRunBasePath, agentName), make([]byte, 0), 0700); err != nil {
		log.Fatalf("Error creating done_file: %v", err)
	}
}
