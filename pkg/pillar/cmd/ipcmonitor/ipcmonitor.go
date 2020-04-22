// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Connect to and watch for updates for a given agent, agentScope, and topic.
// Uses AF_UNIX socket
//
// Example usage: to monitor what zedmanager publishes in DomainConfig use
// ipcmonitor -a zedmanager -t DomainConfig
//     That corresponds to the state in /var/run/zedmanager/DomainConfig/*.json
//     but with ongoing updates and deletes.
// For agents with agentScope, such as downloader and verifier, use e.g.,
// ipcmonitor -a zedmanager -s appImg.obj -t DownloaderConfiga
//     which corresponds to /var/run/zedmanager/appImg.obj/DownloaderConfig/

package ipcmonitor

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	log "github.com/sirupsen/logrus"
)

var debugOverride bool // From command line arg

func Run(ps *pubsub.PubSub) {
	agentNamePtr := flag.String("a", "zedrouter",
		"Agent name")
	agentScopePtr := flag.String("s", "", "agentScope")
	topicPtr := flag.String("t", "DeviceNetworkStatus",
		"topic")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	agentName := *agentNamePtr
	agentScope := *agentScopePtr
	topic := *topicPtr
	debugOverride = *debugPtr
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	name := nameString(agentName, agentScope, topic)
	sockName := fmt.Sprintf("/var/run/%s.sock", name)
	s, err := net.Dial("unixpacket", sockName)
	if err != nil {
		log.Fatal("Dial:", err)
	}
	req := fmt.Sprintf("request %s", topic)
	s.Write([]byte(req))
	buf := make([]byte, 65536)
	for {
		res, err := s.Read(buf)
		if err != nil {
			log.Fatal("Read:", err)
		}
		if res == len(buf) {
			// Likely truncated
			log.Fatalf("Message likely truncated")
		}
		reply := strings.Split(string(buf[0:res]), " ")
		count := len(reply)
		if count < 2 {
			log.Errorf("Too short: %v", reply)
			continue
		}
		msg := reply[0]
		t := reply[1]

		if t != topic {
			log.Errorf("Mismatched topic %s vs. %s for %s",
				t, topic, msg)
			continue
		}

		switch msg {
		case "hello", "restarted", "complete":
			log.Infof("Got message %s type %s", msg, t)

		case "delete":
			if count < 3 {
				log.Errorf("Too short delete: %v", reply)
				continue
			}
			recvKey := reply[2]

			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				log.Errorf("base64: %s", err)
			}
			log.Infof("delete type %s key %s", t, key)

		case "update":
			if count < 4 {
				log.Errorf("Too short update: %v", reply)
				continue
			}
			if count > 4 {
				log.Errorf("Too long update: %v", reply)
				continue
			}
			recvKey := reply[2]
			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				log.Errorf("base64: %s", err)
			}
			recvVal := reply[3]
			val, err := base64.StdEncoding.DecodeString(recvVal)
			if err != nil {
				log.Errorf("base64: %s", err)
			}

			var output interface{}
			if err := json.Unmarshal(val, &output); err != nil {
				log.Fatal(err, "json Unmarshal")
			}
			log.Infof("update type %s key %s val %+v",
				t, key, output)

		default:
			log.Errorf("Unknown message: %s", msg)
		}
	}
}

func nameString(agentname, agentscope, topic string) string {
	if agentscope == "" {
		return fmt.Sprintf("%s/%s", agentname, topic)
	} else {
		return fmt.Sprintf("%s/%s/%s", agentname, agentscope, topic)
	}
}
