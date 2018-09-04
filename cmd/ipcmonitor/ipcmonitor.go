// Copyright (c) 2017,2018 Zededa, Inc.
// All rights reserved.

// Connect to and watch for updates for a given agent, agentScope, and topic
// Uses AF_UNIX socket

package ipcmonitor

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
)

func Run() {
	agentNamePtr := flag.String("a", "zedrouter",
		"Agent name")
	agentScopePtr := flag.String("s", "", "agentScope")
	topicPtr := flag.String("t", "DeviceNetworkStatus",
		"topic")
	flag.Parse()
	agentName := *agentNamePtr
	agentScope := *agentScopePtr
	topic := *topicPtr
	// args := flag.Args()
	name := nameString(agentName, agentScope, topic)
	sockName := fmt.Sprintf("/var/run/%s.sock", name)
	s, err := net.Dial("unixpacket", sockName)
	if err != nil {
		log.Fatal("Dial:", err)
	}
	req := fmt.Sprintf("request %s", topic)
	s.Write([]byte(req))
	buf := make([]byte, 65535)
	for {
		res, err := s.Read(buf)
		if err != nil {
			log.Fatal("Read:", err)
		}
		// XXX check if res == 65536
		reply := strings.Split(string(buf[0:res]), " ")
		count := len(reply)
		log.Printf("Got %d: %v\n", count, reply)
		if count < 2 {
			log.Printf("Too short: %v\n", reply)
			continue
		}
		t := reply[1]
		switch reply[0] {
		case "hello", "restarted", "complete":
			log.Printf("Got message %s type %s\n", reply[0], t)
		case "delete":
			if count < 3 {
				log.Printf("Too short delete: %v\n", reply)
				continue
			}
			recvKey := reply[2]

			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				log.Printf("base64: %s\n", err)
			}
			log.Printf("delete type %s key %s\n", t, key)

		case "update":
			if count < 4 {
				log.Printf("Too short update: %v\n", reply)
				continue
			}
			recvKey := reply[2]
			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				log.Printf("base64: %s\n", err)
			}
			log.Printf("update type %s key %s vallen %s val <%s>\n",
				t, key, len(reply[3]), reply[3])
			var output interface{}
			if err := json.Unmarshal([]byte(reply[3]), &output); err != nil {
				log.Fatal(err, "json Unmarshal")
			}
			log.Printf("update type %s key %s val %+v\n",
				t, key, output)

		default:
			log.Printf("Unknown command: %s\n", reply[0])
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
