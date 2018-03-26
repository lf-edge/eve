// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
)

// XXX how to structure to have config and status?
// XXX call PublishStatus(agentName, key, status) where status is interface.
// XXX also SubscribeStatus(agentName) to channel with key, interface{}
// XXX SubscribeStatus needs to have ... restartfunc...
// XXX HandleConfigStatusEvent should use LookupStatus instead of reading file
// XXX means we need to read files to pupulate map on startup

// XXX protocol? "sync request", ... "update" "delete" followed by key then val
// "sync done" once all have sent

// Maintain a collection which is used to handle the restart of a subscriber
// map of agentname, key to get a json string
type keyMap struct {
	restarted bool	// XXX add functions; xxx vs. a key called "restart" and "restarted"? Would allow "global"?
	key map[string]interface{}
}
type topicMap map[string]keyMap
type agentMap map[string]topicMap

var agentStatusMap agentMap
var agentConfigMap agentMap

// We always publish to our collection.
// XXX always need to write directory to have a checkpoint on
// restart; need to read restart content in PublishInit
const publishToDir = true
const subscribeFromDir = true // XXX
const subscribeFromSock = false // XXX

// Init function to create socket listener
func PublishInit(agentName string, topicType interface{}) {
	topic := TypeToName(topicType)
	log.Printf("PublishInit(%s, %s)\n", agentName, topic)
	if publishToDir {
		dirName := PubDirName(agentName, topic)
		if _, err := os.Stat(dirName); err != nil {
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}
		
	go publisher(agentName, topic)
}

func publisher(agentName string, topic string) {
	sockName := SockName(agentName, topic)
	if _, err := os.Stat(sockName); err == nil {
		if err := os.Remove(sockName); err != nil {
			log.Fatal(err)
		}
	}
	s, err := net.Listen("unix", sockName)
	if err != nil {
		log.Fatal("publisher:", err)
	}
	for {
		c, err := s.Accept()
		if err != nil {
			log.Printf("publisher:", err)
			continue
		}
		go serveConnection(c, agentName, topic)
	}
}

func serveConnection(s net.Conn, agentName string, topic string) {
	log.Printf("serveConnection(%s, %s)\n", agentName, topic)
	defer s.Close()
	
	_, err := s.Write([]byte(fmt.Sprintf("Hello from %s for %s\n", agentName, topic)))
	if err != nil {
		log.Printf("servceConnection:", err)
	}
	err = SerializeStatus(agentName, topic, s)
	if err != nil {
		log.Printf("servceConnection:", err)
	}
}

func TypeToName(something interface{}) string {
	t := reflect.TypeOf(something)
	out := strings.Split(t.String(), ".")
	return out[len(out)-1]
}

func SockName(agentName string, topic string) string {
	return fmt.Sprintf("/var/run/%s/%s.sock", agentName, topic)
}

func PubDirName(agentName string, topic string) string {
	return fmt.Sprintf("/var/run/%s/%s", agentName, topic)
}

// XXX generic checkAndCreateKeyMap() with agentMap arg
func checkAndCreateStatusMap(agentName string, topic string) keyMap {
	if agentStatusMap == nil {
		agentStatusMap = make(agentMap)
	}
	tm, ok := agentStatusMap[agentName]
	if !ok {
		agentStatusMap[agentName] = make(topicMap)
		tm = agentStatusMap[agentName]
	}
	km, ok := tm[topic]
	if !ok {
		tm[topic] = keyMap{key: make(map[string]interface{})}
		km = tm[topic]
	}
	return km
}

func Publish(agentName string, key string, item interface{}) {
	topic := TypeToName(item)
	log.Printf("Publish(%s, %s, %s)\n", agentName, topic, key)
	km := checkAndCreateStatusMap(agentName, topic)
	km.key[key] = item
	DumpStatus(agentName, topic, "after Publish")

	if publishToDir {
		dirName := PubDirName(agentName, topic)
		fileName := dirName + "/" + key + ".json"
		log.Printf("PublishStatus writing %s\n", fileName)
		b, err := json.Marshal(item)
		if err != nil {
			log.Fatal(err, "json Marshal")
		}
		// We assume a /var/run path hence we don't need to worry about
		// partial writes/empty files due to a kernel crash.
		err = ioutil.WriteFile(fileName, b, 0644)
		if err != nil {
			log.Fatal(err, fileName)
		}
	}

	// XXX send update to all listeners - how? channel to listener -> connections?
}

// XXX could determine topic from type of status?
func Unpublish(agentName string, topic string, key string) {
	log.Printf("Unpublish(%s, %s, %s)\n", agentName, topic, key)
	km := checkAndCreateStatusMap(agentName, topic)
	delete(km.key, key)
	DumpStatus(agentName, topic, "after Unpublish")

	if publishToDir {
		dirName := PubDirName(agentName, topic)
		fileName := dirName + "/" + key + ".json"
		log.Printf("Unpublish deleting %s\n", fileName)
		if err := os.Remove(fileName); err != nil {
			log.Println(err)
		}
	}
	// XXX send update to all listeners - how? channel to listener -> connections?
}

// XXX just Lookup()? We publish config from zedmanger etc
func LookupStatus(agentName string, topic string, key string) (interface{}, error) {
	log.Printf("LookupStatus(%s, %s, %s)\n", agentName, topic, key)
	tm, ok := agentStatusMap[agentName]
	if !ok {
		return nil, fmt.Errorf("agentName %s status not found",
			agentName)
	}
	km, ok := tm[topic]
	if !ok {
		return nil, fmt.Errorf("agentName/topic %s/%s status not found",
			agentName, topic)
	}
	if s, ok := km.key[key]; ok {
		log.Printf("LookupStatus(%s, %s, %s) found\n",
			agentName, topic, key)
		return s, nil
	}
	return nil, fmt.Errorf("key %s not found for %s/%s status",
	       key, agentName, topic)
}

// XXX add a WalkStatus with a callback? based on LookupStatus
// Use for sending? Or this SerializeStatus?
func SerializeStatus(agentName string, topic string, sock net.Conn) error {
	log.Printf("SerializeStatus for %s/%s\n", agentName, topic)
	if tm, ok := agentStatusMap[agentName]; ok {
		if km, ok := tm[topic]; ok {
			for key, s := range km.key {
				b, err := json.Marshal(s)
				if err != nil {
					log.Fatal(err,
						"json Marshal in DumpStatus")
				}
				
				_, err = sock.Write([]byte(fmt.Sprintf("key %s val %s\n", key, b)))
				if err != nil {
					log.Printf("SerializeStatus write failed %s\n", err)
					return err
				}
			}
		}
	}
	return nil
}

func DumpStatus(agentName string, topic string, infoStr string) {
	log.Printf("DumpStatus for %s/%s %s:\n", agentName, topic, infoStr)
	if tm, ok := agentStatusMap[agentName]; ok {
		if km, ok := tm[topic]; ok {
			for key, s := range km.key {
				b, err := json.Marshal(s)
				if err != nil {
					log.Fatal(err,
						"json Marshal in DumpStatus")
				}
				log.Printf("key %s val %s\n", key, b)
			}
		}		    			
	}
}
