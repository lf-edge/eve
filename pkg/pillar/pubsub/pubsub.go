// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

// Protocol over AF_UNIX or other IPC mechanism
// "request" from client after connect to sanity check subject.
// Server sends the other messages; "update" for initial values.
// "complete" once all initial keys/values in collection have been sent.
// "restarted" if/when pub.km.restarted is set.
// Ongoing we send "update" and "delete" messages.
// They keys and values are base64-encoded since they might contain spaces.
// We include typeName after command word for sanity checks.
// Hence the message format is
//	"request" topic
//	"hello"  topic
//	"update" topic key json-val
//	"delete" topic key
//	"complete" topic (aka synchronized)
//	"restarted" topic

// Used locally by each serverConnection goroutine to track updates
// to send.
type localCollection map[string]interface{}

// Maintain a collection which is used to handle the restart of a subscriber
// map of agentname, key to get a json string
// We use StringMap with a RWlock to allow concurrent access.
type keyMap struct {
	restarted bool
	key       *LockedStringMap
}

// We always publish to our collection.
// We always write to a file in order to have a checkpoint on restart
// The special agent name "" implies always reading from the /var/run/zededa/
// directory.
const (
	publishToSock     = true  // XXX
	subscribeFromDir  = false // XXX
	subscribeFromSock = true  // XXX

	// For a subscription, if the agentName is empty we interpret that as
	// being directory in /var/tmp/zededa
	fixedName = "zededa"
	fixedDir  = "/var/tmp/" + fixedName
	maxsize   = 65535 // Max size for json which can be read or written

	// Copied from types package to avoid loop
	// PersistDir - Location to store persistent files.
	PersistDir = "/persist"
	// PersistConfigDir is where we keep some configuration across reboots
	PersistConfigDir = PersistDir + "/config"
)

func Publish(agentName string, topicType interface{}) (*Publication, error) {
	return publishImpl(agentName, "", topicType, false)
}

func PublishPersistent(agentName string, topicType interface{}) (*Publication, error) {
	return publishImpl(agentName, "", topicType, true)
}

func PublishScope(agentName string, agentScope string, topicType interface{}) (*Publication, error) {
	return publishImpl(agentName, agentScope, topicType, false)
}

// Init function to create directory and socket listener based on above settings
// We read any checkpointed state from dirName and insert in pub.km as initial
// values.
func publishImpl(agentName string, agentScope string,
	topicType interface{}, persistent bool) (*Publication, error) {

	topic := TypeToName(topicType)
	pub := new(Publication)
	pub.topicType = topicType
	pub.agentName = agentName
	pub.agentScope = agentScope
	pub.topic = topic
	pub.km = keyMap{key: NewLockedStringMap()}
	pub.persistent = persistent
	name := pub.nameString()

	log.Infof("Publish(%s)\n", name)

	// We always write to the directory as a checkpoint, and only
	// write to it when persistent is set?
	if pub.persistent {
		if agentName == "" {
			pub.publishToDir = true
			pub.dirName = fmt.Sprintf("%s/%s", PersistConfigDir, name)
		} else {
			pub.dirName = PersistentDirName(name)
		}
	} else {
		if agentName == "" {
			pub.publishToDir = true
			pub.dirName = FixedDirName(name)
		} else {
			pub.dirName = PubDirName(name)
		}
	}
	dirName := pub.dirName
	if _, err := os.Stat(dirName); err != nil {
		log.Infof("Publish Create %s\n", dirName)
		if err := os.MkdirAll(dirName, 0700); err != nil {
			errStr := fmt.Sprintf("Publish(%s): %s",
				name, err)
			return nil, errors.New(errStr)
		}
	} else {
		// Read existing status from dir
		pub.populate()
		if log.GetLevel() == log.DebugLevel {
			pub.dump("after populate")
		}
	}

	if !pub.publishToDir && publishToSock {
		sockName := SockName(name)
		dir := path.Dir(sockName)
		if _, err := os.Stat(dir); err != nil {
			log.Infof("Publish Create %s\n", dir)
			if err := os.MkdirAll(dir, 0700); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		if _, err := os.Stat(sockName); err == nil {
			if err := os.Remove(sockName); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		s, err := net.Listen("unixpacket", sockName)
		if err != nil {
			errStr := fmt.Sprintf("Publish(%s): failed %s",
				name, err)
			return nil, errors.New(errStr)
		}
		pub.sockName = sockName
		pub.listener = s
		go pub.publisher()
	}
	return pub, nil
}

// Only reads json files. Sets restarted if that file was found.
func (pub *Publication) populate() {
	name := pub.nameString()
	dirName := pub.dirName
	foundRestarted := false

	log.Infof("populate(%s)\n", name)

	files, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			if file.Name() == "restarted" {
				foundRestarted = true
			}
			continue
		}
		// Remove .json from name */
		key := strings.Split(file.Name(), ".json")[0]

		statusFile := dirName + "/" + file.Name()
		if _, err := os.Stat(statusFile); err != nil {
			// File just vanished!
			log.Errorf("populate: File disappeared <%s>\n",
				statusFile)
			continue
		}

		log.Infof("populate found key %s file %s\n", key, statusFile)

		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Errorf("populate: %s for %s\n", err, statusFile)
			continue
		}
		var item interface{}
		if err := json.Unmarshal(sb, &item); err != nil {
			log.Errorf("populate: %s file: %s\n",
				err, statusFile)
			continue
		}
		pub.km.key.Store(key, item)
	}
	pub.km.restarted = foundRestarted
	log.Infof("populate(%s) done\n", name)
}

// go routine which runs the AF_UNIX server.
func (pub *Publication) publisher() {
	name := pub.nameString()
	instance := 0
	for {
		c, err := pub.listener.Accept()
		if err != nil {
			log.Errorf("publisher(%s) failed %s\n", name, err)
			continue
		}
		go pub.serveConnection(c, instance)
		instance++
	}
}

func (pub *Publication) serveConnection(s net.Conn, instance int) {
	name := pub.nameString()
	log.Infof("serveConnection(%s/%d)\n", name, instance)
	defer s.Close()

	// Track the set of keys/values we are sending to the peer
	sendToPeer := make(localCollection)
	sentRestarted := false
	// Read request
	buf := make([]byte, 65536)
	res, err := s.Read(buf)
	if err != nil {
		// Likely truncated
		log.Fatalf("serveConnection(%s/%d) read error: %v", name, instance, err)
	}
	if res == len(buf) {
		// Likely truncated
		log.Fatalf("serveConnection(%s/%d) request likely truncated\n",
			name, instance)
	}

	request := strings.Split(string(buf[0:res]), " ")
	log.Infof("serveConnection read %d: %v\n", len(request), request)
	if len(request) != 2 || request[0] != "request" || request[1] != pub.topic {
		log.Errorf("Invalid request message: %v\n", request)
		return
	}

	_, err = s.Write([]byte(fmt.Sprintf("hello %s", pub.topic)))
	if err != nil {
		log.Errorf("serveConnection(%s/%d) failed %s\n",
			name, instance, err)
		return
	}
	// Insert our notification channel before we get the initial
	// snapshot to avoid missing any updates/deletes.
	updater := make(chan notify, 1)
	updatersAdd(updater, name, instance)
	defer updatersRemove(updater)

	// Get a local snapshot of the collection and the set of keys
	// we need to send these. Updates the slave collection.
	keys := pub.determineDiffs(sendToPeer)

	// Send the keys we just determined; all since this is the initial
	err = pub.serialize(s, keys, sendToPeer)
	if err != nil {
		log.Errorf("serveConnection(%s/%d) serialize failed %s\n",
			name, instance, err)
		return
	}
	err = pub.sendComplete(s)
	if err != nil {
		log.Errorf("serveConnection(%s/%d) sendComplete failed %s\n",
			name, instance, err)
		return
	}
	if pub.km.restarted && !sentRestarted {
		err = pub.sendRestarted(s)
		if err != nil {
			log.Errorf("serveConnection(%s/%d) sendRestarted failed %s\n",
				name, instance, err)
			return
		}
		sentRestarted = true
	}

	// Handle any changes
	for {
		log.Debugf("serveConnection(%s/%d) waiting for notification\n",
			name, instance)
		startWait := time.Now()
		<-updater
		waitTime := time.Since(startWait)
		log.Debugf("serveConnection(%s/%d) received notification waited %d seconds\n",
			name, instance, waitTime/time.Second)

		// Update and determine which keys changed
		keys := pub.determineDiffs(sendToPeer)

		// Send the updates and deletes for those keys
		err = pub.serialize(s, keys, sendToPeer)
		if err != nil {
			log.Errorf("serveConnection(%s/%d) serialize failed %s\n",
				name, instance, err)
			return
		}

		if pub.km.restarted && !sentRestarted {
			err = pub.sendRestarted(s)
			if err != nil {
				log.Errorf("serveConnection(%s/%d) sendRestarted failed %s\n",
					name, instance, err)
				return
			}
			sentRestarted = true
		}
	}
}

// Returns the deleted keys before the added/modified ones
func (pub *Publication) determineDiffs(slaveCollection localCollection) []string {

	var keys []string
	name := pub.nameString()
	items := pub.GetAll()
	// Look for deleted
	for slaveKey := range slaveCollection {
		_, ok := items[slaveKey]
		if !ok {
			log.Debugf("determineDiffs(%s): key %s deleted\n",
				name, slaveKey)
			delete(slaveCollection, slaveKey)
			keys = append(keys, slaveKey)
		}

	}
	// Look for new/changed
	for masterKey, master := range items {
		slave := lookupSlave(slaveCollection, masterKey)
		if slave == nil {
			log.Debugf("determineDiffs(%s): key %s added\n",
				name, masterKey)
			// XXX is deepCopy needed?
			slaveCollection[masterKey] = deepCopy(master)
			keys = append(keys, masterKey)
		} else if !cmp.Equal(master, *slave) {
			log.Debugf("determineDiffs(%s): key %s replacing due to diff %v\n",
				name, masterKey,
				cmp.Diff(master, *slave))
			// XXX is deepCopy needed?
			slaveCollection[masterKey] = deepCopy(master)
			keys = append(keys, masterKey)
		} else {
			log.Debugf("determineDiffs(%s): key %s unchanged\n",
				name, masterKey)
		}
	}
	return keys
}

func SockName(name string) string {
	return fmt.Sprintf("/var/run/%s.sock", name)
}

func PubDirName(name string) string {
	return fmt.Sprintf("/var/run/%s", name)
}

func FixedDirName(name string) string {
	return fmt.Sprintf("%s/%s", fixedDir, name)
}

func PersistentDirName(name string) string {
	return fmt.Sprintf("%s/status/%s", "/persist", name)
}

// Init function for Subscribe; returns a context.
// Assumption is that agent with call Get(key) later or specify
// handleModify and/or handleDelete functions
// watch ensures that any restart/restarted notification is after any other
// notifications from ReadDir
func Subscribe(agentName string, topicType interface{}, activate bool,
	ctx interface{}) (*Subscription, error) {

	return subscribeImpl(agentName, "", topicType, activate, ctx, false)
}

func SubscribeScope(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}) (*Subscription, error) {

	return subscribeImpl(agentName, agentScope, topicType, activate, ctx,
		false)
}

func SubscribePersistent(agentName string, topicType interface{}, activate bool,
	ctx interface{}) (*Subscription, error) {

	return subscribeImpl(agentName, "", topicType, activate, ctx, true)
}

func subscribeImpl(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}, persistent bool) (*Subscription, error) {

	topic := TypeToName(topicType)
	changes := make(chan string)
	sub := new(Subscription)
	sub.C = changes
	sub.sendChan = changes
	sub.topicType = topicType
	sub.agentName = agentName
	sub.agentScope = agentScope
	sub.topic = topic
	sub.userCtx = ctx
	sub.km = keyMap{key: NewLockedStringMap()}
	sub.persistent = persistent
	name := sub.nameString()

	// Special case for files in /var/tmp/zededa/ and also
	// for zedclient going away yet metrics being read after it
	// is gone.
	if agentName == "" {
		sub.subscribeFromDir = true
		sub.dirName = FixedDirName(name)
	} else if agentName == "zedclient" {
		sub.subscribeFromDir = true
		sub.dirName = PubDirName(name)
	} else if persistent {
		sub.subscribeFromDir = true
		sub.dirName = PersistentDirName(name)
	} else {
		sub.subscribeFromDir = subscribeFromDir
		sub.dirName = PubDirName(name)
	}
	log.Infof("Subscribe(%s)\n", name)
	if activate {
		if err := sub.Activate(); err != nil {
			return nil, err
		}
	}
	return sub, nil
}
