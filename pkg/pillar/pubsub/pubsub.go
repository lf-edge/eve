// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/watch"
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
const publishToSock = true     // XXX
const subscribeFromDir = false // XXX
const subscribeFromSock = true // XXX

// For a subscription, if the agentName is empty we interpret that as
// being directory in /var/tmp/zededa
const fixedName = "zededa"
const fixedDir = "/var/tmp/" + fixedName

type notify struct{}

// The set of channels to which we need to send notifications
type updaters struct {
	lock    sync.Mutex
	servers []notifyName
}

type notifyName struct {
	name     string // From pub.nameString()
	instance int
	ch       chan<- notify
}

var updaterList updaters

func updatersAdd(updater chan notify, name string, instance int) {
	updaterList.lock.Lock()
	nn := notifyName{name: name, instance: instance, ch: updater}
	updaterList.servers = append(updaterList.servers, nn)
	updaterList.lock.Unlock()
}

func updatersRemove(updater chan notify) {
	updaterList.lock.Lock()
	servers := make([]notifyName, len(updaterList.servers))
	found := false
	for _, old := range updaterList.servers {
		if old.ch == updater {
			found = true
		} else {
			servers = append(servers, old)
		}
	}
	if !found {
		log.Fatal("updatersRemove: not found\n")
	}
	updaterList.servers = servers
	updaterList.lock.Unlock()
}

// Send a notification to all the matching channels which does not yet
// have one queued.
func (pub *Publication) updatersNotify(name string) {
	updaterList.lock.Lock()
	for _, nn := range updaterList.servers {
		if nn.name != name {
			continue
		}
		select {
		case nn.ch <- notify{}:
			log.Debugf("updaterNotify sent to %s/%d\n",
				nn.name, nn.instance)
		default:
			log.Debugf("updaterNotify NOT sent to %s/%d\n",
				nn.name, nn.instance)
		}
	}
	updaterList.lock.Unlock()
}

// Usage:
//  p1, err := pubsub.Publish("foo", fooStruct{})
//  ...
//  // Optional
//  p1.SignalRestarted()
//  ...
//  p1.Publish(key, item)
//  p1.Unpublish(key) to delete
//
//  foo := p1.Get(key)
//  fooAll := p1.GetAll()

type Publication struct {
	// Private fields
	topicType  interface{}
	agentName  string
	agentScope string
	topic      string
	km         keyMap
	sockName   string
	listener   net.Listener

	publishToDir bool // Handle special case of file only info
	dirName      string
	persistent   bool
}

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
		pub.dirName = PersistentDirName(name)
	} else {
		pub.dirName = PubDirName(name)
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
		// Read existig status from dir
		pub.populate()
		if log.GetLevel() == log.DebugLevel {
			pub.dump("after populate")
		}
	}

	if publishToSock {
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

// Used locally by each serverConnection goroutine to track updates
// to send.
type localCollection map[string]interface{}

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

func lookupSlave(slaveCollection localCollection, key string) *interface{} {
	for slaveKey := range slaveCollection {
		if slaveKey == key {
			res := slaveCollection[slaveKey]
			return &res
		}
	}
	return nil
}

func TypeToName(something interface{}) string {
	t := reflect.TypeOf(something)
	out := strings.Split(t.String(), ".")
	return out[len(out)-1]
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
	return fmt.Sprintf("/persist/status/%s", name)
}

func (pub *Publication) nameString() string {
	if pub.publishToDir {
		return pub.dirName
	} else if pub.agentScope == "" {
		return fmt.Sprintf("%s/%s", pub.agentName, pub.topic)
	} else {
		return fmt.Sprintf("%s/%s/%s", pub.agentName, pub.agentScope,
			pub.topic)
	}
}

// One shot create directory and publish one key in that directory
func PublishToDir(dirName string, key string, item interface{}) error {
	topic := TypeToName(item)
	pub := new(Publication)
	pub.topicType = item
	pub.topic = topic
	pub.km = keyMap{key: NewLockedStringMap()}
	dirName = fmt.Sprintf("%s/%s", dirName, pub.topic)
	pub.dirName = dirName
	pub.publishToDir = true
	name := pub.nameString()

	if _, err := os.Stat(dirName); err != nil {
		log.Infof("PublishToDir Create %s\n", dirName)
		if err := os.MkdirAll(dirName, 0700); err != nil {
			errStr := fmt.Sprintf("Publish(%s): %s",
				name, err)
			return errors.New(errStr)
		}
	}
	return pub.Publish(key, item)
}

func (pub *Publication) Publish(key string, item interface{}) error {
	topic := TypeToName(item)
	name := pub.nameString()
	if topic != pub.topic {
		errStr := fmt.Sprintf("Publish(%s): item is wrong topic %s",
			name, topic)
		log.Fatalln(errStr)
	}
	// Perform a deepCopy so the Equal check will work
	newItem := deepCopy(item)
	if m, ok := pub.km.key.Load(key); ok {
		if cmp.Equal(m, newItem) {
			log.Debugf("Publish(%s/%s) unchanged\n", name, key)
			return nil
		}
		log.Debugf("Publish(%s/%s) replacing due to diff %s\n",
			name, key, cmp.Diff(m, newItem))
	} else {
		log.Debugf("Publish(%s/%s) adding %+v\n", name, key, newItem)
	}
	pub.km.key.Store(key, newItem)

	if log.GetLevel() == log.DebugLevel {
		pub.dump("after Publish")
	}
	pub.updatersNotify(name)

	fileName := pub.dirName + "/" + key + ".json"
	log.Debugf("Publish writing %s\n", fileName)

	// XXX already did a marshal in deepCopy; save that result?
	b, err := json.Marshal(item)
	if err != nil {
		log.Fatal("json Marshal in Publish", err)
	}
	err = WriteRename(fileName, b)
	if err != nil {
		return err
	}
	return nil
}

func WriteRename(fileName string, b []byte) error {
	dirName := filepath.Dir(fileName)
	// Do atomic rename to avoid partially written files
	tmpfile, err := ioutil.TempFile(dirName, "pubsub")
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(b)
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	if err := tmpfile.Close(); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	if err := os.Rename(tmpfile.Name(), fileName); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	return nil
}

func deepCopy(in interface{}) interface{} {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal("json Marshal in deepCopy", err)
	}
	var output interface{}
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in deepCopy")
	}
	return output
}

func (pub *Publication) Unpublish(key string) error {
	name := pub.nameString()
	if m, ok := pub.km.key.Load(key); ok {
		log.Debugf("Unpublish(%s/%s) removing %+v\n", name, key, m)
	} else {
		errStr := fmt.Sprintf("Unpublish(%s/%s): key does not exist",
			name, key)
		log.Errorf("%s\n", errStr)
		return errors.New(errStr)
	}
	pub.km.key.Delete(key)
	if log.GetLevel() == log.DebugLevel {
		pub.dump("after Unpublish")
	}
	pub.updatersNotify(name)

	fileName := pub.dirName + "/" + key + ".json"
	log.Debugf("Unpublish deleting file %s\n", fileName)
	if err := os.Remove(fileName); err != nil {
		errStr := fmt.Sprintf("Unpublish(%s/%s): failed %s",
			name, key, err)
		return errors.New(errStr)
	}
	return nil
}

func (pub *Publication) SignalRestarted() error {
	log.Debugf("pub.SignalRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(true)
}

func (pub *Publication) ClearRestarted() error {
	log.Debugf("pub.ClearRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(false)
}

// Record the restarted state and send over socket/file.
func (pub *Publication) restartImpl(restarted bool) error {

	name := pub.nameString()
	log.Debugf("pub.restartImpl(%s, %v)\n", name, restarted)

	if restarted == pub.km.restarted {
		log.Debugf("pub.restartImpl(%s, %v) value unchanged\n",
			name, restarted)
		return nil
	}
	pub.km.restarted = restarted
	if restarted {
		// XXX lock on restarted to make sure it gets noticed?
		// Implicit in updaters lock??
		pub.updatersNotify(name)
	}

	restartFile := pub.dirName + "/" + "restarted"
	if restarted {
		f, err := os.OpenFile(restartFile, os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			errStr := fmt.Sprintf("pub.restartImpl(%s): openfile failed %s",
				name, err)
			return errors.New(errStr)
		}
		f.Close()
	} else {
		if err := os.Remove(restartFile); err != nil {
			errStr := fmt.Sprintf("pub.restartImpl(%s): remove failed %s",
				name, err)
			return errors.New(errStr)
		}
	}
	return nil
}

func (pub *Publication) serialize(sock net.Conn, keys []string,
	sendToPeer localCollection) error {

	name := pub.nameString()
	log.Debugf("serialize(%s, %v)\n", name, keys)

	for _, key := range keys {
		val, ok := sendToPeer[key]
		if ok {
			err := pub.sendUpdate(sock, key, val)
			if err != nil {
				log.Errorf("serialize(%s) sendUpdate failed %s\n",
					name, err)
				return err
			}
		} else {
			err := pub.sendDelete(sock, key)
			if err != nil {
				log.Errorf("serialize(%s) sendDelete failed %s\n",
					name, err)
				return err
			}
		}
	}
	return nil
}

func (pub *Publication) sendUpdate(sock net.Conn, key string,
	val interface{}) error {

	log.Debugf("sendUpdate(%s): key %s\n", pub.nameString(), key)
	b, err := json.Marshal(val)
	if err != nil {
		log.Fatal("json Marshal in sendUpdate", err)
	}
	// base64-encode to avoid having spaces in the key and val
	sendKey := base64.StdEncoding.EncodeToString([]byte(key))
	sendVal := base64.StdEncoding.EncodeToString(b)
	_, err = sock.Write([]byte(fmt.Sprintf("update %s %s %s",
		pub.topic, sendKey, sendVal)))
	return err
}

func (pub *Publication) sendDelete(sock net.Conn, key string) error {

	log.Debugf("sendDelete(%s): key %s\n", pub.nameString(), key)
	// base64-encode to avoid having spaces in the key
	sendKey := base64.StdEncoding.EncodeToString([]byte(key))
	_, err := sock.Write([]byte(fmt.Sprintf("delete %s %s",
		pub.topic, sendKey)))
	return err
}

func (pub *Publication) sendRestarted(sock net.Conn) error {

	log.Debugf("sendRestarted(%s)\n", pub.nameString())
	_, err := sock.Write([]byte(fmt.Sprintf("restarted %s", pub.topic)))
	return err
}

func (pub *Publication) sendComplete(sock net.Conn) error {

	log.Debugf("sendComplete(%s)\n", pub.nameString())
	_, err := sock.Write([]byte(fmt.Sprintf("complete %s", pub.topic)))
	return err
}

func (pub *Publication) dump(infoStr string) {

	name := pub.nameString()
	log.Debugf("dump(%s) %s\n", name, infoStr)
	dumper := func(key string, val interface{}) bool {
		b, err := json.Marshal(val)
		if err != nil {
			log.Fatal("json Marshal in dump", err)
		}
		log.Debugf("\tkey %s val %s\n", key, b)
		return true
	}
	pub.km.key.Range(dumper)
	log.Debugf("\trestarted %t\n", pub.km.restarted)
}

func (pub *Publication) Get(key string) (interface{}, error) {
	m, ok := pub.km.key.Load(key)
	if ok {
		return m, nil
	} else {
		name := pub.nameString()
		errStr := fmt.Sprintf("Get(%s) unknown key %s", name, key)
		return nil, errors.New(errStr)
	}
}

// Enumerate all the key, value for the collection
func (pub *Publication) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	assigner := func(key string, val interface{}) bool {
		result[key] = val
		return true
	}
	pub.km.key.Range(assigner)
	return result
}

// SubHandler is a generic handler to handle create, modify and delete
// Usage:
//  s1 := pubsub.Subscribe("foo", fooStruct{}, true, &myctx)
// Or
//  s1 := pubsub.Subscribe("foo", fooStruct{}, false, &myctx)
//  s1.ModifyHandler = func(...), // Optional
//  s1.DeleteHandler = func(...), // Optional
//  s1.RestartHandler = func(...), // Optional
//  [ Initialize myctx ]
//  s1.Activate()
//  ...
//  select {
//     case change := <- s1.C:
//         s1.ProcessChange(change, ctx)
//  }
//  The ProcessChange function calls the various handlers (if set) and updates
//  the subscribed collection. The subscribed collection can be accessed using:
//  foo := s1.Get(key)
//  fooAll := s1.GetAll()
// SubHandler is a generic handler to handle create, modify and delete
type SubHandler func(ctx interface{}, key string, status interface{})
type SubRestartHandler func(ctx interface{}, restarted bool)

type Subscription struct {
	C                   <-chan string
	CreateHandler       SubHandler
	ModifyHandler       SubHandler
	DeleteHandler       SubHandler
	RestartHandler      SubRestartHandler
	SynchronizedHandler SubRestartHandler

	// Private fields
	sendChan   chan<- string
	topicType  interface{}
	agentName  string
	agentScope string
	topic      string
	km         keyMap
	userCtx    interface{}
	sock       net.Conn // For socket subscriptions

	synchronized     bool
	subscribeFromDir bool // Handle special case of file only info
	dirName          string
	persistent       bool
}

func (sub *Subscription) nameString() string {
	agentName := sub.agentName
	if agentName == "" {
		agentName = fixedName
	}
	if sub.agentScope == "" {
		return fmt.Sprintf("%s/%s", sub.agentName, sub.topic)
	} else {
		return fmt.Sprintf("%s/%s/%s", sub.agentName, sub.agentScope,
			sub.topic)
	}
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

// If the agentName is empty we interpret that as being dir /var/tmp/zededa
func (sub *Subscription) Activate() error {

	name := sub.nameString()
	if sub.subscribeFromDir {
		// Waiting for directory to appear
		for {
			if _, err := os.Stat(sub.dirName); err != nil {
				errStr := fmt.Sprintf("Subscribe(%s): failed %s; waiting",
					name, err)
				log.Errorln(errStr)
				time.Sleep(10 * time.Second)
			} else {
				break
			}
		}
		go watch.WatchStatus(sub.dirName, true, sub.sendChan)
		return nil
	} else if subscribeFromSock {
		go sub.watchSock()
		return nil
	} else {
		errStr := fmt.Sprintf("Subscribe(%s): failed %s",
			name, "nowhere to subscribe")
		return errors.New(errStr)
	}
}

func (sub *Subscription) watchSock() {

	for {
		msg, key, val := sub.connectAndRead()
		switch msg {
		case "hello":
			// Do nothing
		case "complete":
			// XXX to handle restart we need to handle "complete"
			// by doing a sweep across the KeyMap to handleDelete
			// what we didn't see before the "complete"
			sub.sendChan <- "C done"

		case "restarted":
			sub.sendChan <- "R done"

		case "delete":
			sub.sendChan <- "D " + key

		case "update":
			// XXX is size of val any issue? pointer?
			sub.sendChan <- "M " + key + " " + val
		}
	}
}

// Returns msg, key, val
// key and val are base64-encoded
func (sub *Subscription) connectAndRead() (string, string, string) {

	name := sub.nameString()
	sockName := SockName(name)
	buf := make([]byte, 65536)

	// Waiting for publisher to appear; retry on error
	for {
		if sub.sock == nil {
			s, err := net.Dial("unixpacket", sockName)
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): Dial failed %s",
					name, err)
				log.Warnln(errStr)
				time.Sleep(10 * time.Second)
				continue
			}
			sub.sock = s
			req := fmt.Sprintf("request %s", sub.topic)
			_, err = s.Write([]byte(req))
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): sock write failed %s",
					name, err)
				log.Errorln(errStr)
				sub.sock.Close()
				sub.sock = nil
				continue
			}
		}

		res, err := sub.sock.Read(buf)
		if err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s): sock read failed %s",
				name, err)
			log.Errorln(errStr)
			sub.sock.Close()
			sub.sock = nil
			continue
		}

		if res == len(buf) {
			// Likely truncated
			log.Fatalf("connectAndRead(%s) request likely truncated\n",
				name)
		}
		reply := strings.Split(string(buf[0:res]), " ")
		count := len(reply)
		if count < 2 {
			errStr := fmt.Sprintf("connectAndRead(%s): too short read",
				name)
			log.Errorln(errStr)
			continue
		}
		msg := reply[0]
		t := reply[1]

		if t != sub.topic {
			errStr := fmt.Sprintf("connectAndRead(%s): mismatched topic %s vs. %s for %s",
				name, t, sub.topic, msg)
			log.Errorln(errStr)
			// XXX continue
		}

		// XXX are there error cases where we should Close and
		// continue aka reconnect?
		switch msg {
		case "hello", "restarted", "complete":
			log.Debugf("connectAndRead(%s) Got message %s type %s\n",
				name, msg, t)
			return msg, "", ""

		case "delete":
			if count < 3 {
				errStr := fmt.Sprintf("connectAndRead(%s): too short delete",
					name)
				log.Errorln(errStr)
				continue
			}
			recvKey := reply[2]

			if log.GetLevel() == log.DebugLevel {
				key, err := base64.StdEncoding.DecodeString(recvKey)
				if err != nil {
					errStr := fmt.Sprintf("connectAndRead(%s): base64 failed %s",
						name, err)
					log.Errorln(errStr)
					continue
				}
				log.Debugf("connectAndRead(%s): delete type %s key %s\n",
					name, t, string(key))
			}
			return msg, recvKey, ""

		case "update":
			if count < 4 {
				errStr := fmt.Sprintf("connectAndRead(%s): too short update",
					name)
				log.Errorln(errStr)
				continue
			}
			if count > 4 {
				errStr := fmt.Sprintf("connectAndRead(%s): too long update",
					name)
				log.Errorln(errStr)
				continue
			}
			recvKey := reply[2]
			recvVal := reply[3]
			if log.GetLevel() == log.DebugLevel {
				key, err := base64.StdEncoding.DecodeString(recvKey)
				if err != nil {
					errStr := fmt.Sprintf("connectAndRead(%s): base64 failed %s",
						name, err)
					log.Errorln(errStr)
					continue
				}
				val, err := base64.StdEncoding.DecodeString(recvVal)
				if err != nil {
					errStr := fmt.Sprintf("connectAndRead(%s): base64 val failed %s",
						name, err)
					log.Errorln(errStr)
					continue
				}
				log.Debugf("connectAndRead(%s): update type %s key %s val %s\n",
					name, t, string(key), string(val))
			}
			return msg, recvKey, recvVal

		default:
			errStr := fmt.Sprintf("connectAndRead(%s): unknown message %s",
				name, msg)
			log.Errorln(errStr)
			continue
		}
	}
}

// We handle both subscribeFromDir and subscribeFromSock
// Note that change filename includes .json for subscribeFromDir. That
// is removed by HandleStatusEvent.
func (sub *Subscription) ProcessChange(change string) {

	if sub.subscribeFromDir {
		var restartFn watch.StatusRestartHandler = handleRestart
		var completeFn watch.StatusRestartHandler = handleSynchronized
		watch.HandleStatusEvent(change, sub,
			sub.dirName, &sub.topicType,
			handleModify, handleDelete, &restartFn,
			&completeFn)
	} else if subscribeFromSock {
		name := sub.nameString()
		reply := strings.Split(change, " ")
		operation := reply[0]

		switch operation {
		case "C":
			handleSynchronized(sub, true)
		case "R":
			handleRestart(sub, true)
		case "D":
			recvKey := reply[1]
			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				errStr := fmt.Sprintf("ProcessChange(%s): base64 failed %s",
					name, err)
				log.Errorln(errStr)
				return
			}
			handleDelete(sub, string(key))

		case "M":
			recvKey := reply[1]
			recvVal := reply[2]
			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				errStr := fmt.Sprintf("ProcessChange(%s): base64 failed %s",
					name, err)
				log.Errorln(errStr)
				return
			}
			val, err := base64.StdEncoding.DecodeString(recvVal)
			if err != nil {
				errStr := fmt.Sprintf("ProcessChange(%s): base64 val failed %s",
					name, err)
				log.Errorln(errStr)
				return
			}
			var output interface{}
			if err := json.Unmarshal(val, &output); err != nil {
				errStr := fmt.Sprintf("ProcessChange(%s): json failed %s",
					name, err)
				log.Errorln(errStr)
				return
			}
			handleModify(sub, string(key), output)
		}
	} else {
		// Enforced in Subscribe()
		log.Fatal("ProcessChange: neither subscribeFromDir nor subscribeFromSock")
	}
}

func handleModify(ctxArg interface{}, key string, item interface{}) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	log.Debugf("pubsub.handleModify(%s) key %s\n", name, key)
	// NOTE: without a deepCopy we would just save a pointer since
	// item is a pointer. That would cause failures.
	newItem := deepCopy(item)
	m, ok := sub.km.key.Load(key)
	if ok {
		if cmp.Equal(m, newItem) {
			log.Debugf("pubsub.handleModify(%s/%s) unchanged\n",
				name, key)
			return
		}
		log.Debugf("pubsub.handleModify(%s/%s) replacing due to diff %s\n",
			name, key, cmp.Diff(m, newItem))
	} else {
		log.Debugf("pubsub.handleModify(%s) add %+v for key %s\n",
			name, newItem, key)
	}
	sub.km.key.Store(key, newItem)
	if log.GetLevel() == log.DebugLevel {
		sub.dump("after handleModify")
	}
	if sub.CreateHandler != nil {
		(sub.CreateHandler)(sub.userCtx, key, newItem)
	} else if sub.ModifyHandler != nil {
		(sub.ModifyHandler)(sub.userCtx, key, newItem)
	}
	log.Debugf("pubsub.handleModify(%s) done for key %s\n", name, key)
}

func handleDelete(ctxArg interface{}, key string) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	log.Debugf("pubsub.handleDelete(%s) key %s\n", name, key)

	m, ok := sub.km.key.Load(key)
	if !ok {
		log.Errorf("pubsub.handleDelete(%s) %s key not found\n",
			name, key)
		return
	}
	log.Debugf("pubsub.handleDelete(%s) key %s value %+v\n",
		name, key, m)
	sub.km.key.Delete(key)
	if log.GetLevel() == log.DebugLevel {
		sub.dump("after handleDelete")
	}
	if sub.DeleteHandler != nil {
		(sub.DeleteHandler)(sub.userCtx, key, m)
	}
	log.Debugf("pubsub.handleDelete(%s) done for key %s\n", name, key)
}

func handleRestart(ctxArg interface{}, restarted bool) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	log.Debugf("pubsub.handleRestart(%s) restarted %v\n", name, restarted)
	if restarted == sub.km.restarted {
		log.Debugf("pubsub.handleRestart(%s) value unchanged\n", name)
		return
	}
	sub.km.restarted = restarted
	if sub.RestartHandler != nil {
		(sub.RestartHandler)(sub.userCtx, restarted)
	}
	log.Debugf("pubsub.handleRestart(%s) done for restarted %v\n",
		name, restarted)
}

func handleSynchronized(ctxArg interface{}, synchronized bool) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	log.Debugf("pubsub.handleSynchronized(%s) synchronized %v\n", name, synchronized)
	if synchronized == sub.synchronized {
		log.Debugf("pubsub.handleSynchronized(%s) value unchanged\n", name)
		return
	}
	sub.synchronized = synchronized
	if sub.SynchronizedHandler != nil {
		(sub.SynchronizedHandler)(sub.userCtx, synchronized)
	}
	log.Debugf("pubsub.handleSynchronized(%s) done for synchronized %v\n",
		name, synchronized)
}

func (sub *Subscription) dump(infoStr string) {
	name := sub.nameString()
	log.Debugf("dump(%s) %s\n", name, infoStr)
	dumper := func(key string, val interface{}) bool {
		b, err := json.Marshal(val)
		if err != nil {
			log.Fatal("json Marshal in dump", err)
		}
		log.Debugf("\tkey %s val %s\n", key, b)
		return true
	}
	sub.km.key.Range(dumper)
	log.Debugf("\trestarted %t\n", sub.km.restarted)
	log.Debugf("\tsynchronized %t\n", sub.synchronized)
}

func (sub *Subscription) Get(key string) (interface{}, error) {
	m, ok := sub.km.key.Load(key)
	if ok {
		return m, nil
	} else {
		name := sub.nameString()
		errStr := fmt.Sprintf("Get(%s) unknown key %s", name, key)
		return nil, errors.New(errStr)
	}
}

// Enumerate all the key, value for the collection
func (sub *Subscription) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	assigner := func(key string, val interface{}) bool {
		result[key] = val
		return true
	}
	sub.km.key.Range(assigner)
	return result
}

func (sub *Subscription) Restarted() bool {
	return sub.km.restarted
}

func (sub *Subscription) Synchronized() bool {
	return sub.synchronized
}
