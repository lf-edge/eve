// Copyright (c) 2017,2018 Zededa, Inc.
// All rights reserved.

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/zededa/go-provision/watch"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// XXX add protocol over AF_UNIX later
// "sync request", ... "update" "delete" followed by key then val
// "sync done" once all have sent
// Plus "restart" if application calls SignalRestarted()
// After end of sync (aka ReadDir processing) then look for explicit application
// restart/restarted signal.

// Maintain a collection which is used to handle the restart of a subscriber
// map of agentname, key to get a json string
type keyMap struct {
	restarted bool
	key       map[string]interface{}
}

// We always publish to our collection.
// We always write to a file in order to have a checkpoint on restart
const publishToSock = false     // XXX
const subscribeFromDir = true   // XXX
const subscribeFromSock = false // XXX

// For a subscription, if the agentName is empty we interpret that as
// being directory in /var/tmp/zededa
const fixedName = "zededa"
const fixedDir = "/var/tmp/" + fixedName

const debug = false // XXX setable?

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
}

func Publish(agentName string, topicType interface{}) (*Publication, error) {
	return publishImpl(agentName, "", topicType)
}

func PublishScope(agentName string, agentScope string, topicType interface{}) (*Publication, error) {
	return publishImpl(agentName, agentScope, topicType)
}

// Init function to create directory and socket listener based on above settings
// We read any checkpointed state from dirName and insert in pub.km as initial
// values.
func publishImpl(agentName string, agentScope string,
	topicType interface{}) (*Publication, error) {

	topic := TypeToName(topicType)
	pub := new(Publication)
	pub.topicType = topicType
	pub.agentName = agentName
	pub.agentScope = agentScope
	pub.topic = topic
	pub.km = keyMap{key: make(map[string]interface{})}
	name := pub.nameString()

	log.Printf("Publish(%s)\n", name)

	// We always write to the directory as a checkpoint
	dirName := PubDirName(name)
	if _, err := os.Stat(dirName); err != nil {
		log.Printf("Publish Create %s\n", dirName)
		if err := os.MkdirAll(dirName, 0700); err != nil {
			errStr := fmt.Sprintf("Publish(%s): %s",
				name, err)
			return nil, errors.New(errStr)
		}
	} else {
		// Read existig status from dir
		pub.populate()
		if debug {
			pub.dump("after populate")
		}
	}

	if publishToSock {
		sockName := SockName(name)
		if _, err := os.Stat(sockName); err == nil {
			if err := os.Remove(sockName); err != nil {
				errStr := fmt.Sprintf("Publish(%s): %s",
					name, err)
				return nil, errors.New(errStr)
			}
		}
		s, err := net.Listen("unix", sockName)
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
	dirName := PubDirName(name)
	foundRestarted := false

	log.Printf("populate(%s)\n", name)

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
			log.Printf("populate: File disappeared <%s>\n",
				statusFile)
			continue
		}

		log.Printf("populate found key %s file %s\n", key, statusFile)

		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Printf("populate: %s for %s\n", err, statusFile)
			continue
		}
		var item interface{}
		if err := json.Unmarshal(sb, &item); err != nil {
			log.Printf("populate: %s file: %s\n",
				err, statusFile)
			continue
		}
		pub.km.key[key] = item
	}
	pub.km.restarted = foundRestarted
	log.Printf("populate(%s) done\n", name)
}

// go routine which runs the AF_UNIX server
// XXX would need some synchronization on the accesses to the published
// collection?
func (pub *Publication) publisher() {
	name := pub.nameString()
	for {
		c, err := pub.listener.Accept()
		if err != nil {
			log.Printf("publisher(%s) failed %s\n", name, err)
			continue
		}
		go pub.serveConnection(c)
	}
}

// XXX can't close if we serve updates
func (pub *Publication) serveConnection(s net.Conn) {
	name := pub.nameString()
	log.Printf("serveConnection(%s)\n", name)
	defer s.Close()

	_, err := s.Write([]byte(fmt.Sprintf("Hello from %s\n", name)))
	if err != nil {
		log.Printf("serveConnection(%s) failed %s\n",
			name, err)
	}
	err = pub.serialize(s)
	if err != nil {
		log.Printf("serveConnection(%s) failed %s\n",
			name, err)
	}
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

func (pub *Publication) nameString() string {
	if pub.agentScope == "" {
		return fmt.Sprintf("%s/%s", pub.agentName, pub.topic)
	} else {
		return fmt.Sprintf("%s/%s/%s", pub.agentName, pub.agentScope,
			pub.topic)
	}
}

func (pub *Publication) Publish(key string, item interface{}) error {
	topic := TypeToName(item)
	name := pub.nameString()
	if topic != pub.topic {
		errStr := fmt.Sprintf("Publish(%s): item is wrong topic %s",
			name, topic)
		return errors.New(errStr)
	}
	// Perform a deepCopy so the Equal check will work
	newItem := deepCopy(item)
	if m, ok := pub.km.key[key]; ok {
		if cmp.Equal(m, newItem) {
			if debug {
				log.Printf("Publish(%s/%s) unchanged\n",
					name, key)
			}
			return nil
		}
		if debug {
			log.Printf("Publish(%s/%s) replacing due to diff %s\n",
				name, key, cmp.Diff(m, newItem))
		}
	} else if debug {
		log.Printf("Publish(%s/%s) adding %+v\n",
			name, key, newItem)
	}
	pub.km.key[key] = newItem

	if debug {
		pub.dump("after Publish")
	}
	dirName := PubDirName(name)
	fileName := dirName + "/" + key + ".json"
	if debug {
		log.Printf("Publish writing %s\n", fileName)
	}
	// XXX already did a marshal in deepCopy; save that result?
	b, err := json.Marshal(item)
	if err != nil {
		log.Fatal(err, "json Marshal in Publish")
	}
	err = WriteRename(fileName, b)
	if err != nil {
		return err
	}
	// XXX send update to all listeners - how? channel to listener -> connections?
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
		log.Fatal(err, "json Marshal in deepCopy")
	}
	var output interface{}
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in deepCopy")
	}
	return output
}

func (pub *Publication) Unpublish(key string) error {
	name := pub.nameString()
	if m, ok := pub.km.key[key]; ok {
		if debug {
			log.Printf("Unpublish(%s/%s) removing %+v\n",
				name, key, m)
		}
	} else {
		errStr := fmt.Sprintf("Unpublish(%s/%s): key does not exist",
			name, key)
		log.Printf("%s\n", errStr)
		return errors.New(errStr)
	}
	delete(pub.km.key, key)
	if debug {
		pub.dump("after Unpublish")
	}
	dirName := PubDirName(name)
	fileName := dirName + "/" + key + ".json"
	if debug {
		log.Printf("Unpublish deleting file %s\n", fileName)
	}
	if err := os.Remove(fileName); err != nil {
		errStr := fmt.Sprintf("Unpublish(%s/%s): failed %s",
			name, key, err)
		return errors.New(errStr)
	}
	// XXX send update to all listeners - how? channel to listener -> connections?
	return nil
}

func (pub *Publication) SignalRestarted() error {
	if debug {
		log.Printf("pub.SignalRestarted(%s)\n", pub.nameString())
	}
	return pub.restartImpl(true)
}

func (pub *Publication) ClearRestarted() error {
	if debug {
		log.Printf("pub.ClearRestarted(%s)\n", pub.nameString())
	}
	return pub.restartImpl(false)
}

// Record the restarted state and send over socket/file.
// XXXTBD when sending/resynchronizing send the restarted indication last
func (pub *Publication) restartImpl(restarted bool) error {
	name := pub.nameString()
	log.Printf("pub.restartImpl(%s, %v)\n", name, restarted)
	if restarted == pub.km.restarted {
		log.Printf("pub.restartImpl(%s, %v) value unchanged\n",
			name, restarted)
		return nil
	}
	pub.km.restarted = restarted

	// XXX socket case?
	// XXX send update to all listeners - how? channel to listener -> connections?
	dirName := PubDirName(name)
	restartFile := dirName + "/" + "restarted"
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

func (pub *Publication) serialize(sock net.Conn) error {
	name := pub.nameString()
	log.Printf("serialize(%s)\n", name)
	for key, s := range pub.km.key {
		b, err := json.Marshal(s)
		if err != nil {
			log.Fatal(err, "json Marshal in serialize")
		}
		_, err = sock.Write([]byte(fmt.Sprintf("key %s val %s\n", key, b)))
		if err != nil {
			log.Printf("serialize(%s) write failed %s\n",
				name, err)
			return err
		}
	}
	if pub.km.restarted {
		_, err := sock.Write([]byte(fmt.Sprintf("restarted\n")))
		if err != nil {
			log.Printf("serialize(%s) write failed %s\n",
				name, err)
			return err
		}
	}
	return nil
}

func (pub *Publication) dump(infoStr string) {
	name := pub.nameString()
	log.Printf("dump(%s) %s\n", name, infoStr)
	for key, s := range pub.km.key {
		b, err := json.Marshal(s)
		if err != nil {
			log.Fatal(err, "json Marshal in dump")
		}
		log.Printf("\tkey %s val %s\n", key, b)
	}
	log.Printf("\trestarted %t\n", name, pub.km.restarted)
}

func (pub *Publication) Get(key string) (interface{}, error) {
	m, ok := pub.km.key[key]
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
	for k, e := range pub.km.key {
		result[k] = e
	}
	return result
}

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
//     change := <- s1.C:
//         s1.ProcessChange(change, ctx)
//  }
//  The ProcessChange function calls the various handlers (if set) and updates
//  the subscribed collection. The subscribed collection can be accessed using:
//  foo := s1.Get(key)
//  fooAll := s1.GetAll()

type SubModifyHandler func(ctx interface{}, key string, status interface{})
type SubDeleteHandler func(ctx interface{}, key string, status interface{})
type SubRestartHandler func(ctx interface{}, restarted bool)

type Subscription struct {
	C              <-chan string
	ModifyHandler  SubModifyHandler
	DeleteHandler  SubDeleteHandler
	RestartHandler SubRestartHandler

	// Private fields
	sendChan   chan<- string
	topicType  interface{}
	agentName  string
	agentScope string
	topic      string
	km         keyMap
	userCtx    interface{}
	// Handle special case of file only info
	subscribeFromDir bool
	dirName          string
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

	return subscribeImpl(agentName, "", topicType, activate, ctx)
}

func SubscribeScope(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}) (*Subscription, error) {

	return subscribeImpl(agentName, agentScope, topicType, activate, ctx)
}

func subscribeImpl(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}) (*Subscription, error) {

	topic := TypeToName(topicType)
	changes := make(chan string)
	sub := new(Subscription)
	sub.C = changes
	sub.sendChan = changes
	sub.topicType = topicType
	sub.agentName = agentName
	sub.agentScope = agentScope
	sub.topic = topic
	sub.km = keyMap{key: make(map[string]interface{})}
	sub.userCtx = ctx
	name := sub.nameString()

	if agentName == "" {
		sub.subscribeFromDir = true
		sub.dirName = FixedDirName(name)
	} else {
		sub.subscribeFromDir = subscribeFromDir
		sub.dirName = PubDirName(name)
	}
	log.Printf("Subscribe(%s)\n", name)

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
				log.Println(errStr)
				time.Sleep(10 * time.Second)
			} else {
				break
			}
		}
		go watch.WatchStatus(sub.dirName, sub.sendChan)
		return nil
	} else if subscribeFromSock {
		errStr := fmt.Sprintf("subscribeFromSock not implemented")
		return errors.New(errStr)
	} else {
		errStr := fmt.Sprintf("Subscribe(%s): failed %s",
			name, "nowhere to subscribe")
		return errors.New(errStr)
	}
}

// XXX Currently only handles directory subscriptions; no AF_UNIX
func (sub *Subscription) ProcessChange(change string) {
	name := sub.nameString()
	if debug {
		log.Printf("ProcessChange(%s) %s\n", name, change)
	}
	var restartFn watch.StatusRestartHandler = handleRestart
	watch.HandleStatusEvent(change, sub,
		sub.dirName, &sub.topicType,
		handleModify, handleDelete, &restartFn)
}

func handleModify(ctxArg interface{}, key string, item interface{}) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	if debug {
		log.Printf("pubsub.handleModify(%s) key %s\n", name, key)
	}
	// NOTE: without a deepCopy we would just save a pointer since
	// item is a pointer. That would cause failures.
	newItem := deepCopy(item)
	m, ok := sub.km.key[key]
	if ok {
		if cmp.Equal(m, newItem) {
			if debug {
				log.Printf("pubsub.handleModify(%s/%s) unchanged\n",
					name, key)
			}
			return
		}
		if debug {
			log.Printf("pubsub.handleModify(%s/%s) replacing due to diff %s\n",
				name, key, cmp.Diff(m, newItem))
		}
	} else if debug {
		log.Printf("pubsub.handleModify(%s) add %+v for key %s\n",
			name, newItem, key)
	}
	sub.km.key[key] = newItem
	if debug {
		sub.dump("after handleModify")
	}
	if sub.ModifyHandler != nil {
		(sub.ModifyHandler)(sub.userCtx, key, newItem)
	}
	if debug {
		log.Printf("pubsub.handleModify(%s) done for key %s\n",
			name, key)
	}
}

func handleDelete(ctxArg interface{}, key string) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	if debug {
		log.Printf("pubsub.handleDelete(%s) key %s\n", name, key)
	}
	m, ok := sub.km.key[key]
	if !ok {
		log.Printf("pubsub.handleDelete(%s) %s key not found\n",
			name, key)
		return
	}
	if debug {
		log.Printf("pubsub.handleDelete(%s) key %s value %+v\n",
			name, key, m)
	}
	delete(sub.km.key, key)
	if debug {
		sub.dump("after handleDelete")
	}
	if sub.DeleteHandler != nil {
		(sub.DeleteHandler)(sub.userCtx, key, m)
	}
	if debug {
		log.Printf("pubsub.handleModify(%s) done for key %s\n",
			name, key)
	}
}

func handleRestart(ctxArg interface{}, restarted bool) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	if debug {
		log.Printf("pubsub.handleRestart(%s) restarted %v\n",
			name, restarted)
	}
	if restarted == sub.km.restarted {
		if debug {
			log.Printf("pubsub.handleRestart(%s) value unchanged\n",
				name)
		}
		return
	}
	sub.km.restarted = restarted
	if sub.RestartHandler != nil {
		(sub.RestartHandler)(sub.userCtx, restarted)
	}
	if debug {
		log.Printf("pubsub.handleRestart(%s) done for restarted %v\n",
			name, restarted)
	}
}

func (sub *Subscription) dump(infoStr string) {
	name := sub.nameString()
	log.Printf("dump(%s) %s\n", name, infoStr)
	for key, s := range sub.km.key {
		b, err := json.Marshal(s)
		if err != nil {
			log.Fatal(err, "json Marshal in dump")
		}
		log.Printf("\tkey %s val %s\n", key, b)
	}
	log.Printf("\trestarted %t\n", name, sub.km.restarted)
}

func (sub *Subscription) Get(key string) (interface{}, error) {
	m, ok := sub.km.key[key]
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
	for k, e := range sub.km.key {
		result[k] = e
	}
	return result
}
