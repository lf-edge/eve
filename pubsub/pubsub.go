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
)

// XXX what do we need for restart/restarted?
// XXX add functions; xxx vs. a key called "restart" and "restarted"? Would allow "global"?
// XXX how to structure to have config and status? Matters for create vs. modify
// notifications. Should we put that in a layer on top if the pubsub?

// XXX add protocol over AF_UNIX later
// "sync request", ... "update" "delete" followed by key then val
// "sync done" once all have sent

// Maintain a collection which is used to handle the restart of a subscriber
// map of agentname, key to get a json string
type keyMap struct {
	// XXX restarted bool
	key map[string]interface{}
}

// We always publish to our collection.
// XXX always need to write directory to have a checkpoint on
// XXX restart; need to read restart content in Publish?
const publishToSock = false     // XXX
const subscribeFromDir = true   // XXX
const subscribeFromSock = false // XXX

const debug = false // XXX setable?

// Usage:
//  p1, err := pubsub.Publish("foo", fooStruct{})
//  ...
//  p1.Publish(key, item)
//  p1.Unpublish(key) to delete
//
//  foo := p1.Get(key)
//  fooAll := p1.GetAll()

type publication struct {
	// Private fields
	topicType interface{}
	agentName string
	agentScope string // XXX objType
	topic     string
	km        keyMap
	sockName  string
	listener  net.Listener
}

// Init function to create directory and socket listener based on above settings
// XXX should read current state from dirName and insert in pub.km as initial
// values.
// XXX add agentScope aka objType
func Publish(agentName string, topicType interface{}) (*publication, error) {
	topic := TypeToName(topicType)
	log.Printf("Publish(%s, %s)\n", agentName, topic)
	// We always write to the directory as a checkpoint
	dirName := PubDirName(agentName, topic)
	if _, err := os.Stat(dirName); err != nil {
		log.Printf("Publish Create %s\n", dirName)
		if err := os.MkdirAll(dirName, 0700); err != nil {
			errStr := fmt.Sprintf("Publish(%s, %s): %s",
				agentName, topic, err)
			return nil, errors.New(errStr)
		}
	}
	pub := new(publication)
	pub.topicType = topicType
	pub.agentName = agentName
	pub.topic = topic
	pub.km = keyMap{key: make(map[string]interface{})}

	if publishToSock {
		sockName := SockName(agentName, topic)
		if _, err := os.Stat(sockName); err == nil {
			if err := os.Remove(sockName); err != nil {
				errStr := fmt.Sprintf("Publish(%s, %s): %s",
					agentName, topic, err)
				return nil, errors.New(errStr)
			}
		}
		s, err := net.Listen("unix", sockName)
		if err != nil {
			errStr := fmt.Sprintf("Publish(%s, %s): %s",
				agentName, topic, err)
			return nil, errors.New(errStr)
		}
		pub.sockName = sockName
		pub.listener = s
		go pub.publisher()
	}
	return pub, nil
}

// go routine which runs the AF_UNIX server
// XXX would need some synchronization on the accesses to the published
// collection?
func (pub *publication) publisher() {
	for {
		c, err := pub.listener.Accept()
		if err != nil {
			log.Printf("publisher:", err)
			continue
		}
		go pub.serveConnection(c)
	}
}

// XXX can't close if we serve updates
func (pub *publication) serveConnection(s net.Conn) {
	agentName := pub.agentName
	topic := pub.topic
	log.Printf("serveConnection(%s, %s)\n", agentName, topic)
	defer s.Close()

	_, err := s.Write([]byte(fmt.Sprintf("Hello from %s for %s\n", agentName, topic)))
	if err != nil {
		log.Printf("serveConnection:", err)
	}
	err = pub.serialize(s)
	if err != nil {
		log.Printf("serveConnection:", err)
	}
}

func TypeToName(something interface{}) string {
	t := reflect.TypeOf(something)
	out := strings.Split(t.String(), ".")
	return out[len(out)-1]
}

// XXX add agentScope aka objType
func SockName(agentName string, topic string) string {
	return fmt.Sprintf("/var/run/%s/%s.sock", agentName, topic)
}

// XXX add agentScope aka objType
func PubDirName(agentName string, topic string) string {
	return fmt.Sprintf("/var/run/%s/%s", agentName, topic)
}

func (pub *publication) Publish(key string, item interface{}) error {
	agentName := pub.agentName
	topic := TypeToName(item)
	if topic != pub.topic {
		// XXX add agentScope aka objType
		errStr := fmt.Sprintf("Publish(%s, %s): item is topic %s",
			agentName, pub.topic, topic)
		return errors.New(errStr)
	}
	if m, ok := pub.km.key[key]; ok {
		// XXX fails to equal on e.g., /var/run/downloader/metricsMap/global.json
		if cmp.Equal(m, item) {
			if debug {
				log.Printf("Publish(%s, %s, %s) unchanged\n",
					agentName, topic, key)
			}
			return nil
		}
		if debug {
			log.Printf("Publish(%s, %s, %s) replacing due to diff %s\n",
				agentName, topic, key, cmp.Diff(m, item))
		}
	} else if debug {
		log.Printf("Publish(%s, %s, %s) adding %v\n",
			agentName, topic, key, item)
	}
	// Perform a deep copy so the above Equal check will work
	pub.km.key[key] = deepCopy(item)
	if debug {
		pub.dump("after Publish")
	}
	dirName := PubDirName(agentName, topic)
	fileName := dirName + "/" + key + ".json"
	if debug {
		log.Printf("Publish writing %s\n", fileName)
	}
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

func (pub *publication) Unpublish(key string) error {
	agentName := pub.agentName
	topic := pub.topic
	if m, ok := pub.km.key[key]; ok {
		if debug {
			log.Printf("Unpublish(%s, %s, %s) removing %v\n",
				agentName, topic, key, m)
		}
	} else {
		// XXX add agentScope aka objType
		errStr := fmt.Sprintf("Unpublish(%s, %s): key %s does not exist",
			agentName, pub.topic, key)
		log.Printf("XXX %s\n", errStr)
		return errors.New(errStr)
	}
	delete(pub.km.key, key)
	if debug {
		pub.dump("after Unpublish")
	}
	dirName := PubDirName(agentName, topic)
	fileName := dirName + "/" + key + ".json"
	if debug {
		log.Printf("Unpublish deleting %s\n", fileName)
	}
	if err := os.Remove(fileName); err != nil {
		// XXX add agentScope aka objType
		errStr := fmt.Sprintf("Publish(%s, %s): %s",
			agentName, pub.topic, err)
		return errors.New(errStr)
	}
	// XXX send update to all listeners - how? channel to listener -> connections?
	return nil
}

func (pub *publication) serialize(sock net.Conn) error {
	log.Printf("serialize for %s/%s\n", pub.agentName, pub.topic)
	for key, s := range pub.km.key {
		b, err := json.Marshal(s)
		if err != nil {
			log.Fatal(err, "json Marshal in serialize")
		}
		_, err = sock.Write([]byte(fmt.Sprintf("key %s val %s\n", key, b)))
		if err != nil {
			log.Printf("serialize write failed %s\n", err)
			return err
		}
	}
	return nil
}

func (pub *publication) dump(infoStr string) {
	log.Printf("dump for %s/%s %s\n", pub.agentName, pub.topic, infoStr)
	for key, s := range pub.km.key {
		b, err := json.Marshal(s)
		if err != nil {
			log.Fatal(err, "json Marshal in dump")
		}
		log.Printf("key %s val %s\n", key, b)
	}
}

// XXX add agentScope aka objType
func (pub *publication) Get(key string) (interface{}, error) {
	m, ok := pub.km.key[key]
	if ok {
		return m, nil
	} else {
		errStr := fmt.Sprintf("Unknown key %s for %s/%s", key,
			pub.agentName, pub.topic)
		return nil, errors.New(errStr)
	}
}

// XXX add agentScope aka objType
// Enumerate all the key, value for the collection
func (pub *publication) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	for k, e := range pub.km.key {
		result[k] = e
	}
	return result
}

// Usage:
//  s1 := pubsub.Subscribe("foo", fooStruct{})
//  s1.ModifyHandler = func(...) // Optional
//  select {
//     change := <- s1.C:
//         s1.ProcessChange(change, ctx)
//  }
//  foo := s1.Get(key) // Optional
//  fooAll := s1.GetAll()

type SubModifyHandler func(ctx interface{}, key string, status interface{})
type SubDeleteHandler func(ctx interface{}, key string)
type SubRestartHandler func(ctx interface{}, restarted bool) // XXX needed?

type subscription struct {
	C             <-chan string
	ModifyHandler *SubModifyHandler
	DeleteHandler *SubDeleteHandler

	// Private fields
	topicType interface{}
	agentName string
	// XXX add agentScope aka objType
	topic     string
	km        keyMap
	userCtx   interface{}
}

// Init function for Subscribe; returns a context.
// Assumption is that agent with call Get(key) later or specify
// handleModify and/or handleDelete functions
// XXX separate function to subscribe to diffs i.e. WatchConfigStatus?
// Layer above this pubsub? Wapper to do px.Get(key) and compare?
// XXX add agentScope aka objType
func Subscribe(agentName string, topicType interface{}, ctx interface{}) (*subscription, error) {
	topic := TypeToName(topicType)
	log.Printf("Subscribe(%s, %s)\n", agentName, topic)
	if subscribeFromDir {
		// XXX TBD add waiting for directory to appear?
		dirName := PubDirName(agentName, topic)
		if _, err := os.Stat(dirName); err != nil {
			// XXX add agentScope aka objType
			errStr := fmt.Sprintf("Subscribe(%s, %s): %s",
				agentName, topic, err)
			return nil, errors.New(errStr)
		}
		changes := make(chan string)
		sub := new(subscription)
		sub.C = changes
		sub.topicType = topicType
		sub.agentName = agentName
		sub.topic = topic
		sub.km = keyMap{key: make(map[string]interface{})}
		sub.userCtx = ctx
		go watch.WatchStatus(dirName, changes)
		return sub, nil
	} else if subscribeFromSock {
		errStr := fmt.Sprintf("subscribeFromSock not implemented")
		return nil, errors.New(errStr)
	} else {
		// XXX add agentScope aka objType
		errStr := fmt.Sprintf("Subscribe(%s, %s): %s",
			agentName, topic, "nowhere to subscribe")
		return nil, errors.New(errStr)
	}
	return nil, nil
}

// XXX Currently only handles directory subscriptions; no AF_UNIX
func (sub *subscription) ProcessChange(change string) {
	if debug {
		log.Printf("ProcessEvent %s\n", change)
	}
	dirName := PubDirName(sub.agentName, sub.topic)
	watch.HandleStatusEvent(change, sub,
		dirName, &sub.topicType,
		handleModify, handleDelete, nil)
}

// XXX note that we could add a CreateHandler since we know if we've already
// read it. Is that different than the handleConfigStatus notion of create??
func handleModify(ctxArg interface{}, key string, stateArg interface{}) {
	if debug {
		log.Printf("handleModify for %s\n", key)
	}
	sub := ctxArg.(*subscription)
	m, ok := sub.km.key[key]
	// XXX if debug; need json encode to get readable output
	if debug {
		if ok {
			log.Printf("Replace %v with %v for key %s\n",
				m, stateArg, key)
		} else {
			log.Printf("Add %v for key %s\n", stateArg, key)
		}
	}
	// Note that the stateArg was created by the caller hence no
	// need for a deep copy
	sub.km.key[key] = stateArg
	if sub.ModifyHandler != nil {
		(*sub.ModifyHandler)(sub.userCtx, key, stateArg)
	}
	if debug {
		log.Printf("handleModify done for %s\n", key)
	}
}

func handleDelete(ctxArg interface{}, key string) {
	sub := ctxArg.(*subscription)
	m, ok := sub.km.key[key]
	if !ok {
		log.Printf("XXX Delete not found for key %s\n", key)
		return
	}
	if debug {
		log.Printf("Delete key %s value %v\n", key, m)
	}
	delete(sub.km.key, key)
	if sub.DeleteHandler != nil {
		(*sub.DeleteHandler)(sub.userCtx, key)
	}
}

// XXX add agentScope aka objType
func (sub *subscription) Get(key string) (interface{}, error) {
	m, ok := sub.km.key[key]
	if ok {
		return m, nil
	} else {
		errStr := fmt.Sprintf("Unknown key %s for %s/%s", key,
			sub.agentName, sub.topic)
		return nil, errors.New(errStr)
	}
}

// XXX add agentScope aka objType
// Enumerate all the key, value for the collection
func (sub *subscription) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	for k, e := range sub.km.key {
		result[k] = e
	}
	return result
}
