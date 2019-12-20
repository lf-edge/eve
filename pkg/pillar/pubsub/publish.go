package pubsub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

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

// Publish publish an item on a given key
func (pub *Publication) Publish(key string, item interface{}) error {
	topic := TypeToName(item)
	name := pub.nameString()
	if topic != pub.topic {
		errStr := fmt.Sprintf("Publish(%s): item is wrong topic %s",
			name, topic)
		log.Fatalln(errStr)
	}
	val := reflect.ValueOf(item)
	if val.Kind() == reflect.Ptr {
		log.Fatalf("Publish got a pointer for %s", name)
	}
	// XXX how can we make sure caller doesn't change ... maps etc
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

// Unpublish unpublish the value at a given key
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

// SignalRestarted signal that a publication is restarted
func (pub *Publication) SignalRestarted() error {
	log.Debugf("pub.SignalRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(true)
}

// ClearRestarted clear the restart signal
func (pub *Publication) ClearRestarted() error {
	log.Debugf("pub.ClearRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(false)
}

// Record the restarted state and send over socket/file.
func (pub *Publication) restartImpl(restarted bool) error {

	name := pub.nameString()
	log.Infof("pub.restartImpl(%s, %v)\n", name, restarted)

	if restarted == pub.km.restarted {
		log.Infof("pub.restartImpl(%s, %v) value unchanged\n",
			name, restarted)
		return nil
	}
	pub.km.restarted = restarted
	if restarted {
		// XXX lock on restarted to make sure it gets noticed?
		// XXX bug?
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
	buf := fmt.Sprintf("update %s %s %s", pub.topic, sendKey, sendVal)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s key %s",
			len(buf), pub.nameString(), pub.topic, key)
	}
	_, err = sock.Write([]byte(buf))
	return err
}

func (pub *Publication) sendDelete(sock net.Conn, key string) error {

	log.Debugf("sendDelete(%s): key %s\n", pub.nameString(), key)
	// base64-encode to avoid having spaces in the key
	sendKey := base64.StdEncoding.EncodeToString([]byte(key))
	buf := fmt.Sprintf("delete %s %s", pub.topic, sendKey)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s key %s",
			len(buf), pub.nameString(), pub.topic, key)
	}
	_, err := sock.Write([]byte(buf))
	return err
}

func (pub *Publication) sendRestarted(sock net.Conn) error {

	log.Infof("sendRestarted(%s)\n", pub.nameString())
	buf := fmt.Sprintf("restarted %s", pub.topic)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s",
			len(buf), pub.nameString(), pub.topic)
	}
	_, err := sock.Write([]byte(buf))
	return err
}

func (pub *Publication) sendComplete(sock net.Conn) error {

	log.Infof("sendComplete(%s)\n", pub.nameString())
	buf := fmt.Sprintf("complete %s", pub.topic)
	if len(buf) >= maxsize {
		log.Fatalf("Too large message (%d bytes) sent to %s topic %s",
			len(buf), pub.nameString(), pub.topic)
	}
	_, err := sock.Write([]byte(buf))
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

// Get get the value for a specific key
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

// GetAll enumerate all the key, value for the collection
func (pub *Publication) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	assigner := func(key string, val interface{}) bool {
		result[key] = val
		return true
	}
	pub.km.key.Range(assigner)
	return result
}

// Topic returns the string definiting the topic
func (pub *Publication) Topic() string {
	return pub.topic
}
