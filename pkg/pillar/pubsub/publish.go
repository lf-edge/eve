package pubsub

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

const (
	// Global fixed string for a global subject, i.e. no agent
	Global = "global"
)

// LocalCollection represents an entire local copy of a set of key-value pairs
type LocalCollection map[string][]byte

// Notify simple struct to pass notification messages
type Notify struct{}

// Publication to publish to an individual topic
// Usage:
//  p1, err := pubsublegacy.Publish("foo", fooStruct{})
//  ...
//  // Optional
//  p1.SignalRestarted()
//  ...
//  p1.Publish(key, item)
//  p1.Unpublish(key) to delete
//
//  foo := p1.Get(key)
//  fooAll := p1.GetAll()

// PublicationImpl - Publication Implementation. The main structure that implements
//  Publication interface.
type PublicationImpl struct {
	// Private fields
	topicType   reflect.Type
	agentName   string
	agentScope  string
	topic       string
	km          keyMap
	global      bool
	defaultName string
	updaterList *Updaters

	driver DriverPublisher
}

// IsRestarted has this publication been set to "restarted"
func (pub *PublicationImpl) IsRestarted() bool {
	return pub.km.restarted
}

// Publish publish a key-value pair
func (pub *PublicationImpl) Publish(key string, item interface{}) error {
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
	// Perform a deepCopy in case the caller might change a map etc
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
	// marshal to json bytes to send to the driver
	b, err := json.Marshal(item)
	if err != nil {
		log.Fatal("json Marshal in socketdriver Publish", err)
	}

	return pub.driver.Publish(key, b)
}

// Unpublish delete a key from the key-value map
func (pub *PublicationImpl) Unpublish(key string) error {
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

	return pub.driver.Unpublish(key)
}

// SignalRestarted signal that a publication is restarted
func (pub *PublicationImpl) SignalRestarted() error {
	log.Debugf("pub.SignalRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(true)
}

// ClearRestarted clear the restart signal
func (pub *PublicationImpl) ClearRestarted() error {
	log.Debugf("pub.ClearRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(false)
}

// Get the value for a given key
func (pub *PublicationImpl) Get(key string) (interface{}, error) {
	m, ok := pub.km.key.Load(key)
	if ok {
		return m, nil
	} else {
		name := pub.nameString()
		errStr := fmt.Sprintf("Get(%s) unknown key %s", name, key)
		return nil, errors.New(errStr)
	}
}

// GetAll enumerate all the key-value pairs for the collection
func (pub *PublicationImpl) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	assigner := func(key string, val interface{}) bool {
		result[key] = val
		return true
	}
	pub.km.key.Range(assigner)
	return result
}

// methods just for this implementation of Publisher

// updatersNotify send a notification to all the matching channels which does not yet
// have one queued.
func (pub *PublicationImpl) updatersNotify(name string) {
	pub.updaterList.lock.Lock()
	for _, nn := range pub.updaterList.servers {
		if nn.name != name {
			continue
		}
		select {
		case nn.ch <- Notify{}:
			log.Debugf("updaterNotify sent to %s/%d\n",
				nn.name, nn.instance)
		default:
			log.Debugf("updaterNotify NOT sent to %s/%d\n",
				nn.name, nn.instance)
		}
	}
	pub.updaterList.lock.Unlock()
}

// Only reads json files. Sets restarted if that file was found.
func (pub *PublicationImpl) populate() {
	name := pub.nameString()

	log.Infof("populate(%s)\n", name)

	pairs, restarted, err := pub.driver.Load()
	if err != nil {
		log.Fatalf(err.Error())
	}
	for key, itemB := range pairs {
		item, err := parseTemplate(itemB, pub.topicType)
		if err != nil {
			log.Fatalf(err.Error())
			return
		}
		pub.km.key.Store(key, item)
	}
	pub.km.restarted = restarted
	log.Infof("populate(%s) done\n", name)
}

// go routine which runs the AF_UNIX server.
func (pub *PublicationImpl) publisher() {
	pub.driver.Start()
}

// DetermineDiffs update a provided LocalCollection to the current state,
// and return the deleted keys before the added/modified ones
func (pub *PublicationImpl) DetermineDiffs(slaveCollection LocalCollection) []string {
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
		masterb, err := json.Marshal(master)
		if err != nil {
			log.Fatalf("json Marshal in DetermineDiffs for master key %s: %v", masterKey, err)
		}

		slave := lookupSlave(slaveCollection, masterKey)
		if slave == nil {
			log.Debugf("determineDiffs(%s): key %s added\n",
				name, masterKey)
			slaveCollection[masterKey] = masterb
			keys = append(keys, masterKey)
		} else if bytes.Compare(masterb, slave) != 0 {
			log.Debugf("determineDiffs(%s): key %s replacing due to diff\n",
				name, masterKey)
			// XXX is deepCopy needed?
			slaveCollection[masterKey] = masterb
			keys = append(keys, masterKey)
		} else {
			log.Debugf("determineDiffs(%s): key %s unchanged\n",
				name, masterKey)
		}
	}
	return keys
}

func (pub *PublicationImpl) nameString() string {
	var name string
	switch {
	case pub.global:
		name = Global
	case pub.agentScope == "":
		name = fmt.Sprintf("%s/%s", pub.agentName, pub.topic)
	default:
		name = fmt.Sprintf("%s/%s/%s", pub.agentName, pub.agentScope, pub.topic)
	}
	return name
}

// Record the restarted state and send over socket/file.
func (pub *PublicationImpl) restartImpl(restarted bool) error {
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
	return pub.driver.Restart(restarted)
}

func (pub *PublicationImpl) dump(infoStr string) {

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
