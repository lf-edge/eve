// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

const (
	// Global fixed string for a global subject, i.e. no agent
	Global = "global"
)

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
//
//	Publication interface.
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
	persistent  bool
	logger      *logrus.Logger
	log         *base.LogObject

	driver DriverPublisher
}

// published is what a publication holds for a key: the item, which Iterate
// hands out, and the value subscribers are sent, from which Get makes
// copies.
type published struct {
	item  interface{}
	value *Value
}

// IsRestarted has this publication been set to "restarted"
func (pub *PublicationImpl) IsRestarted() bool {
	return pub.km.restartCounter.Load() != 0
}

// RestartCounter number of times this this publication been set to "restarted"
func (pub *PublicationImpl) RestartCounter() int {
	return int(pub.km.restartCounter.Load())
}

// CheckMaxSize returns an error if the item is too large and would result
// in a fatal if it was published
func (pub *PublicationImpl) CheckMaxSize(key string, item interface{}) error {
	topic := TypeToName(item)
	name := pub.nameString()
	if topic != pub.topic {
		errStr := fmt.Sprintf("CheckMaxSize(%s): item is wrong topic %s",
			name, topic)
		pub.log.Fatalln(errStr)
	}
	val := reflect.ValueOf(item)
	if val.Kind() == reflect.Ptr {
		pub.log.Fatalf("CheckMaxSize got a pointer for %s", name)
	}
	// marshal to json bytes to send to the driver
	b, err := json.Marshal(item)
	if err != nil {
		pub.log.Fatal("json Marshal in CheckMaxSize", err)
	}
	PublicationStats(name).AllocMarshal.Add(len(b))
	return pub.driver.CheckMaxSize(key, b)
}

// Publish publish a key-value pair
func (pub *PublicationImpl) Publish(key string, item interface{}) error {
	topic := TypeToName(item)
	name := pub.nameString()
	if topic != pub.topic {
		errStr := fmt.Sprintf("Publish(%s): item is wrong topic %s",
			name, topic)
		pub.log.Fatalln(errStr)
	}
	val := reflect.ValueOf(item)
	if val.Kind() == reflect.Ptr {
		pub.log.Fatalf("Publish got a pointer for %s", name)
	}
	// The JSON is what is checkpointed and sent to every subscriber. An
	// item which marshals to the JSON published is unchanged; so is one
	// equal to the item published by the Equal methods of its type.
	b, err := json.Marshal(item)
	if err != nil {
		pub.log.Fatal("json Marshal in Publish", err)
	}
	PublicationStats(name).AllocMarshal.Add(len(b))
	old, ok := pub.load(key)
	if ok && bytes.Equal(old.value.JSON, b) {
		pub.log.Tracef("Publish(%s/%s) unchanged\n", name, key)
		return nil
	}
	// Keep a copy, made from the JSON, in case the caller changes a map etc.
	newItem := pub.decode(b, reflect.TypeOf(item))
	if ok && cmp.Equal(old.item, newItem) {
		pub.log.Tracef("Publish(%s/%s) unchanged\n", name, key)
		return nil
	}
	// Refuse a value which does not fit in a message before it is stored or
	// checkpointed: sending it would fail on every connection, and after
	// every reboot if checkpointed.
	if err := pub.driver.CheckMaxSize(key, b); err != nil {
		PublicationStats(name).Refused.Add(1)
		pub.log.Errorf("Publish(%s/%s) refused: %v", name, key, err)
		return err
	}
	if ok {
		// DO NOT log Values. They may contain sensitive information.
		pub.log.Tracef("Publish(%s/%s) replacing due to diff\n",
			name, key)

		loggable, ok := newItem.(base.LoggableObject)
		if ok {
			loggable.LogModify(pub.log, old.item)
		}
	} else {
		// DO NOT log Values. They may contain sensitive information.
		pub.log.Tracef("Publish(%s/%s) adding Item", name, key)
		loggable, ok := newItem.(base.LoggableObject)
		if ok {
			loggable.LogCreate(pub.log)
		}
	}
	pub.km.key.Store(key, &published{item: newItem, value: &Value{JSON: b}})

	if pub.logger.GetLevel() == logrus.TraceLevel {
		pub.dump("after Publish")
	}
	pub.updatersNotify(name)
	return pub.driver.Publish(key, b)
}

// Unpublish delete a key from the key-value map
func (pub *PublicationImpl) Unpublish(key string) error {
	name := pub.nameString()
	if p, ok := pub.load(key); ok {
		// DO NOT log Values. They may contain sensitive information.
		pub.log.Tracef("Unpublish(%s/%s) removing Item", name, key)
		loggable, ok := p.item.(base.LoggableObject)
		if ok {
			loggable.LogDelete(pub.log)
		}
	} else {
		errStr := fmt.Sprintf("Unpublish(%s/%s): key does not exist",
			name, key)
		pub.log.Errorf("%s\n", errStr)
		return errors.New(errStr)
	}
	pub.km.key.Delete(key)
	if pub.logger.GetLevel() == logrus.TraceLevel {
		pub.dump("after Unpublish")
	}
	pub.updatersNotify(name)

	return pub.driver.Unpublish(key)
}

// SignalRestarted signal that a publication is restarted one more time
func (pub *PublicationImpl) SignalRestarted() error {
	pub.log.Tracef("pub.SignalRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(true)
}

// ClearRestarted clear the restart signal
func (pub *PublicationImpl) ClearRestarted() error {
	pub.log.Tracef("pub.ClearRestarted(%s)\n", pub.nameString())
	return pub.restartImpl(false)
}

// Get returns a copy of the item of a given key.
func (pub *PublicationImpl) Get(key string) (interface{}, error) {
	p, ok := pub.load(key)
	if !ok {
		name := pub.nameString()
		errStr := fmt.Sprintf("Get(%s) unknown key %s", name, key)
		return nil, errors.New(errStr)
	}
	return pub.copyOf(p), nil
}

// GetAll returns a copy of every item, by key.
func (pub *PublicationImpl) GetAll() map[string]interface{} {
	all := make(map[string]*published)
	pub.km.key.Range(func(key string, val interface{}) bool {
		all[key] = val.(*published)
		return true
	})
	result := make(map[string]interface{}, len(all))
	for key, p := range all {
		result[key] = pub.copyOf(p)
	}
	return result
}

// Iterate - performs some callback function on all items
func (pub *PublicationImpl) Iterate(function base.StrMapFunc) {
	pub.km.key.Range(func(key string, val interface{}) bool {
		return function(key, val.(*published).item)
	})
}

// Close the publisher
func (pub *PublicationImpl) Close() error {
	var keys []string
	pub.km.key.Range(func(key string, _ interface{}) bool {
		keys = append(keys, key)
		return true
	})
	if !pub.persistent {
		for _, key := range keys {
			pub.log.Functionf("Close(%s) unloading key %s",
				pub.nameString(), key)
			pub.Unpublish(key)
		}
	}
	pub.ClearRestarted()
	pub.driver.Stop()
	return nil
}

// methods just for this implementation of Publisher

func (pub *PublicationImpl) load(key string) (*published, bool) {
	p, ok := pub.km.key.Load(key)
	if !ok {
		return nil, false
	}
	return p.(*published), true
}

// decode returns a new item of type t decoded from b.
func (pub *PublicationImpl) decode(b []byte, t reflect.Type) interface{} {
	item, err := parseTemplate(pub.log, b, t)
	if err != nil {
		pub.log.Fatalf("json Unmarshal of %s: %v", pub.nameString(), err)
	}
	return item
}

// copyOf returns a copy of the item of p, decoded from its JSON.
func (pub *PublicationImpl) copyOf(p *published) interface{} {
	return pub.decode(p.value.JSON, reflect.TypeOf(p.item))
}

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
			pub.log.Tracef("updaterNotify sent to %s/%d\n",
				nn.name, nn.instance)
		default:
			pub.log.Tracef("updaterNotify NOT sent to %s/%d\n",
				nn.name, nn.instance)
		}
	}
	pub.updaterList.lock.Unlock()
}

// Only reads json files. Sets restarted if that file was found and contains
// an integer
func (pub *PublicationImpl) populate() {
	name := pub.nameString()

	pub.log.Tracef("populate(%s)\n", name)

	pairs, restartCounter, err := pub.driver.Load()
	if err != nil {
		// Could be a truncated or empty file
		pub.log.Error(err)
		return
	}
	for key, itemB := range pairs {
		item, err := parseTemplate(pub.log, itemB, pub.topicType)
		if err != nil {
			// Handle bad files such as those of size zero
			pub.log.Error(err)
			continue
		}
		// Send the item as this version of its type marshals it, not as
		// the checkpoint, maybe of an older version, has it.
		b, err := json.Marshal(item)
		if err != nil {
			pub.log.Fatal("json Marshal in populate", err)
		}
		PublicationStats(name).AllocMarshal.Add(len(b))
		pub.km.key.Store(key, &published{item: item, value: &Value{JSON: b}})
	}
	pub.km.restartCounter.Store(int64(restartCounter))
	pub.log.Tracef("populate(%s) done\n", name)
}

// go routine which runs the AF_UNIX server.
func (pub *PublicationImpl) publisher() {
	pub.driver.Start()
}

// DetermineDiffs updates a provided LocalCollection to the current state,
// and returns the deleted keys before the added/modified ones. A key is
// modified if its Value is not the one in the collection: every Publish
// which changes a key makes a new Value, so nothing is marshalled or
// compared here, and every collection holds the same Values.
func (pub *PublicationImpl) DetermineDiffs(localCollection LocalCollection) []string {
	var deleted, changed []string
	current := 0
	pub.km.key.Range(func(key string, val interface{}) bool {
		current++
		value := val.(*published).value
		if localCollection[key] != value {
			localCollection[key] = value
			changed = append(changed, key)
		}
		return true
	})
	// The collection now holds every current key, so it holds more only if
	// some were deleted.
	if len(localCollection) > current {
		for key := range localCollection {
			if _, ok := pub.km.key.Load(key); !ok {
				delete(localCollection, key)
				deleted = append(deleted, key)
			}
		}
	}
	return append(deleted, changed...)
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
	pub.log.Functionf("pub.restartImpl(%s, %v)\n", name, restarted)
	var restartCounter int64
	if restarted {
		restartCounter = pub.km.restartCounter.Load() + 1
	} else {
		restartCounter = 0
	}

	if restartCounter == pub.km.restartCounter.Load() {
		pub.log.Functionf("pub.restartImpl(%s, %v) value unchanged\n",
			name, restarted)
		return nil
	}
	pub.km.restartCounter.Store(restartCounter)
	// XXX lock on restarted to make sure it gets noticed?
	// XXX bug?
	// Implicit in updaters lock??
	pub.updatersNotify(name)
	return pub.driver.Restart(int(restartCounter))
}

func (pub *PublicationImpl) dump(infoStr string) {

	name := pub.nameString()
	pub.log.Tracef("dump(%s) %s\n", name, infoStr)
	dumper := func(key string, _ interface{}) bool {
		// DO NOT log Values. They may contain sensitive information.
		pub.log.Tracef("\tkey %s", key)
		return true
	}
	pub.km.key.Range(dumper)
	pub.log.Tracef("\trestarted %d", pub.km.restartCounter.Load())
}
