// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	log "github.com/sirupsen/logrus"
)

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
type SubHandler func(ctx interface{}, key string, status interface{})
type SubRestartHandler func(ctx interface{}, restarted bool)

// Maintain a collection which is used to handle the restart of a subscriber
// map of agentname, key to get a json string
// We use StringMap with a RWlock to allow concurrent access.
type keyMap struct {
	restarted bool
	key       *LockedStringMap
}

// PubSub is a system for publishing and subscribing to messages
// it manages the creation of Publication and Subscription, which handle the actual
// implementation of in-memory structures and logic
// the message passing and persistence are handled by a Driver
type PubSub struct {
	driver      Driver
	updaterList *Updaters
}

func New(driver Driver) *PubSub {
	return &PubSub{
		driver: driver,
	}
}

func (p *PubSub) Publish(agentName string, topicType interface{}) (Publication, error) {
	return p.publishImpl(agentName, "", topicType, false)
}

func (p *PubSub) PublishPersistent(agentName string, topicType interface{}) (Publication, error) {
	return p.publishImpl(agentName, "", topicType, true)
}

func (p *PubSub) PublishScope(agentName string, agentScope string, topicType interface{}) (Publication, error) {
	return p.publishImpl(agentName, agentScope, topicType, false)
}

func (p *PubSub) Subscribe(agentName string, topicType interface{}, activate bool,
	ctx interface{}) (Subscription, error) {
	return p.subscribeImpl(agentName, "", topicType, activate, ctx, false)
}

func (p *PubSub) SubscribeScope(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}) (Subscription, error) {
	return p.subscribeImpl(agentName, agentScope, topicType, activate, ctx,
		false)
}

func (p *PubSub) SubscribePersistent(agentName string, topicType interface{}, activate bool,
	ctx interface{}) (Subscription, error) {
	return p.subscribeImpl(agentName, "", topicType, activate, ctx, true)
}

// methods unique to this implementation

func (p *PubSub) subscribeImpl(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}, persistent bool) (Subscription, error) {

	topic := TypeToName(topicType)
	changes := make(chan Change)
	sub := Subscription{
		C:          changes,
		agentName:  agentName,
		agentScope: agentScope,
		topic:      topic,
		userCtx:    ctx,
		km:         keyMap{key: NewLockedStringMap()},
	}
	name := sub.nameString()
	global := agentName == ""
	driver, err := p.driver.Subscriber(global, name, topic, persistent, changes)
	if err != nil {
		return sub, err
	}
	sub.driver = driver

	log.Infof("Subscribe(%s)\n", name)
	if activate {
		if err := sub.Activate(); err != nil {
			return sub, err
		}
	}
	return sub, nil
}

// Init function to create directory and socket listener based on above settings
// We read any checkpointed state from dirName and insert in pub.km as initial
// values.
func (p *PubSub) publishImpl(agentName string, agentScope string,
	topicType interface{}, persistent bool) (Publication, error) {

	topic := TypeToName(topicType)
	// ensure the updaterlist is populated. This is the only place we consume it,
	//  so fine to set it here
	if p.updaterList == nil {
		p.updaterList = &Updaters{}
	}
	pub := Publication{
		agentName:   agentName,
		agentScope:  agentScope,
		topic:       topic,
		km:          keyMap{key: NewLockedStringMap()},
		updaterList: p.updaterList,
	}
	// create the driver
	name := pub.nameString()
	global := agentName == ""
	driver, err := p.driver.Publisher(global, name, topic, persistent, p.updaterList, &pub, &pub)
	if err != nil {
		return pub, err
	}
	pub.driver = driver

	pub.populate()
	if log.GetLevel() == log.DebugLevel {
		pub.dump("after populate")
	}
	log.Infof("Publish(%s)\n", name)

	pub.publisher()

	return pub, nil
}
