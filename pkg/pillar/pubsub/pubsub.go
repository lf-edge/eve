// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"fmt"
	"reflect"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

// SubscriptionOptions options to pass when creating a Subscription
type SubscriptionOptions struct {
	CreateHandler  SubHandler
	ModifyHandler  SubHandler
	DeleteHandler  SubHandler
	RestartHandler SubRestartHandler
	SyncHandler    SubRestartHandler
	WarningTime    time.Duration
	ErrorTime      time.Duration
	AgentName      string
	AgentScope     string
	TopicImpl      interface{}
	Activate       bool
	Ctx            interface{}
	Persistent     bool
	MyAgentName    string // For logging
}

// SubHandler is a generic handler to handle create, modify and delete
// Usage:
//  s1 := pubsublegacy.Subscribe("foo", fooStruct{}, true, &myctx)
// Or
//  s1 := pubsublegacy.Subscribe("foo", fooStruct{}, false, &myctx)
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

// SubRestartHandler generic handler for restarts
type SubRestartHandler func(ctx interface{}, restarted bool)

// Maintain a collection which is used to handle the restart of a subscriber
// map of agentname, key to get a json string
// We use StringMap with a RWlock to allow concurrent access.
type keyMap struct {
	restarted bool
	key       *base.LockedStringMap
}

// PubSub is a system for publishing and subscribing to messages
// it manages the creation of Publication and Subscription, which handle the actual
// implementation of in-memory structures and logic
// the message passing and persistence are handled by a Driver.
// Should not be called directly. Instead use the `New()` function.
type PubSub struct {
	driver      Driver
	updaterList *Updaters
	log         *base.LogObject
}

// New create a new `PubSub` with a given `Driver`.
func New(driver Driver, logObj *base.LogObject) *PubSub {
	return &PubSub{
		driver: driver,
		log:    logObj,
	}
}

// methods unique to this implementation

// NewSubscription creates a new Subscription with given options
func (p *PubSub) NewSubscription(options SubscriptionOptions) (Subscription, error) {

	if options.TopicImpl == nil {
		return nil, fmt.Errorf("cannot create a subcription with a nil "+
			" topicImpl. options: %+v", options)
	}

	topic := TypeToName(options.TopicImpl)
	topicType := reflect.TypeOf(options.TopicImpl)
	changes := make(chan Change)
	sub := &SubscriptionImpl{
		C:                   changes,
		agentName:           options.AgentName,
		agentScope:          options.AgentScope,
		topic:               topic,
		topicType:           topicType,
		userCtx:             options.Ctx,
		km:                  keyMap{key: base.NewLockedStringMap()},
		defaultName:         p.driver.DefaultName(),
		CreateHandler:       options.CreateHandler,
		ModifyHandler:       options.ModifyHandler,
		DeleteHandler:       options.DeleteHandler,
		RestartHandler:      options.RestartHandler,
		SynchronizedHandler: options.SyncHandler,
		MaxProcessTimeWarn:  options.WarningTime,
		MaxProcessTimeError: options.ErrorTime,
		Persistent:          options.Persistent,
		log:                 p.log,
		myAgentName:         options.MyAgentName,
		ps:                  p,
	}
	name := sub.nameString()
	global := options.AgentName == ""
	driver, err := p.driver.Subscriber(global, name, topic, options.Persistent, changes)
	if err != nil {
		return sub, err
	}
	sub.driver = driver

	sub.log.Infof("Subscribe(%s)\n", name)
	if options.Activate {
		if err := sub.Activate(); err != nil {
			return sub, err
		}
	}
	return sub, nil
}

// publishImpl init function to create directory and socket listener based on above settings
// We read any checkpointed state from dirName and insert in pub.km as initial
// values.

// PublicationOptions defines all the possible options a new publication may have
type PublicationOptions struct {
	AgentName  string
	AgentScope string
	TopicType  interface{}
	Persistent bool
}

// NewPublication creates a new Publication with given options
func (p *PubSub) NewPublication(options PublicationOptions) (Publication, error) {
	if options.TopicType == nil {
		return nil, fmt.Errorf("cannot create a publication with a nil "+
			"topic type. options: %+v", options)
	}

	topic := TypeToName(options.TopicType)
	// ensure the updaterlist is populated. This is the only place we consume it,
	//  so fine to set it here
	if p.updaterList == nil {
		p.updaterList = &Updaters{}
	}
	pub := &PublicationImpl{
		agentName:   options.AgentName,
		agentScope:  options.AgentScope,
		topic:       topic,
		topicType:   reflect.TypeOf(options.TopicType),
		km:          keyMap{key: base.NewLockedStringMap()},
		updaterList: p.updaterList,
		defaultName: p.driver.DefaultName(),
		log:         p.log,
	}
	// create the driver
	name := pub.nameString()
	global := options.AgentName == ""
	pub.log.Debugf("publishImpl agentName(%s), agentScope(%s), topic(%s), nameString(%s), global(%v), persistent(%v)\n",
		options.AgentName, options.AgentScope, topic, name, global, options.Persistent)
	driver, err := p.driver.Publisher(global, name, topic, options.Persistent, p.updaterList, pub, pub)
	if err != nil {
		return pub, err
	}
	pub.driver = driver

	pub.populate()
	// XXX logger vs. event question
	if logrus.GetLevel() == logrus.DebugLevel {
		pub.dump("after populate")
	}
	pub.log.Debugf("Publish(%s)\n", name)

	pub.publisher()

	return pub, nil
}
