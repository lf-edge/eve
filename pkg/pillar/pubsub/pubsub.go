// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"fmt"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
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
	key       *LockedStringMap
}

// PubSub is a system for publishing and subscribing to messages
// it manages the creation of Publication and Subscription, which handle the actual
// implementation of in-memory structures and logic
// the message passing and persistence are handled by a Driver.
// Should not be called directly. Instead use the `New()` function.
type PubSub struct {
	driver      Driver
	updaterList *Updaters
}

// PublicationOptions defines all the possible options a new publication may have
type PublicationOptions struct {
	AgentName  string
	AgentScope string
	TopicType  interface{}
	Persistent bool
}

// NewPublication creates a new publication with given options
func (p *PubSub) Publication(options PublicationOptions) (Publication, error) {
	if options.AgentScope != "" && options.Persistent == true {
		return nil, fmt.Errorf("cannot create a persitent publication with a scope agentName %s", options.AgentName)
	}
	if options.AgentName == "" {
		return nil, fmt.Errorf("cannot create a publication with a nil agentName")
	}
	if options.TopicType == nil {
		return nil, fmt.Errorf("cannot create a publication with a nil topic type")
	}
	return p.publishImpl(options.AgentName, options.AgentScope, options.TopicType, options.Persistent)
}

// New create a new `PubSub` with a given `Driver`.
func New(driver Driver) *PubSub {
	return &PubSub{
		driver: driver,
	}
}

// Publish create a `Publication` for the given agent name and topic type.
func (p *PubSub) Publish(agentName string, topicType interface{}) (Publication, error) {
	return p.publishImpl(agentName, "", topicType, false)
}

// PublishPersistent create a `Publication` for the given agent name and topic
// type, but with persistence of the messages across reboots.
func (p *PubSub) PublishPersistent(agentName string, topicType interface{}) (Publication, error) {
	return p.publishImpl(agentName, "", topicType, true)
}

// PublishScope create a `Publication` for the given agent name and topic,
// restricted to a given scope.
func (p *PubSub) PublishScope(agentName string, agentScope string, topicType interface{}) (Publication, error) {
	return p.publishImpl(agentName, agentScope, topicType, false)
}

// Subscribe create a subscription for the given agent name and topic
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func (p *PubSub) Subscribe(agentName string, topicType interface{}, activate bool,
	ctx interface{}, options *SubscriptionOptions) (Subscription, error) {
	return p.subscribeImpl(agentName, "", topicType, activate, ctx, false, options)
}

// SubscribeScope create a subscription for the given agent name and topic,
// limited to a given scope,
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func (p *PubSub) SubscribeScope(agentName string, agentScope string, topicType interface{},
	activate bool, ctx interface{}, options *SubscriptionOptions) (Subscription, error) {
	return p.subscribeImpl(agentName, agentScope, topicType, activate, ctx,
		false, options)
}

// SubscribePersistent create a subscription for the given agent name and topic,
// persistent,
// optionally activating immediately. If `activate` is set to `false`
// (the default), then the subscription will not begin to send messages
// on the channel or process them until `Subscription.Start()` is called.
func (p *PubSub) SubscribePersistent(agentName string, topicType interface{}, activate bool,
	ctx interface{}, options *SubscriptionOptions) (Subscription, error) {
	return p.subscribeImpl(agentName, "", topicType, activate, ctx, true, options)
}

// methods unique to this implementation

func (p *PubSub) subscribeImpl(agentName string, agentScope string, topicImpl interface{},
	activate bool, ctx interface{}, persistent bool, options *SubscriptionOptions) (Subscription, error) {

	topic := TypeToName(topicImpl)
	topicType := reflect.TypeOf(topicImpl)
	changes := make(chan Change)
	sub := &SubscriptionImpl{
		C:           changes,
		agentName:   agentName,
		agentScope:  agentScope,
		topic:       topic,
		topicType:   topicType,
		userCtx:     ctx,
		km:          keyMap{key: NewLockedStringMap()},
		defaultName: p.driver.DefaultName(),
	}
	if options != nil {
		sub.CreateHandler = options.CreateHandler
		sub.ModifyHandler = options.ModifyHandler
		sub.DeleteHandler = options.DeleteHandler
		sub.RestartHandler = options.RestartHandler
		sub.SynchronizedHandler = options.SyncHandler
		sub.MaxProcessTimeWarn = options.WarningTime
		sub.MaxProcessTimeError = options.ErrorTime
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

// publishImpl init function to create directory and socket listener based on above settings
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
	pub := &PublicationImpl{
		agentName:   agentName,
		agentScope:  agentScope,
		topic:       topic,
		topicType:   reflect.TypeOf(topicType),
		km:          keyMap{key: NewLockedStringMap()},
		updaterList: p.updaterList,
		defaultName: p.driver.DefaultName(),
	}
	// create the driver
	name := pub.nameString()
	global := agentName == ""
	log.Infof("publishImpl agentName(%s), agentScope(%s), topic(%s), nameString(%s), global(%v), persistent(%v)\n", agentName, agentScope, topic, name, global, persistent)
	driver, err := p.driver.Publisher(global, name, topic, persistent, p.updaterList, pub, pub)
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
