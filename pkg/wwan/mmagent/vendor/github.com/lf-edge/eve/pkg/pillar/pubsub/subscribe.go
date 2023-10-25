package pubsub

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

// SubscriptionImpl handle a subscription to a single agent+topic, optionally scope
// as well. Never should be instantiated directly. Rather, call
// `PubSub.Subscribe*`
type SubscriptionImpl struct {
	C                   <-chan Change
	CreateHandler       SubCreateHandler
	ModifyHandler       SubModifyHandler
	DeleteHandler       SubDeleteHandler
	RestartHandler      SubRestartHandler
	SynchronizedHandler SubSyncHandler
	MaxProcessTimeWarn  time.Duration // If set generate warning if ProcessChange
	MaxProcessTimeError time.Duration // If set generate warning if ProcessChange
	Persistent          bool

	// Private fields
	agentName    string
	agentScope   string
	topic        string
	topicType    reflect.Type
	km           keyMap
	userCtx      interface{}
	synchronized bool
	driver       DriverSubscriber
	defaultName  string
	logger       *logrus.Logger
	log          *base.LogObject
	myAgentName  string // For logging
	ps           *PubSub
}

// MsgChan return the Message Channel for the Subscription.
func (sub *SubscriptionImpl) MsgChan() <-chan Change {
	return sub.C
}

// Activate starts the subscription
func (sub *SubscriptionImpl) Activate() error {
	if sub.Persistent {
		sub.populate()
	}
	return sub.driver.Start()
}

// Close stops the subscription and removes the content
func (sub *SubscriptionImpl) Close() error {
	sub.driver.Stop()
	items := sub.GetAll()
	for key := range items {
		sub.log.Functionf("Close(%s) unloading key %s",
			sub.nameString(), key)
		handleDelete(sub, key)
	}
	handleRestart(sub, 0)
	handleSynchronized(sub, false)
	return nil
}

// populate is used when activating a persistent subscription to read
// from the json files. This ensures that even if the publisher hasn't started
// yet, the subscriber will be notified with the initial content.
// This sets restartCounter if the restarted file exists and contains an integer.
// Note that this directly calls handleModify thus unlike subsequent
// changes the agent's handler will be called without going through
// a select on the MsgChan and ProcessChange call.
// Subsequent information from the publisher will be compared in handleModfy
// to avoid spurious notifications to the agent.
// XXX can we miss a handleDelete call if the file is deleted after we load?
// Need for a mark and then sweep when handleSynchronized is called?
func (sub *SubscriptionImpl) populate() {
	name := sub.nameString()

	sub.log.Functionf("populate(%s)", name)

	pairs, restartCounter, err := sub.driver.Load()
	if err != nil {
		// Could be a truncated or empty file
		sub.log.Error(err)
		return
	}
	for key, itemB := range pairs {
		sub.log.Functionf("populate(%s) key %s", name, key)
		handleModify(sub, key, itemB)
	}
	if restartCounter != 0 {
		handleRestart(sub, restartCounter)
	}
	sub.log.Functionf("populate(%s) done", name)
}

// ProcessChange process a single change and its parameters. It
// calls the various handlers (if set) and updates the subscribed collection.
// The subscribed collection can be accessed using:
//
//	foo := s1.Get(key)
//	fooAll := s1.GetAll()
func (sub *SubscriptionImpl) ProcessChange(change Change) {
	start := time.Now()
	sub.log.Tracef("ProcessChange agentName(%s) agentScope(%s) topic(%s): %#v", sub.agentName, sub.agentScope, sub.topic, change)

	switch change.Operation {
	case Restart:
		name := sub.nameString()
		restartCounter, err := strconv.Atoi(change.Key)
		// Treat present but empty file as "1" to handle old file
		// in /persist
		if err != nil {
			sub.log.Warnf("Load: %s for %s; read %s treat as 1",
				err, name, change.Key)
		}
		sub.log.Tracef("Restart(%s) key %s counter %d",
			name, change.Key, restartCounter)
		handleRestart(sub, restartCounter)
	case Sync:
		handleSynchronized(sub, true)
	case Delete:
		handleDelete(sub, change.Key)
	case Modify:
		handleModify(sub, change.Key, change.Value)
	}
	sub.ps.CheckMaxTimeTopic(sub.myAgentName, sub.topic, start, sub.MaxProcessTimeWarn, sub.MaxProcessTimeError)
}

// Get - Get object with specified Key from this Subscription.
func (sub *SubscriptionImpl) Get(key string) (interface{}, error) {
	m, ok := sub.km.key.Load(key)
	if ok {
		return m, nil
	} else {
		name := sub.nameString()
		errStr := fmt.Sprintf("Get(%s) unknown key %s", name, key)
		return nil, errors.New(errStr)
	}
}

// GetAll - Enumerate all the key, value for the collection
func (sub *SubscriptionImpl) GetAll() map[string]interface{} {
	result := make(map[string]interface{})
	assigner := func(key string, val interface{}) bool {
		result[key] = val
		return true
	}
	sub.km.key.Range(assigner)
	return result
}

// Iterate - performs some callback function on all items
func (sub *SubscriptionImpl) Iterate(function base.StrMapFunc) {
	sub.km.key.Range(function)
}

// Restarted - Check if the Publisher has Restarted
func (sub *SubscriptionImpl) Restarted() bool {
	return sub.km.restartCounter != 0
}

// RestartCounter - Check how many times the Publisher has Restarted
func (sub *SubscriptionImpl) RestartCounter() int {
	return sub.km.restartCounter
}

// Synchronized -
func (sub *SubscriptionImpl) Synchronized() bool {
	return sub.synchronized
}

// Topic returns the string definiting the topic
func (sub *SubscriptionImpl) Topic() string {
	return sub.topic
}

func (sub *SubscriptionImpl) nameString() string {
	var name string
	agentName := sub.agentName
	if agentName == "" {
		agentName = sub.defaultName
	}
	if sub.agentScope == "" {
		name = fmt.Sprintf("%s/%s", sub.agentName, sub.topic)
	} else {
		name = fmt.Sprintf("%s/%s/%s", sub.agentName, sub.agentScope, sub.topic)
	}
	return name
}

func (sub *SubscriptionImpl) dump(infoStr string) {
	name := sub.nameString()
	sub.log.Tracef("dump(%s) %s\n", name, infoStr)
	dumper := func(key string, val interface{}) bool {
		_, err := json.Marshal(val)
		if err != nil {
			sub.log.Fatal("json Marshal in dump", err)
		}
		// DO NOT log Values. They may contain sensitive information.
		sub.log.Tracef("\tkey %s", key)
		return true
	}
	sub.km.key.Range(dumper)
	sub.log.Tracef("\trestarted %d\n", sub.km.restartCounter)
	sub.log.Tracef("\tsynchronized %t\n", sub.synchronized)
}

// handlers
func handleModify(ctxArg interface{}, key string, itemcb []byte) {
	sub := ctxArg.(*SubscriptionImpl)
	name := sub.nameString()
	sub.log.Tracef("pubsub.handleModify(%s) key %s\n", name, key)
	// Any large items which were stored separately?
	itemcb, err := readAddLarge(sub.log, itemcb)
	if err != nil {
		errStr := fmt.Sprintf("handleModify(%s): readAddLarge failed %s",
			name, err)
		sub.log.Errorln(errStr)
		return
	}
	item, err := parseTemplate(sub.log, itemcb, sub.topicType)
	if err != nil {
		errStr := fmt.Sprintf("handleModify(%s): json failed %s",
			name, err)
		sub.log.Errorln(errStr)
		return
	}
	created := false
	m, ok := sub.km.key.Load(key)
	if ok {
		if cmp.Equal(m, item) {
			sub.log.Tracef("pubsub.handleModify(%s/%s) unchanged\n",
				name, key)
			return
		}
		sub.log.Tracef("pubsub.handleModify(%s/%s) replacing due to diff",
			name, key)
		loggable, ok := item.(base.LoggableObject)
		if ok {
			loggable.LogModify(sub.log, m)
		}
	} else {
		// DO NOT log Values. They may contain sensitive information.
		sub.log.Tracef("pubsub.handleModify(%s) add for key %s\n",
			name, key)
		created = true
		loggable, ok := item.(base.LoggableObject)
		if ok {
			loggable.LogCreate(sub.log)
		}
	}
	sub.km.key.Store(key, item)
	if sub.logger.GetLevel() == logrus.TraceLevel {
		sub.dump("after handleModify")
	}
	// Need a copy in case the caller will modify e.g., embedded maps
	newItem := deepCopy(sub.log, item)
	if created {
		if sub.CreateHandler != nil {
			(sub.CreateHandler)(sub.userCtx, key, newItem)
		}
	} else {
		if sub.ModifyHandler != nil {
			(sub.ModifyHandler)(sub.userCtx, key, newItem, m)
		}
	}
	sub.log.Tracef("pubsub.handleModify(%s) done for key %s\n", name, key)
}

func handleDelete(ctxArg interface{}, key string) {
	sub := ctxArg.(*SubscriptionImpl)
	name := sub.nameString()
	sub.log.Tracef("pubsub.handleDelete(%s) key %s\n", name, key)

	m, ok := sub.km.key.Load(key)
	if !ok {
		sub.log.Errorf("pubsub.handleDelete(%s) %s key not found\n",
			name, key)
		return
	}
	loggable, ok := m.(base.LoggableObject)
	if ok {
		loggable.LogDelete(sub.log)
	}
	// DO NOT log Values. They may contain sensitive information.
	sub.log.Tracef("pubsub.handleDelete(%s) key %s", name, key)
	sub.km.key.Delete(key)
	if sub.logger.GetLevel() == logrus.TraceLevel {
		sub.dump("after handleDelete")
	}
	if sub.DeleteHandler != nil {
		(sub.DeleteHandler)(sub.userCtx, key, m)
	}
	sub.log.Tracef("pubsub.handleDelete(%s) done for key %s\n", name, key)
}

func handleRestart(ctxArg interface{}, restartCounter int) {
	sub := ctxArg.(*SubscriptionImpl)
	name := sub.nameString()
	sub.log.Tracef("pubsub.handleRestart(%s) restartCounter %d",
		name, restartCounter)
	if restartCounter == sub.km.restartCounter {
		sub.log.Tracef("pubsub.handleRestart(%s) value unchanged\n", name)
		return
	}
	sub.km.restartCounter = restartCounter
	if sub.RestartHandler != nil {
		(sub.RestartHandler)(sub.userCtx, restartCounter)
	}
	sub.log.Tracef("pubsub.handleRestart(%s) done for restartCounter %d",
		name, restartCounter)
}

func handleSynchronized(ctxArg interface{}, synchronized bool) {
	sub := ctxArg.(*SubscriptionImpl)
	name := sub.nameString()
	sub.log.Tracef("pubsub.handleSynchronized(%s) synchronized %v\n", name, synchronized)
	if synchronized == sub.synchronized {
		sub.log.Tracef("pubsub.handleSynchronized(%s) value unchanged\n", name)
		return
	}
	sub.synchronized = synchronized
	if sub.SynchronizedHandler != nil {
		(sub.SynchronizedHandler)(sub.userCtx, synchronized)
	}
	sub.log.Tracef("pubsub.handleSynchronized(%s) done for synchronized %v\n",
		name, synchronized)
}
