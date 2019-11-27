package pubsub

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

//  The ProcessChange function calls the various handlers (if set) and updates
//  the subscribed collection. The subscribed collection can be accessed using:
//  foo := s1.Get(key)
//  fooAll := s1.GetAll()
// SubHandler is a generic handler to handle create, modify and delete
type Subscription struct {
	C                   <-chan Change
	CreateHandler       SubHandler
	ModifyHandler       SubHandler
	DeleteHandler       SubHandler
	RestartHandler      SubRestartHandler
	SynchronizedHandler SubRestartHandler
	MaxProcessTimeWarn  time.Duration // If set generate warning if ProcessChange
	MaxProcessTimeError time.Duration // If set generate warning if ProcessChange

	// Private fields
	agentName    string
	agentScope   string
	topic        string
	km           keyMap
	userCtx      interface{}
	synchronized bool
	driver       DriverSubscriber
}

// If the agentName is empty we interpret that as being global
func (sub *Subscription) Activate() error {
	if err := sub.driver.Start(); err != nil {
		return err
	}
	return nil
}

// ProcessChange process a single change and its parameters
func (sub *Subscription) ProcessChange(change Change) {
	start := time.Now()

	switch change.Operation {
	case Restart:
		handleRestart(sub, true)
	case Create:
		handleSynchronized(sub, true)
	case Delete:
		handleDelete(sub, change.Key)
	case Modify:
		handleModify(sub, change.Key, change.Value)
	}
	CheckMaxTimeTopic(sub.agentName, sub.topic, start, sub.MaxProcessTimeWarn, sub.MaxProcessTimeError)
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

// Topic returns the string definiting the topic
func (sub *Subscription) Topic() string {
	return sub.topic
}

func (sub *Subscription) nameString() string {
	var name string
	agentName := sub.agentName
	if agentName == "" {
		agentName = sub.driver.DefaultName()
	}
	if sub.agentScope == "" {
		name = fmt.Sprintf("%s/%s", sub.agentName, sub.topic)
	} else {
		name = fmt.Sprintf("%s/%s/%s", sub.agentName, sub.agentScope, sub.topic)
	}
	return name
}

// handlers
func handleModify(ctxArg interface{}, key string, item interface{}) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	log.Debugf("pubsub.handleModify(%s) key %s\n", name, key)
	// NOTE: without a deepCopy we would just save a pointer since
	// item is a pointer. That would cause failures.
	newItem := deepCopy(item)
	created := false
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
		created = true
	}
	sub.km.key.Store(key, newItem)
	if log.GetLevel() == log.DebugLevel {
		sub.dump("after handleModify")
	}
	if created && sub.CreateHandler != nil {
		(sub.CreateHandler)(sub.userCtx, key, newItem)
	} else if sub.ModifyHandler != nil {
		(sub.ModifyHandler)(sub.userCtx, key, newItem)
	}
	log.Debugf("pubsub.handleModify(%s) done for key %s\n", name, key)
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
