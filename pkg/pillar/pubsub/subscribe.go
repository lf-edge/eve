package pubsub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/watch"
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
//  The ProcessChange function calls the various handlers (if set) and updates
//  the subscribed collection. The subscribed collection can be accessed using:
//  foo := s1.Get(key)
//  fooAll := s1.GetAll()
// SubHandler is a generic handler to handle create, modify and delete
type SubHandler func(ctx interface{}, key string, status interface{})

// SubRestartHandler is a generic handler to handle restart and synchronized
type SubRestartHandler func(ctx interface{}, restarted bool)

// Subscription holds subscription to a single topic with its channel
type Subscription struct {
	C                   <-chan string
	CreateHandler       SubHandler
	ModifyHandler       SubHandler
	DeleteHandler       SubHandler
	RestartHandler      SubRestartHandler
	SynchronizedHandler SubRestartHandler
	MaxProcessTimeWarn  time.Duration // If set generate warning if ProcessChange
	MaxProcessTimeError time.Duration // If set generate warning if ProcessChange

	// Private fields
	sendChan   chan<- string
	topicType  interface{}
	agentName  string
	agentScope string
	topic      string
	km         keyMap
	userCtx    interface{}
	sock       net.Conn // For socket subscriptions

	synchronized     bool
	subscribeFromDir bool // Handle special case of file only info
	dirName          string
	persistent       bool
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

// If the agentName is empty we interpret that as being dir /var/tmp/zededa
func (sub *Subscription) Activate() error {

	name := sub.nameString()
	if sub.subscribeFromDir {
		// Waiting for directory to appear
		for {
			if _, err := os.Stat(sub.dirName); err != nil {
				errStr := fmt.Sprintf("Subscribe(%s): failed %s; waiting",
					name, err)
				log.Errorln(errStr)
				time.Sleep(10 * time.Second)
			} else {
				break
			}
		}
		go watch.WatchStatus(sub.dirName, true, sub.sendChan)
		return nil
	} else if subscribeFromSock {
		go sub.watchSock()
		return nil
	} else {
		errStr := fmt.Sprintf("Subscribe(%s): failed %s",
			name, "nowhere to subscribe")
		return errors.New(errStr)
	}
}

func (sub *Subscription) watchSock() {

	for {
		msg, key, val := sub.connectAndRead()
		switch msg {
		case "hello":
			// Do nothing
		case "complete":
			// XXX to handle restart we need to handle "complete"
			// by doing a sweep across the KeyMap to handleDelete
			// what we didn't see before the "complete"
			sub.sendChan <- "C done"

		case "restarted":
			sub.sendChan <- "R done"

		case "delete":
			sub.sendChan <- "D " + key

		case "update":
			// XXX is size of val any issue? pointer?
			sub.sendChan <- "M " + key + " " + val
		}
	}
}

// Returns msg, key, val
// key and val are base64-encoded
func (sub *Subscription) connectAndRead() (string, string, string) {

	name := sub.nameString()
	sockName := SockName(name)
	buf := make([]byte, maxsize+1)

	// Waiting for publisher to appear; retry on error
	for {
		if sub.sock == nil {
			s, err := net.Dial("unixpacket", sockName)
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): Dial failed %s",
					name, err)
				log.Warnln(errStr)
				time.Sleep(10 * time.Second)
				continue
			}
			sub.sock = s
			req := fmt.Sprintf("request %s", sub.topic)
			_, err = s.Write([]byte(req))
			if err != nil {
				errStr := fmt.Sprintf("connectAndRead(%s): sock write failed %s",
					name, err)
				log.Errorln(errStr)
				sub.sock.Close()
				sub.sock = nil
				continue
			}
		}

		res, err := sub.sock.Read(buf)
		if err != nil {
			errStr := fmt.Sprintf("connectAndRead(%s): sock read failed %s",
				name, err)
			log.Errorln(errStr)
			sub.sock.Close()
			sub.sock = nil
			continue
		}

		if res == len(buf) {
			// Likely truncated
			log.Fatalf("connectAndRead(%s) request likely truncated\n",
				name)
		}
		reply := strings.Split(string(buf[0:res]), " ")
		count := len(reply)
		if count < 2 {
			errStr := fmt.Sprintf("connectAndRead(%s): too short read",
				name)
			log.Errorln(errStr)
			continue
		}
		msg := reply[0]
		t := reply[1]

		if t != sub.topic {
			errStr := fmt.Sprintf("connectAndRead(%s): mismatched topic %s vs. %s for %s",
				name, t, sub.topic, msg)
			log.Errorln(errStr)
			// XXX continue
		}

		// XXX are there error cases where we should Close and
		// continue aka reconnect?
		switch msg {
		case "hello", "restarted", "complete":
			log.Debugf("connectAndRead(%s) Got message %s type %s\n",
				name, msg, t)
			return msg, "", ""

		case "delete":
			if count < 3 {
				errStr := fmt.Sprintf("connectAndRead(%s): too short delete",
					name)
				log.Errorln(errStr)
				continue
			}
			recvKey := reply[2]

			if log.GetLevel() == log.DebugLevel {
				key, err := base64.StdEncoding.DecodeString(recvKey)
				if err != nil {
					errStr := fmt.Sprintf("connectAndRead(%s): base64 failed %s",
						name, err)
					log.Errorln(errStr)
					continue
				}
				log.Debugf("connectAndRead(%s): delete type %s key %s\n",
					name, t, string(key))
			}
			return msg, recvKey, ""

		case "update":
			if count < 4 {
				errStr := fmt.Sprintf("connectAndRead(%s): too short update",
					name)
				log.Errorln(errStr)
				continue
			}
			if count > 4 {
				errStr := fmt.Sprintf("connectAndRead(%s): too long update",
					name)
				log.Errorln(errStr)
				continue
			}
			recvKey := reply[2]
			recvVal := reply[3]
			if log.GetLevel() == log.DebugLevel {
				key, err := base64.StdEncoding.DecodeString(recvKey)
				if err != nil {
					errStr := fmt.Sprintf("connectAndRead(%s): base64 failed %s",
						name, err)
					log.Errorln(errStr)
					continue
				}
				val, err := base64.StdEncoding.DecodeString(recvVal)
				if err != nil {
					errStr := fmt.Sprintf("connectAndRead(%s): base64 val failed %s",
						name, err)
					log.Errorln(errStr)
					continue
				}
				log.Debugf("connectAndRead(%s): update type %s key %s val %s\n",
					name, t, string(key), string(val))
			}
			return msg, recvKey, recvVal

		default:
			errStr := fmt.Sprintf("connectAndRead(%s): unknown message %s",
				name, msg)
			log.Errorln(errStr)
			continue
		}
	}
}

// We handle both subscribeFromDir and subscribeFromSock
// Note that change filename includes .json for subscribeFromDir. That
// is removed by HandleStatusEvent.
func (sub *Subscription) ProcessChange(change string) {

	start := time.Now()
	if sub.subscribeFromDir {
		var restartFn watch.StatusRestartHandler = handleRestart
		var completeFn watch.StatusRestartHandler = handleSynchronized
		watch.HandleStatusEvent(change, sub, sub.dirName,
			handleModify, handleDelete, &restartFn,
			&completeFn)
	} else if subscribeFromSock {
		name := sub.nameString()
		reply := strings.Split(change, " ")
		operation := reply[0]

		switch operation {
		case "C":
			handleSynchronized(sub, true)
		case "R":
			handleRestart(sub, true)
		case "D":
			recvKey := reply[1]
			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				errStr := fmt.Sprintf("ProcessChange(%s): base64 failed %s",
					name, err)
				log.Errorln(errStr)
				break
			}
			handleDelete(sub, string(key))

		case "M":
			recvKey := reply[1]
			recvVal := reply[2]
			key, err := base64.StdEncoding.DecodeString(recvKey)
			if err != nil {
				errStr := fmt.Sprintf("ProcessChange(%s): base64 failed %s",
					name, err)
				log.Errorln(errStr)
				break
			}
			val, err := base64.StdEncoding.DecodeString(recvVal)
			if err != nil {
				errStr := fmt.Sprintf("ProcessChange(%s): base64 val failed %s",
					name, err)
				log.Errorln(errStr)
				break
			}
			handleModify(sub, string(key), val)
		}
	} else {
		// Enforced in Subscribe()
		log.Fatal("ProcessChange: neither subscribeFromDir nor subscribeFromSock")
	}
	CheckMaxTimeTopic(sub.agentName, sub.topic, start,
		sub.MaxProcessTimeWarn, sub.MaxProcessTimeError)
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

// handlers
func handleModify(ctxArg interface{}, key string, itemcb []byte) {
	sub := ctxArg.(*Subscription)
	name := sub.nameString()
	log.Debugf("pubsub.handleModify(%s) key %s\n", name, key)
	item, err := parseTemplate(itemcb, sub.topicType)
	if err != nil {
		errStr := fmt.Sprintf("handleModify(%s): json failed %s",
			name, err)
		log.Errorln(errStr)
		return
	}
	created := false
	m, ok := sub.km.key.Load(key)
	if ok {
		if cmp.Equal(m, item) {
			log.Debugf("pubsub.handleModify(%s/%s) unchanged\n",
				name, key)
			return
		}
		log.Debugf("pubsub.handleModify(%s/%s) replacing due to diff %s\n",
			name, key, cmp.Diff(m, item))
	} else {
		log.Debugf("pubsub.handleModify(%s) add %+v for key %s\n",
			name, item, key)
		created = true
	}
	sub.km.key.Store(key, item)
	if log.GetLevel() == log.DebugLevel {
		sub.dump("after handleModify")
	}
	if created && sub.CreateHandler != nil {
		(sub.CreateHandler)(sub.userCtx, key, item)
	} else if sub.ModifyHandler != nil {
		(sub.ModifyHandler)(sub.userCtx, key, item)
	}
	log.Debugf("pubsub.handleModify(%s) done for key %s\n", name, key)
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
