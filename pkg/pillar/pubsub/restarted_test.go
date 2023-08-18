// Copyright (c) 2020-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRestarted(t *testing.T) {
	// Run in a unique directory
	rootPath, err := os.MkdirTemp("", "restarted_test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}

	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.InfoLevel)
	formatter := logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	logger.SetFormatter(&formatter)
	logger.SetReportCaller(true)
	log := base.NewSourceLogObject(logger, "test", 1234)
	driver := socketdriver.SocketDriver{
		Logger:  logger,
		Log:     log,
		RootDir: rootPath,
	}
	ps := pubsub.New(&driver, logger, log)

	myCtx := context{}
	testMatrix := map[string]struct {
		agentName  string
		agentScope string
		persistent bool
	}{
		"File": {
			agentName: "",
			//			agentScope: "testscope1",
		},
		"IPC": {
			agentName: "testagent1",
			//			agentScope: "testscope",
		},
		"IPC with persistent": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent: true,
		},
	}

	var events []string
	events = nil
	subCreateHandler := func(ctxArg interface{}, key string, status interface{}) {
		log.Functionf("subCreateHandler %s", key)
		events = append(events, "create "+key)
	}
	subModifyHandler := func(ctxArg interface{}, key string, status interface{}, oldStatus interface{}) {
		log.Functionf("subModifyHandler %s", key)
		events = append(events, "modify "+key)
	}
	subDeleteHandler := func(ctxArg interface{}, key string, status interface{}) {
		log.Functionf("subDeleteHandler %s", key)
		events = append(events, "delete "+key)

	}
	subRestartHandler := func(ctxArg interface{}, restartCounter int) {
		str := fmt.Sprintf("%d", restartCounter)
		log.Functionf("subRestartHandler %s", str)
		events = append(events, "restarted "+str)
	}
	subSynchronizedHandler := func(ctxArg interface{}, synchronized bool) {
		str := fmt.Sprintf("%t", synchronized)
		log.Functionf("subSynchronizedHandler %s", str)
		events = append(events, "synchronized "+str)
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		t.Run(testname, func(t *testing.T) {
			pub, err := ps.NewPublication(
				pubsub.PublicationOptions{
					AgentName:  test.agentName,
					AgentScope: test.agentScope,
					Persistent: test.persistent,
					TopicType:  item{},
				})
			if err != nil {
				t.Fatalf("unable to publish: %v", err)
			}
			item1 := item{FieldA: "item1"}
			log.Functionf("Publishing key1")
			pub.Publish("key1", item1)
			log.Functionf("SignalRestarted")
			pub.SignalRestarted()

			log.Functionf("NewSubscription")
			sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
				AgentName:      test.agentName,
				AgentScope:     test.agentScope,
				Persistent:     test.persistent,
				TopicImpl:      item{},
				CreateHandler:  subCreateHandler,
				ModifyHandler:  subModifyHandler,
				DeleteHandler:  subDeleteHandler,
				RestartHandler: subRestartHandler,
				SyncHandler:    subSynchronizedHandler,
				Ctx:            &myCtx,
			})
			if err != nil {
				t.Fatalf("unable to subscribe: %v", err)
			}
			assert.Equal(t, 0, len(events))
			log.Functionf("Activate")
			sub.Activate()
			// Process subscription to populate
			for !sub.Synchronized() || !sub.Restarted() {
				select {
				case change := <-sub.MsgChan():
					log.Functionf("ProcessChange")
					sub.ProcessChange(change)
				}
			}
			items := sub.GetAll()
			assert.Equal(t, 1, len(items))
			assert.Equal(t, 3, len(events))
			if len(events) == 3 {
				assert.Equal(t, "create key1", events[0])
				// Could be in either order
				if events[1] == "restarted 1" {
					assert.Equal(t, "synchronized true", events[2])
				} else {
					assert.Equal(t, "synchronized true", events[1])
					assert.Equal(t, "restarted 1", events[2])
				}
			}
			events = nil

			item1modified := item{FieldA: "item1modified"}
			log.Functionf("Publishing key1")
			pub.Publish("key1", item1modified)
			item2 := item{FieldA: "item2"}
			log.Functionf("Publishing key2")
			pub.Publish("key2", item2)
			log.Functionf("SignalRestarted")
			pub.SignalRestarted()

			timer := time.NewTimer(10 * time.Second)
			done := false
			for !done {
				select {
				case change := <-sub.MsgChan():
					log.Functionf("ProcessChange")
					sub.ProcessChange(change)
					if len(events) == 3 {
						done = true
						break
					}
				case <-timer.C:
					log.Errorf("Timed out for three: got %d: %+v",
						len(events), events)
					done = true
					break
				}
			}
			items = sub.GetAll()
			assert.Equal(t, 2, len(items))
			assert.Equal(t, 3, len(events))
			if len(events) == 3 {
				// modify and create in any order
				if events[0] == "modify key1" {
					assert.Equal(t, "create key2", events[1])
				} else {
					assert.Equal(t, "create key2", events[0])
					assert.Equal(t, "modify key1", events[1])
				}
				assert.Equal(t, "restarted 2", events[2])
			}
			events = nil

			pub.Unpublish("key1")
			log.Functionf("SignalRestarted")
			pub.SignalRestarted()

			timer = time.NewTimer(10 * time.Second)
			done = false
			for !done {
				select {
				case change := <-sub.MsgChan():
					log.Functionf("ProcessChange")
					sub.ProcessChange(change)
					if len(events) == 2 {
						done = true
						break
					}
				case <-timer.C:
					log.Errorf("Timed out for two: got %d: %+v",
						len(events), events)
					done = true
					break
				}
			}
			items = sub.GetAll()
			assert.Equal(t, 1, len(items))
			assert.Equal(t, 2, len(events))
			if len(events) == 2 {
				assert.Equal(t, "delete key1", events[0])
				assert.Equal(t, "restarted 3", events[1])
			}
			events = nil
		})
	}
	os.RemoveAll(rootPath)
}
