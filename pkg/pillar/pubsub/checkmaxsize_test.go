// Copyright (c) 2020,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCheckMaxSize(t *testing.T) {
	// Run in a unique directory
	rootPath, err := ioutil.TempDir("", "checkmaxsize_test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}

	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.ErrorLevel)
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

	// The values 49120 and 49122 have been determined experimentally
	// to be what fits and not for this particular struct and string
	// content.
	myCtx := context{}
	testMatrix := map[string]struct {
		agentName  string
		agentScope string
		persistent bool
		stringSize int
		expectFail bool
	}{
		"File small enough": {
			agentName: "",
			//			agentScope: "testscope1",
			stringSize: 49120,
		},
		"File with persistent small enough": {
			agentName: "",
			//			agentScope: "testscope2",
			persistent: true,
			stringSize: 49120,
		},
		"IPC small enough": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringSize: 49120,
		},
		"IPC with persistent small enough": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent: true,
			stringSize: 49120,
		},
		"File too large": {
			agentName: "",
			//			agentScope: "testscope1",
			stringSize: 49122,
			expectFail: true,
		},
		"File with persistent too large": {
			agentName: "",
			//			agentScope: "testscope2",
			persistent: true,
			stringSize: 49122,
			expectFail: true,
		},
		"IPC too large": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringSize: 49122,
			expectFail: true,
		},
		"IPC with persistent too large": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent: true,
			stringSize: 49122,
			expectFail: true,
		},
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
				AgentName:  test.agentName,
				AgentScope: test.agentScope,
				Persistent: test.persistent,
				TopicImpl:  item{},
				Ctx:        &myCtx,
			})
			if err != nil {
				t.Fatalf("unable to subscribe: %v", err)
			}
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

			largeString := make([]byte, test.stringSize)
			for i := range largeString {
				largeString[i] = byte(0x40 + i%25)
			}
			item2 := item{FieldA: string(largeString)}
			log.Functionf("Publishing key2")
			err = pub.CheckMaxSize("key2", item2)
			if test.expectFail {
				assert.NotNil(t, err)
				t.Logf("Test case %s: CheckMaxSize error: %s",
					testname, err)
			} else {
				assert.Nil(t, err)
				pub.Publish("key2", item2)
				items := pub.GetAll()
				assert.Equal(t, 2, len(items))
				timer := time.NewTimer(10 * time.Second)
				done := false
				for !done {
					select {
					case change := <-sub.MsgChan():
						log.Functionf("ProcessChange")
						sub.ProcessChange(change)
						items := sub.GetAll()
						if len(items) == 2 {
							done = true
							break
						}
					case <-timer.C:
						log.Errorf("Timed out")
						done = true
						break
					}
				}
				items = sub.GetAll()
				assert.Equal(t, 2, len(items))
			}
			log.Functionf("sub.Close")
			sub.Close()
			log.Functionf("pub.Close")
			pub.Close()
		})
	}
	os.RemoveAll(rootPath)
}
