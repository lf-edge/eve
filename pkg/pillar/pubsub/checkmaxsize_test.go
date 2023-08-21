// Copyright (c) 2020,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type largeItem struct {
	StrA string
	StrC string `json:"pubsub-large-StrC"`
}

//nolint:gocyclo
func TestCheckMaxSize(t *testing.T) {
	// Run in a unique directory
	rootPath, err := os.MkdirTemp("", "checkmaxsize_test")
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

	// The values 48000 and 49122 have been determined experimentally
	// to be what fits and not for this particular struct and string
	// content.
	myCtx := context{}
	testMatrix := map[string]struct {
		agentName   string
		agentScope  string
		persistent  bool
		stringSize  int
		stringCSize int
		expectFail  bool
	}{
		"File small enough": {
			agentName: "",
			//			agentScope: "testscope1",
			stringSize: 48000,
		},
		"IPC small enough": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringSize: 48000,
		},
		"IPC with persistent small enough": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent: true,
			stringSize: 48000,
		},
		"File too large": {
			agentName: "",
			//			agentScope: "testscope1",
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
		"File using large tag": {
			agentName: "",
			//			agentScope: "testscope1",
			stringCSize: 524288,
		},
		"IPC using large tag": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringCSize: 524288,
		},
		"IPC with persistent using large tag": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent:  true,
			stringCSize: 524288,
		},
		"File too large using large tag": {
			agentName: "",
			//			agentScope: "testscope1",
			stringCSize: 1048576,
			expectFail:  true,
		},
		"IPC too large using large tag": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringCSize: 1048576,
			expectFail:  true,
		},
		"IPC with persistent too large using large tag": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent:  true,
			stringCSize: 1048576,
			expectFail:  true,
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
					TopicType:  largeItem{},
				})
			if err != nil {
				t.Fatalf("unable to publish: %v", err)
			}
			largeItem1 := largeItem{StrA: "largeItem1"}
			log.Functionf("Publishing key1")
			pub.Publish("key1", largeItem1)
			log.Functionf("SignalRestarted")
			pub.SignalRestarted()

			log.Functionf("NewSubscription")
			sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
				AgentName:  test.agentName,
				AgentScope: test.agentScope,
				Persistent: test.persistent,
				TopicImpl:  largeItem{},
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
			largeItems := sub.GetAll()
			assert.Equal(t, 1, len(largeItems))

			largeString := make([]byte, test.stringSize)
			for i := range largeString {
				largeString[i] = byte(0x40 + i%25)
			}
			largeStringC := make([]byte, test.stringCSize)
			for i := range largeStringC {
				largeStringC[i] = byte(0x40 + i%25)
			}
			largeItem2 := largeItem{
				StrA: string(largeString),
				StrC: string(largeStringC),
			}
			log.Functionf("Publishing key2")
			err = pub.CheckMaxSize("key2", largeItem2)
			// Did CheckMaxSize modify argument
			assert.Equal(t, test.stringSize, len(largeItem2.StrA))
			assert.Equal(t, test.stringCSize, len(largeItem2.StrC))
			if test.expectFail {
				assert.NotNil(t, err)
				t.Logf("Test case %s: CheckMaxSize error: %s",
					testname, err)
			} else {
				assert.Nil(t, err)
				pub.Publish("key2", largeItem2)
				// Did Publish modify argument
				assert.Equal(t, test.stringSize, len(largeItem2.StrA))
				assert.Equal(t, test.stringCSize, len(largeItem2.StrC))
				largeItems := pub.GetAll()
				assert.Equal(t, 2, len(largeItems))

				// Did we store correctly?
				item2, err2 := pub.Get("key2")
				assert.Nil(t, err2)
				if err2 == nil {
					it2 := item2.(largeItem)
					assert.Equal(t, test.stringSize,
						len(it2.StrA))
					assert.Equal(t, test.stringCSize,
						len(it2.StrC))
				}
				timer := time.NewTimer(10 * time.Second)
				done := false
				for !done {
					select {
					case change := <-sub.MsgChan():
						log.Functionf("ProcessChange")
						sub.ProcessChange(change)
						largeItems := sub.GetAll()
						if len(largeItems) == 2 {
							done = true
							break
						}
					case <-timer.C:
						log.Errorf("Timed out")
						done = true
						break
					}
				}
				largeItems = sub.GetAll()
				assert.Equal(t, 2, len(largeItems))
				for key, item := range largeItems {
					it := item.(largeItem)
					if key == "key1" {
						continue
					}
					assert.Equal(t, test.stringSize,
						len(it.StrA))
					assert.Equal(t, test.stringCSize,
						len(it.StrC))
				}

				item2, err := sub.Get("key2")
				assert.Nil(t, err)
				if err == nil {
					it2 := item2.(largeItem)
					assert.Equal(t, test.stringSize,
						len(it2.StrA))
					assert.Equal(t, test.stringCSize,
						len(it2.StrC))
				}
			}
			log.Functionf("sub.Close")
			sub.Close()
			log.Functionf("pub.Close")
			pub.Close()
			if test.persistent && !test.expectFail {
				// Verify that a second publish gets the data
				// filled in.
				pub, err := ps.NewPublication(
					pubsub.PublicationOptions{
						AgentName:  test.agentName,
						AgentScope: test.agentScope,
						Persistent: test.persistent,
						TopicType:  largeItem{},
					})
				if err != nil {
					t.Fatalf("unable to publish: %v", err)
				}
				largeItems = pub.GetAll()
				assert.Equal(t, 2, len(largeItems))
				for key, item := range largeItems {
					it := item.(largeItem)
					if key == "key1" {
						continue
					}
					assert.Equal(t, test.stringSize,
						len(it.StrA))
					assert.Equal(t, test.stringCSize,
						len(it.StrC))
				}

				item2, err := pub.Get("key2")
				assert.Nil(t, err)
				if err == nil {
					it2 := item2.(largeItem)
					assert.Equal(t, test.stringSize,
						len(it2.StrA))
					assert.Equal(t, test.stringCSize,
						len(it2.StrC))
				}
				pub.Unpublish("key1")
				pub.Unpublish("key2")
				pub.Close()
			}
		})
	}
	os.RemoveAll(rootPath)
}
