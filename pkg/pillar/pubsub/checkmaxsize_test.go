// Copyright (c) 2020,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"crypto/rand"
	"encoding/base64"
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

	// A string of 900KB fits in the 1MB message limit as it is. A larger
	// one fits if it compresses into 1MB, as repetitive content does, and
	// random content of 1500KB does not.
	myCtx := context{}
	testMatrix := map[string]struct {
		agentName   string
		agentScope  string
		persistent  bool
		stringSize  int
		stringCSize int
		random      bool
		expectFail  bool
	}{
		"IPC compressed": {
			agentName:  "testagent1",
			stringSize: 5 * 1024 * 1024,
		},
		"IPC with persistent compressed using large tag": {
			agentName:   "testagent2",
			persistent:  true,
			stringCSize: 5 * 1024 * 1024,
		},
		"File small enough": {
			agentName: "",
			//			agentScope: "testscope1",
			stringSize: 900 * 1024,
		},
		"IPC small enough": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringSize: 900 * 1024,
		},
		"IPC with persistent small enough": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent: true,
			stringSize: 900 * 1024,
		},
		"File too large": {
			agentName: "",
			//			agentScope: "testscope1",
			stringSize: 1500 * 1024,
			random:     true,
			expectFail: true,
		},
		"IPC too large": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringSize: 1500 * 1024,
			random:     true,
			expectFail: true,
		},
		"IPC with persistent too large": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent: true,
			stringSize: 1500 * 1024,
			random:     true,
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
			stringCSize: 1500 * 1024,
			random:      true,
			expectFail:  true,
		},
		"IPC too large using large tag": {
			agentName: "testagent1",
			//			agentScope: "testscope",
			stringCSize: 1500 * 1024,
			random:      true,
			expectFail:  true,
		},
		"IPC with persistent too large using large tag": {
			agentName: "testagent2",
			//			agentScope: "testscope",
			persistent:  true,
			stringCSize: 1500 * 1024,
			random:      true,
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

			largeString := testString(test.stringSize, test.random)
			largeStringC := testString(test.stringCSize, test.random)
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

// testString returns size bytes of printable text, repeating or random.
func testString(size int, random bool) []byte {
	if random {
		b := make([]byte, size*3/4+3)
		_, _ = rand.Read(b)
		return []byte(base64.StdEncoding.EncodeToString(b))[:size]
	}
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(0x40 + i%25)
	}
	return b
}
