// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type item struct {
	FieldA string
}

type context struct {
}

func TestUnsubscribe(t *testing.T) {
	// Run in a unique directory
	rootPath, err := os.MkdirTemp("", "unsubscribe_test")
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

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		t.Run(testname, func(t *testing.T) {
			numGoroutines := runtime.NumGoroutine()
			origStacks := getStacks(true)
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

			log.Functionf("sub.Close")
			sub.Close()
			assert.Equal(t, 1, len(items))

			for sub.Synchronized() {
				select {
				case change := <-sub.MsgChan():
					log.Functionf("ProcessChange")
					sub.ProcessChange(change)
				}
			}
			items = sub.GetAll()
			assert.Equal(t, 0, len(items))
			log.Functionf("pub.Close")
			pub.Close()
			log.Functionf("Waiting to end test case pub %s", testname)
			// Wait for fsnotify to go away
			time.Sleep(time.Second)

			// Check that goroutines are gone
			// Sometimes we see a decrease
			assert.GreaterOrEqual(t, numGoroutines, runtime.NumGoroutine())
			if numGoroutines != runtime.NumGoroutine() {
				t.Logf("All goroutine stacks on entry: %v",
					origStacks)
				t.Logf("All goroutine stacks on exit: %v",
					getStacks(true))
			}
		})
	}
	os.RemoveAll(rootPath)
}

func getStacks(all bool) string {
	var (
		buf       []byte
		stackSize int
	)
	bufferLen := 16384
	for stackSize == len(buf) {
		buf = make([]byte, bufferLen)
		stackSize = runtime.Stack(buf, all)
		bufferLen *= 2
	}
	buf = buf[:stackSize]
	return string(buf)
}
