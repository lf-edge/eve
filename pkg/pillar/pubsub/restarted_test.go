// Copyright (c) 2020-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/nkvdriver"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRestarted(t *testing.T) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not construct pool: %s", err)
	}
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "nkv.sock")

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "uncledecart/nkv",
		Tag:        "0.0.6",
		Cmd: []string{
			"./nkv-server", "--addr", "/var/run/nkv.sock",
		},
		Mounts: []string{
			fmt.Sprintf("%s:/var/run", tmpDir),
		},
		// User: fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}, func(hc *docker.HostConfig) {
		// Needed for mounting Unix sockets
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("Could not start nkv container: %s", err)
	}
	defer func() {
		_ = pool.Purge(resource)
	}()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("Socket not found at %s: %v", socketPath, err)
	}
	_ = exec.Command("sudo", "chmod", "777", socketPath).Run()

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
	driver := nkvdriver.NewNkvDriver(socketPath, "")
	ps := pubsub.New(driver, logger, log)

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
				change := <-sub.MsgChan()
				log.Functionf("ProcessChange")
				sub.ProcessChange(change)
			}
			items := sub.GetAll()
			assert.Equal(t, 1, len(items))  // because __restarted__ is added
			assert.Equal(t, 3, len(events)) // because __restarted__ is added
			expected := []string{"create key1", "synchronized true", "restarted 1"}
			assert.ElementsMatch(t, expected, events, "elements should match in any order")
			events = []string{}

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
					}
				case <-timer.C:
					log.Errorf("Timed out for three: got %d: %+v",
						len(events), events)
					done = true
				}
			}
			items = sub.GetAll()
			assert.Equal(t, 2, len(items)) // __restarted__ is added
			assert.Equal(t, 3, len(events))
			expected = []string{"modify key1", "create key2", "restarted 2"}
			assert.ElementsMatch(t, expected, events, "elements should match in any order")
			events = []string{}

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
					}
				case <-timer.C:
					log.Errorf("Timed out for two: got %d: %+v",
						len(events), events)
					done = true
				}
			}
			items = sub.GetAll()
			assert.Equal(t, 1, len(items))
			assert.Equal(t, 2, len(events))
			assert.Equal(t, "delete key1", events[0])
			assert.Equal(t, "restarted 3", events[1])
			events = nil
		})
		break
	}
	os.RemoveAll(rootPath)
}
