// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package agentlog_test checks the logging
package agentlog_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	defaultAgent    = "zedbox"
	agentName       = "myAgent"
	subscriberAgent = "subscriberAgent"
	publisherAgent  = "publisherAgent"
)

// Really a constant
var nilUUID = uuid.UUID{}

const myLogType = "mylogtype"

type Item struct {
	AString string
	ID      string
}

// Key for pubsub
func (status Item) Key() string {
	return status.ID
}

// LogCreate :
func (status Item) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, myLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("a-string", status.AString).
		Noticef("Item create")
}

// LogModify :
func (status Item) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, myLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(Item)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of Item type")
	}
	if oldStatus.AString != status.AString {
		logObject.CloneAndAddField("a-string", status.AString).
			AddField("old-a-string", oldStatus.AString).
			Noticef("Item modify")
	} else {
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Item modify other change")
	}
}

// LogDelete :
func (status Item) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, myLogType, "",
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("a-string", status.AString).
		Noticef("Item delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status Item) LogKey() string {
	return myLogType + "-" + status.Key()
}

var (
	item = Item{
		AString: "aString",
		ID:      "myID",
	}
)

// TestPubsubLog verifies some agentlog+pubsub operations
// TBD add assertions on what is logged in terms of "source"
// This test only works if /persist and /run are writable
func TestPubsubLog(t *testing.T) {
	if !utils.Writable(types.PersistDir) || !utils.Writable("/run") {
		t.Logf("Required directories not writeable; SKIP")
		return
	}
	defaultLogger, defaultLog := agentlog.Init(defaultAgent)
	// how do we check this appears in log?
	defaultLogger.Infof("defaultLogger")
	defaultLog.Noticef("defaultLog")
	logrus.Infof("logrus")

	pubLogger, pubLog := agentlog.Init(publisherAgent)
	// pubLogger.SetLevel(logrus.TraceLevel)
	pubPs := pubsub.New(
		&socketdriver.SocketDriver{
			Logger: pubLogger,
			Log:    pubLog,
		},
		pubLogger, pubLog)
	pub, err := pubPs.NewPublication(pubsub.PublicationOptions{
		AgentName:  publisherAgent,
		TopicType:  item,
		Persistent: false,
	})
	if err != nil {
		t.Fatalf("unable to publish: %v", err)
	}

	subLogger, subLog := agentlog.Init(subscriberAgent)
	// subLogger.SetLevel(logrus.TraceLevel)
	subPs := pubsub.New(
		&socketdriver.SocketDriver{
			Logger: subLogger,
			Log:    subLog,
		},
		subLogger, subLog)

	restarted := false
	synchronized := false
	created := false
	modified := false
	deleted := false
	subRestartHandler := func(ctxArg interface{}, restartCounter int) {
		t.Logf("subRestartHandler %d", restartCounter)
		if restartCounter == 0 {
			t.Fatalf("subRestartHandler called with zero")
		} else {
			restarted = true
		}
	}
	subSyncHandler := func(ctxArg interface{}, arg bool) {
		t.Logf("subSyncHandler")
		if !arg {
			t.Fatalf("subSyncHandler called with false")
		} else {
			synchronized = true
		}
	}
	subCreateHandler := func(ctxArg interface{}, key string, status interface{}) {
		t.Logf("subCreateHandler")
		created = true
	}
	subModifyHandler := func(ctxArg interface{}, key string, status interface{}, oldStatus interface{}) {
		t.Logf("subModifyHandler")
		modified = true
	}
	subDeleteHandler := func(ctxArg interface{}, key string, status interface{}) {
		t.Logf("subDeleteHandler")
		deleted = true
	}

	sub, err := subPs.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      publisherAgent,
		MyAgentName:    subscriberAgent,
		RestartHandler: subRestartHandler,
		SyncHandler:    subSyncHandler,
		CreateHandler:  subCreateHandler,
		ModifyHandler:  subModifyHandler,
		DeleteHandler:  subDeleteHandler,
		TopicImpl:      item,
		Persistent:     false,
		Ctx:            &item,
		Activate:       true,
	})
	if err != nil {
		t.Fatalf("unable to subscribe: %v", err)
	}

	dummyItem := Item{AString: "something to publish", ID: "mykey"}
	t.Logf("Initial Publish")
	pub.Publish(dummyItem.ID, dummyItem)
	i, err := pub.Get("mykey")
	assert.Nil(t, err)
	i2 := i.(Item)
	assert.Equal(t, "something to publish", i2.AString)
	assert.Equal(t, "mykey", i2.ID)

	change := <-sub.MsgChan()
	t.Logf("ProcessChange synchronized?")
	sub.ProcessChange(change)
	assert.False(t, synchronized)
	assert.False(t, restarted)

	change = <-sub.MsgChan()
	t.Logf("ProcessChange created?")
	sub.ProcessChange(change)
	assert.True(t, created)

	dummyItem.AString = "something else"
	t.Logf("Modify Publish")
	pub.Publish(dummyItem.ID, dummyItem)
	change = <-sub.MsgChan()
	t.Logf("ProcessChange modified?")
	sub.ProcessChange(change)
	assert.True(t, modified)

	t.Logf("Unpublish")
	pub.Unpublish(dummyItem.ID)
	change = <-sub.MsgChan()
	t.Logf("ProcessChange deleted?")
	sub.ProcessChange(change)
	assert.True(t, deleted)
}
