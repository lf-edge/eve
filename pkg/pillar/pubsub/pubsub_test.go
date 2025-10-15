// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	agentName  = "agentName"
	agentScope = "agentScope"
)

type Item struct {
	aString string
}

var (
	item = Item{
		aString: "aString",
	}
)

func TestHandleModify(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	ps := New(&EmptyDriver{}, logger, log)
	sub, err := ps.NewSubscription(SubscriptionOptions{
		AgentName:  agentName,
		AgentScope: agentScope,
		TopicImpl:  item,
		Persistent: false,
		Ctx:        &item,
	})
	if err != nil {
		t.Fatalf("unable to subscribe: %v", err)
	}
	subImpl, ok := sub.(*SubscriptionImpl)
	if !ok {
		t.Fatal("NewSubscription was not a *SubscriptionImpl")
	}

	created := false
	modified := false
	subCreateHandler := func(ctxArg any, key string, status any) {
		created = true
	}
	subModifyHandler := func(ctxArg any, key string, status any, oldStatus any) {
		modified = true
	}

	testMatrix := map[string]struct {
		ctxArg         *SubscriptionImpl
		key            string
		item           any
		modifyHandler  SubModifyHandler
		createHandler  SubCreateHandler
		expectedCreate bool
		expectedModify bool
	}{
		"Modify Handler is nil": {
			ctxArg:         subImpl,
			key:            "key_0",
			item:           item,
			modifyHandler:  nil,
			createHandler:  subCreateHandler,
			expectedCreate: true,
			expectedModify: false,
		},
		"Create Handler is nil": {
			ctxArg:         subImpl,
			key:            "key_1",
			item:           item,
			modifyHandler:  subModifyHandler,
			createHandler:  nil,
			expectedCreate: false,
			expectedModify: false,
		},
		"Create Handler and Modify Handler are nil": {
			ctxArg:         subImpl,
			key:            "key_2",
			item:           item,
			modifyHandler:  nil,
			createHandler:  nil,
			expectedCreate: false,
			expectedModify: false,
		},
		"Both Handlers are set": {
			ctxArg:         subImpl,
			key:            "key_3",
			item:           item,
			modifyHandler:  subModifyHandler,
			createHandler:  subCreateHandler,
			expectedCreate: true,
			expectedModify: false,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		test.ctxArg.CreateHandler = test.createHandler
		test.ctxArg.ModifyHandler = test.modifyHandler
		b, err := json.Marshal(test.item)
		if err != nil {
			t.Fatalf("json.Marshal failed: %s", err)
		}
		handleModify(test.ctxArg, test.key, b)
		// Make sure both weren't called
		assert.Equal(t, test.expectedCreate, created)
		assert.Equal(t, test.expectedModify, modified)
		// Reset created and modified to false for next test
		created = false
		modified = false
	}
}
