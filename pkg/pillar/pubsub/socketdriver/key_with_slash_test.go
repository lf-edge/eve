// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type Item struct {
	Content string
}

// nolint: paralleltest
func TestKeyWithSlash(t *testing.T) {
	key := "/dev/zd0"
	// Run in a unique directory.
	rootPath, err := ioutil.TempDir("", "key_with_slash_test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(rootPath)
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)

	driver := socketdriver.SocketDriver{
		Logger:  logger,
		Log:     log,
		RootDir: rootPath,
	}
	ctx := Item{}
	ps := pubsub.New(&driver, logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "test",
		TopicType:  Item{},
		Persistent: true,
	})
	if err != nil {
		t.Fatalf("unable to create publisher: %v", err)
	}
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "test",
		MyAgentName: "test",
		TopicImpl:   Item{},
		Persistent:  true,
		Ctx:         &ctx,
	})
	if err != nil {
		t.Fatalf("unable to create subscriber: %v", err)
	}
	err = sub.Activate()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for change := range sub.MsgChan() {
			sub.ProcessChange(change)
		}
	}()

	// Second publication, the first value should be copied to a backup file.
	err = pub.Publish(key, Item{Content: "test"})
	if err != nil {
		t.Fatal(err)
	}

	encodedKey, encoded := pubsub.MaybeEncodeKey(key)
	assert.True(t, encoded)

	filePath := filepath.Join(rootPath, "persist", "status", "test", "Item", encodedKey+pubsub.EncodedJSONSuffix)
	_, err = os.Stat(filePath)
	if err != nil {
		t.Fatalf("published item was not persisted: %v", err)
	}

	items := sub.GetAll()
	assert.Len(t, items, 1)
	assert.Contains(t, items, key)
	assert.Equal(t, Item{Content: "test"}, items[key])

	items = sub.GetAll()
	assert.Len(t, items, 1)
	assert.Contains(t, items, key)
	assert.Equal(t, Item{Content: "test"}, items[key])

	err = pub.Unpublish(key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(filePath)
	if !os.IsNotExist(err) {
		t.Fatal("unexpected orig file")
	}

	items = sub.GetAll()
	assert.Len(t, items, 0)
}
