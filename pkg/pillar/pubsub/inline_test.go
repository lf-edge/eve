// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
)

// TestFieldsTaggedLargeInline checks that a field tagged pubsub-large-
// reaches subscribers inside the message, without files in between.
func TestFieldsTaggedLargeInline(t *testing.T) {
	rootPath := t.TempDir()
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "inlinetest", 1234)
	driver := socketdriver.SocketDriver{Logger: logger, Log: log, RootDir: rootPath}
	ps := pubsub.New(&driver, logger, log)

	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "inlineagent",
		TopicType: largeItem{},
	})
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 300*1024)
	if err := pub.Publish("key", largeItem{StrA: "a", StrC: big}); err != nil {
		t.Fatal(err)
	}

	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "inlineagent",
		TopicImpl: largeItem{},
		Activate:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for {
		if item, err := sub.Get("key"); err == nil {
			if got := item.(largeItem); got.StrA != "a" || got.StrC != big {
				t.Fatalf("item corrupted: StrA %q, StrC of %d bytes", got.StrA, len(got.StrC))
			}
			break
		}
		select {
		case change := <-sub.MsgChan():
			sub.ProcessChange(change)
		case <-deadline:
			t.Fatal("timed out waiting for the item")
		}
	}
	if _, err := os.Stat(filepath.Join(rootPath, "persist", "pubsub-large")); !os.IsNotExist(err) {
		t.Fatalf("no pubsub-large files are expected, stat says %v", err)
	}
}
