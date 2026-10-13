// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver_test

import (
	"bytes"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// statsTestID keeps the counters of repeated runs (-count) apart: they are
// kept per publication name for the life of the process.
var statsTestID atomic.Int32

func TestSocketDriverStats(t *testing.T) {
	rootPath, err := os.MkdirTemp("", "stats_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootPath)
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	driver := socketdriver.SocketDriver{Logger: logger, Log: log, RootDir: rootPath}

	name := fmt.Sprintf("statsagent%d/item", statsTestID.Add(1))
	differ := staticDiffer{items: map[string][]byte{
		"small": bytes.Repeat([]byte("s"), 2*1024),
		"big":   bytes.Repeat([]byte("b"), 100*1024),
	}}
	publisher, err := driver.Publisher(false, name, "item", false,
		&pubsub.Updaters{}, differ, differ)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Start(); err != nil {
		t.Fatal(err)
	}
	changes := make(chan pubsub.Change, 10)
	subscriber, err := driver.Subscriber(false, name, "item", false, changes)
	if err != nil {
		t.Fatal(err)
	}
	if err := subscriber.Start(); err != nil {
		t.Fatal(err)
	}
	for synced := false; !synced; {
		select {
		case c := <-changes:
			synced = c.Operation == pubsub.Sync
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for the initial sync")
		}
	}

	pub := pubsub.PublicationStats(name)
	sub := pubsub.SubscriptionStats(name)
	// hello, two updates and complete.
	if pub.Messages.Load() != 4 || sub.Frames.Load() != 4 {
		t.Errorf("messages %d frames %d, want 4", pub.Messages.Load(), sub.Frames.Load())
	}
	if pub.Bytes.Load() != sub.Bytes.Load() || pub.MaxMessage.Load() != sub.MaxFrame.Load() {
		t.Errorf("sent %d/%d bytes/max, received %d/%d", pub.Bytes.Load(),
			pub.MaxMessage.Load(), sub.Bytes.Load(), sub.MaxFrame.Load())
	}
	if pub.MaxMessage.Load() < 100*1024 {
		t.Errorf("max message %d, want at least 100 KiB", pub.MaxMessage.Load())
	}
	if pub.LargeWarnings.Load() != 1 || sub.OversizedFrames.Load() != 1 {
		t.Errorf("large warnings %d oversized frames %d, want 1 each",
			pub.LargeWarnings.Load(), sub.OversizedFrames.Load())
	}
	if pub.Connections.Load() != 1 || sub.Subscribers.Load() != 1 {
		t.Errorf("connections %d subscribers %d, want 1 each",
			pub.Connections.Load(), sub.Subscribers.Load())
	}
	waitFor(t, "the idle subscription to hold no read buffer", func() bool {
		return sub.RetainedBufBytes.Load() == 0
	})

	subscriber.Stop()
	waitFor(t, "the subscriber to release its buffer", func() bool {
		return sub.Subscribers.Load() == 0 && sub.RetainedBufBytes.Load() == 0
	})
	publisher.Stop()
	waitFor(t, "the publisher to drop the connection", func() bool {
		return pub.Connections.Load() == 0
	})
}
