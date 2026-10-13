// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver_test

import (
	"fmt"
	"net"
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

// TestStopWhileStreaming stops subscriptions while the publisher is still
// sending its initial dump, so that Stop races with the read goroutine
// leaving through its done path.
func TestStopWhileStreaming(t *testing.T) {
	rootPath, err := os.MkdirTemp("", "stop_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootPath)
	logger := logrus.New()
	logger.SetOutput(&syncBuffer{})
	log := base.NewSourceLogObject(logger, "stoptest", 1234)
	driver := socketdriver.SocketDriver{Logger: logger, Log: log, RootDir: rootPath}

	items := make(map[string][]byte)
	for i := 0; i < 3000; i++ {
		items[fmt.Sprintf("key%d", i)] = []byte(`{"value":"0123456789"}`)
	}
	differ := staticDiffer{items: items}
	name := fmt.Sprintf("stopagent%d/item", statsTestID.Add(1))
	publisher, err := driver.Publisher(false, name, "item", false,
		&pubsub.Updaters{}, differ, differ)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Start(); err != nil {
		t.Fatal(err)
	}
	defer publisher.Stop()

	for i := 0; i < 50; i++ {
		changes := make(chan pubsub.Change, 3)
		subscriber, err := driver.Subscriber(false, name, "item", false, changes)
		if err != nil {
			t.Fatal(err)
		}
		if err := subscriber.Start(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-changes:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for the dump to start")
		}
		go func() {
			for range changes {
			}
		}()
		if err := subscriber.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	sub := pubsub.SubscriptionStats(name)
	waitFor(t, "all subscriptions to disconnect", func() bool {
		return sub.Subscribers.Load() == 0 && sub.RetainedBufBytes.Load() == 0
	})
}

// TestOldProtocolPublisherReported checks that a subscriber tells when the
// publisher still listens on a unixpacket socket instead of retrying in
// silence.
func TestOldProtocolPublisherReported(t *testing.T) {
	rootPath, err := os.MkdirTemp("", "oldproto_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootPath)
	var logOutput syncBuffer
	logger := logrus.New()
	logger.SetOutput(&logOutput)
	log := base.NewSourceLogObject(logger, fmt.Sprintf("oldproto-%d", statsTestID.Add(1)), 1234)
	driver := socketdriver.SocketDriver{Logger: logger, Log: log, RootDir: rootPath}

	sockName := filepath.Join(rootPath, "var/run/oldagent/item.sock")
	if err := os.MkdirAll(filepath.Dir(sockName), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unixpacket", sockName)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	subscriber, err := driver.Subscriber(false, "oldagent/item", "item", false,
		make(chan pubsub.Change, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := subscriber.Start(); err != nil {
		t.Fatal(err)
	}
	defer subscriber.Stop()
	waitFor(t, "an error about the protocol", func() bool {
		return strings.Contains(logOutput.String(), "different pubsub wire protocol")
	})
	if !strings.Contains(logOutput.String(), `"level":"error"`) &&
		!strings.Contains(logOutput.String(), "level=error") {
		t.Errorf("the protocol mismatch must be logged as an error:\n%s", logOutput.String())
	}
}
