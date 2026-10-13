// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
)

// staticDiffer hands a fixed set of items to every connecting subscriber.
type staticDiffer struct {
	mockPubSub
	items map[string][]byte
}

func (d staticDiffer) DetermineDiffs(local pubsub.LocalCollection) []string {
	var keys []string
	for key, val := range d.items {
		if _, ok := local[key]; !ok {
			local[key] = val
			keys = append(keys, key)
		}
	}
	return keys
}

// TestLargeMessage verifies that values well beyond the old 64KB datagram
// limit, and close to maxsize, are delivered intact from a publisher to a
// subscriber.
func TestLargeMessage(t *testing.T) {
	for _, size := range []int{200 * 1024, 1000 * 1024} {
		rootPath, err := os.MkdirTemp("", "largemsg_test")
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

		// Values are JSON and can contain spaces, which also separate
		// the fields of a message.
		val := bytes.Repeat([]byte("x "), size/2)
		differ := staticDiffer{items: map[string][]byte{"key": val}}
		publisher, err := driver.Publisher(false, "testagent/item", "item",
			false, &pubsub.Updaters{}, differ, differ)
		if err != nil {
			t.Fatal(err)
		}
		if err := publisher.Start(); err != nil {
			t.Fatal(err)
		}

		changes := make(chan pubsub.Change, 10)
		subscriber, err := driver.Subscriber(false, "testagent/item", "item",
			false, changes)
		if err != nil {
			t.Fatal(err)
		}
		if err := subscriber.Start(); err != nil {
			t.Fatal(err)
		}

		select {
		case change := <-changes:
			if change.Operation != pubsub.Modify || change.Key != "key" {
				t.Fatalf("expected Modify of key, got %v %s",
					change.Operation, change.Key)
			}
			if !bytes.Equal(change.Value, val) {
				t.Fatalf("value of %d bytes corrupted, got %d bytes",
					size, len(change.Value))
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for the %d byte value", size)
		}
		subscriber.Stop()
		publisher.Stop()
	}
}
