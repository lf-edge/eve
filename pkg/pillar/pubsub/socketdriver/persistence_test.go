// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver_test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
)

// handshakeTestID makes the log source name of each handshake run unique.
var handshakeTestID atomic.Int32

// syncBuffer is a goroutine-safe bytes.Buffer for capturing log output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runHandshake connects a subscriber to a publisher with the given
// persistence settings and returns the log output produced by the
// subscriber once the initial handshake (hello..complete) is done.
func runHandshake(t *testing.T, pubPersistent, subPersistent bool) string {
	t.Helper()
	rootPath, err := os.MkdirTemp("", "handshake_test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(rootPath)

	var logOutput syncBuffer
	logger := logrus.New()
	logger.SetOutput(&logOutput)
	// NewSourceLogObject caches objects (and thus loggers) per source name,
	// so use a unique name to get a LogObject bound to this test's logger.
	source := fmt.Sprintf("test-%d", handshakeTestID.Add(1))
	log := base.NewSourceLogObject(logger, source, 1234)

	driver := socketdriver.SocketDriver{
		Logger:  logger,
		Log:     log,
		RootDir: rootPath,
	}

	publisher, err := driver.Publisher(false, "testagent/item", "item",
		pubPersistent, &pubsub.Updaters{}, mockPubSub{}, mockPubSub{})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Start(); err != nil {
		t.Fatal(err)
	}
	defer publisher.Stop()

	changes := make(chan pubsub.Change, 10)
	subscriber, err := driver.Subscriber(false, "testagent/item", "item",
		subPersistent, changes)
	if err != nil {
		t.Fatal(err)
	}
	if err := subscriber.Start(); err != nil {
		t.Fatal(err)
	}
	defer subscriber.Stop()

	// The publisher sends "hello" followed by "complete"; the latter is
	// translated into a Sync change. By then the hello message, including
	// the persistence handshake, has been processed.
	select {
	case change := <-changes:
		if change.Operation != pubsub.Sync {
			t.Fatalf("expected Sync change, got %v", change.Operation)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the initial handshake")
	}
	return logOutput.String()
}

// TestPersistenceMismatchLogged verifies that a persistent subscription to a
// non-persistent publication produces an error log during the handshake,
// and that matched configurations do not.
func TestPersistenceMismatchLogged(t *testing.T) {
	const mismatchMsg = "but the publisher is not"

	output := runHandshake(t, false, true)
	if !strings.Contains(output, mismatchMsg) {
		t.Errorf("expected mismatch error in log output, got: %s", output)
	}

	output = runHandshake(t, true, true)
	if strings.Contains(output, mismatchMsg) {
		t.Errorf("unexpected mismatch error in log output: %s", output)
	}

	output = runHandshake(t, false, false)
	if strings.Contains(output, mismatchMsg) {
		t.Errorf("unexpected mismatch error in log output: %s", output)
	}
}
