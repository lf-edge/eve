// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type mockPubSub struct{}

func (mockPubSub) IsRestarted() bool {
	return false
}

func (mockPubSub) RestartCounter() int {
	return 0
}

func (mockPubSub) DetermineDiffs(pubsub.LocalCollection) []string {
	return nil
}

func TestRecovery(t *testing.T) {
	// Run in a unique directory.
	rootPath, err := os.MkdirTemp("", "recovery_test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(rootPath)
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)

	newPublisher := func() pubsub.DriverPublisher {
		driver := socketdriver.SocketDriver{
			Logger:  logger,
			Log:     log,
			RootDir: rootPath,
		}
		publisher, err := driver.Publisher(false, "test", "item", true, &pubsub.Updaters{},
			mockPubSub{}, mockPubSub{})
		if err != nil {
			t.Fatal(err)
		}
		return publisher
	}
	publisher := newPublisher()
	err = publisher.Publish("global", []byte(`{"field":"abcdef"}`))
	if err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(rootPath, "persist", "status", "test", "global.json")
	_, err = os.Stat(filePath)
	if err != nil {
		t.Fatalf("published item was not persisted: %v", err)
	}
	// Nothing has been backed up yet, this was the first publication.
	backupPath := filePath + ".bak"
	_, err = os.Stat(backupPath)
	if !os.IsNotExist(err) {
		t.Fatal("unexpected backup file")
	}

	// Second publication, the first value should be copied to a backup file.
	err = publisher.Publish("global", []byte(`{"field":"123456"}`))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("missing backup file: %v", err)
	}

	// Simulate reboot without the persisted file getting lost.
	err = publisher.Stop()
	if err != nil {
		t.Logf("Stop failed: %v", err)
	}
	publisher = newPublisher()
	items, _, err := publisher.Load()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, items, 1)
	assert.Contains(t, items, "global")
	assert.Equal(t, items["global"], []byte(`{"field":"123456"}`))

	// Simulate reboot and the persisted file getting lost.
	err = os.Remove(filePath)
	if err != nil {
		t.Fatal(err)
	}
	err = publisher.Stop()
	if err != nil {
		t.Logf("Stop failed: %v", err)
	}
	publisher = newPublisher()
	// Load should recover the first publication.
	items, _, err = publisher.Load()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, items, 1)
	assert.Contains(t, items, "global")
	assert.Equal(t, items["global"], []byte(`{"field":"abcdef"}`))

	// Simulate reboot and the persisted file getting emptied.
	err = os.WriteFile(filePath, nil, file.Mode())
	if err != nil {
		t.Fatal(err)
	}
	err = publisher.Stop()
	if err != nil {
		t.Logf("Stop failed: %v", err)
	}
	publisher = newPublisher()
	// Load should recover the first publication.
	items, _, err = publisher.Load()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, items, 1)
	assert.Contains(t, items, "global")
	assert.Equal(t, items["global"], []byte(`{"field":"abcdef"}`))

	// Un-publish - backup file should be also removed.
	err = publisher.Unpublish("global")
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(backupPath)
	if !os.IsNotExist(err) {
		t.Fatal("unexpected backup file")
	}
}
