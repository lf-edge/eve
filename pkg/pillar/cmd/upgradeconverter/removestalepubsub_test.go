// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRemoveStalePersistentTopics(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	statusDir := t.TempDir()

	makeTopic := func(parts ...string) string {
		dir := filepath.Join(append([]string{statusDir}, parts...)...)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"global.json", "restarted", "global.json.bak"} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte("x"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	// Listed (now non-persistent) topics must be removed.
	stale1 := makeTopic("zedagent", "ConfigItemValueMap")
	// A listed topic one level deeper (the AgentScope case).
	stale2 := makeTopic("nim", "global", "DeviceNetworkStatus")
	// Topics not on the list must survive, including their backup files:
	// a still-persistent publication, and state we cannot reason about
	// (removed publisher, non-Go component, ...).
	kept1 := makeTopic("zedclient", "OnboardingStatus")
	kept2 := makeTopic("goneagent", "GoneTopic")
	// A plain file at the top level is not ours; leave it alone.
	plainFile := filepath.Join(statusDir, "somefile")
	if err := os.WriteFile(plainFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	topicsFile := filepath.Join(t.TempDir(), "non-persistent-pubsub-topics")
	topics := "zedagent/ConfigItemValueMap\nnim/global/DeviceNetworkStatus\n"
	if err := os.WriteFile(topicsFile, []byte(topics), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := &ucContext{
		persistStatusDir:        statusDir,
		nonPersistentTopicsFile: topicsFile,
	}
	assert.NoError(t, removeStalePersistentTopics(ctx))

	assert.NoDirExists(t, stale1)
	assert.NoDirExists(t, stale2)
	// Removing the only listed topic of an agent leaves its (now empty)
	// parent directories in place; only the topic directory itself goes.
	assert.DirExists(t, kept1)
	assert.FileExists(t, filepath.Join(kept1, "restarted"))
	assert.FileExists(t, filepath.Join(kept1, "global.json.bak"))
	assert.DirExists(t, kept2)
	assert.FileExists(t, plainFile)
}

// TestRemoveStalePersistentTopicsNoList verifies that nothing is removed when
// the generated topics list is missing or empty: with a deny-list that is the
// safe direction, so the handler must not fail.
func TestRemoveStalePersistentTopicsNoList(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)

	check := func(topicsFile string) {
		statusDir := t.TempDir()
		topicDir := filepath.Join(statusDir, "zedagent", "ConfigItemValueMap")
		if err := os.MkdirAll(topicDir, 0755); err != nil {
			t.Fatal(err)
		}
		ctx := &ucContext{
			persistStatusDir:        statusDir,
			nonPersistentTopicsFile: topicsFile,
		}
		assert.NoError(t, removeStalePersistentTopics(ctx))
		assert.DirExists(t, topicDir)
	}

	// Missing list file.
	check(filepath.Join(t.TempDir(), "missing"))

	// Empty list file.
	emptyFile := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyFile, []byte("\n"), 0644); err != nil {
		t.Fatal(err)
	}
	check(emptyFile)
}
