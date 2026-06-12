// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"path/filepath"
	"strings"
)

// nonPersistentTopicsFile lists every pubsub publication of this EVE version
// that is published only non-persistently, as "<agentName>/<topic>", one per
// line. It is generated from the pillar sources by
// pkg/pillar/tools/pubsubcheck while building the pillar container image, so
// it can never go out of sync with the code.
const nonPersistentTopicsFile = "/opt/zededa/etc/non-persistent-pubsub-topics"

// removeStalePersistentTopics deletes the directories under /persist/status
// that belong to a topic which is non-persistent in the current EVE version,
// per the generated nonPersistentTopicsFile.
//
// Such a directory is left behind when a publication that used to be
// persistent stops being persistent in an EVE upgrade. It must go away
// before any pubsub process starts: a persistent subscriber pre-loads its
// initial state from these directories at activation time and would
// otherwise consume the stale state of the previous EVE version. This
// handler runs in the pre-vault phase from the pillar-onboot container, i.e.
// strictly before any subscriber service is started.
//
// Only topics statically known to be non-persistent are removed. State of
// publishers removed entirely, of non-Go components, or of publications
// outside the pillar sources is intentionally left in place: the generated
// list cannot see them, and leaving unknown state alone is the safe
// direction (the opposite mistake would delete live state). For the same
// reason a missing or unreadable list removes nothing.
//
// This handler must run after any handler that moves or converts persistent
// pubsub state (it removes whatever those leave behind).
func removeStalePersistentTopics(ctxPtr *ucContext) error {
	nonPersistent, err := readNonPersistentTopics(ctxPtr.nonPersistentTopicsFile)
	if err != nil {
		// Without a list we do not know which topics turned
		// non-persistent. Remove nothing; this is the safe direction.
		log.Warnf("removeStalePersistentTopics: not removing any pubsub state: %v", err)
		return nil
	}
	removeListedTopics(ctxPtr.persistStatusDir, "", nonPersistent)
	return nil
}

// readNonPersistentTopics parses the generated list of non-persistent topics.
// An empty list is fine: removeListedTopics then removes nothing.
func readNonPersistentTopics(file string) (map[string]bool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	topics := make(map[string]bool)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			topics[line] = true
		}
	}
	return topics, nil
}

// removeListedTopics removes the subdirectories of dir whose list key
// (prefix + directory name) is listed. It recurses into directories that are
// not listed themselves but are a prefix of a listed entry (the AgentScope
// case, where the listed topic sits one level deeper). Everything else,
// including all plain files, is left untouched: the current pubsub
// implementation writes no plain files here, so they are not ours to remove.
func removeListedTopics(dir, prefix string, nonPersistent map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("removeListedTopics: %v", err)
		}
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		key := prefix + entry.Name()
		subDir := filepath.Join(dir, entry.Name())
		if nonPersistent[key] {
			log.Noticef("removeListedTopics: removing stale persistent pubsub state %s",
				subDir)
			if err := os.RemoveAll(subDir); err != nil {
				log.Errorf("removeListedTopics: failed to remove %s: %v", subDir, err)
			}
			continue
		}
		if hasEntryWithPrefix(nonPersistent, key+"/") {
			removeListedTopics(subDir, key+"/", nonPersistent)
		}
	}
}

func hasEntryWithPrefix(topics map[string]bool, prefix string) bool {
	for entry := range topics {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}
