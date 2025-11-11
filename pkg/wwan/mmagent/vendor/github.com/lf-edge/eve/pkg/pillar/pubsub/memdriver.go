// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// MemoryDriver is an in-memory PubSub driver designed for writing tests for components
// that use PubSub. It provides a simple, synchronous implementation without any persistence
// or file system dependencies.
//
// Purpose:
//   - Used exclusively for testing PubSub-based components in isolated environments
//   - Enables deterministic, event-driven tests with full control over message flow
//   - Avoids file system operations and external dependencies in test scenarios
//
// Limitation:
//   - Only one subscriber is supported per topic when using notification channels
//   - Multiple subscribers attempting to use the same topic will overwrite each other's
//     notification channel, causing only the last registered subscriber to receive updates
//
// This driver should not be used in production code.
type MemoryDriver struct {
	status      *generics.LockedMap[string, []byte]
	subscribers *generics.LockedMap[string, chan Change]
}

const tmpDir = "/tmp"

// NewMemoryDriver to create MemoryDriver and properly initialize it
func NewMemoryDriver() *MemoryDriver {
	return &MemoryDriver{
		status:      generics.NewLockedMap[string, []byte](),
		subscribers: generics.NewLockedMap[string, chan Change](),
	}
}

const separator = "|"

func composeStatusKey(topic, key string) string {
	return topic + separator + key
}

func decomposeStatusKey(statusKey string) (string, string) {
	before, after, _ := strings.Cut(statusKey, separator)
	return before, after
}

// Publisher function
func (e *MemoryDriver) Publisher(_ bool, _, topic string, _ bool, _ *Updaters, _ Restarted, _ Differ) (DriverPublisher, error) {
	return &MemoryDriverPublisher{
		topic:       topic,
		status:      e.status,
		subscribers: e.subscribers,
	}, nil
}

// Subscriber function
func (e *MemoryDriver) Subscriber(_ bool, _, topic string, _ bool, C chan Change) (DriverSubscriber, error) {
	// Register the subscriber channel using topic as key
	if C != nil {
		e.subscribers.Store(topic, C)
	}
	return &MemoryDriverSubscriber{
		topic:       topic,
		status:      e.status,
		subscribers: e.subscribers,
		changeChan:  C,
	}, nil
}

// DefaultName function
func (e *MemoryDriver) DefaultName() string {
	return "memory"
}

// MemoryDriverPublisher struct
type MemoryDriverPublisher struct {
	topic       string
	status      *generics.LockedMap[string, []byte]
	subscribers *generics.LockedMap[string, chan Change]
}

// Start function
func (e *MemoryDriverPublisher) Start() error {
	return nil
}

// Load function
func (e *MemoryDriverPublisher) Load() (map[string][]byte, int, error) {
	res := make(map[string][]byte)
	e.status.Range(func(k string, v []byte) bool {
		topic, realKey := decomposeStatusKey(k)
		if topic != e.topic {
			// Skipping topics which are not related
			return true
		}
		res[realKey] = v
		return true
	})
	return res, 0, nil
}

// CheckMaxSize function
func (e *MemoryDriverPublisher) CheckMaxSize(string, []byte) error {
	return nil
}

// Publish function
func (e *MemoryDriverPublisher) Publish(key string, item []byte) error {
	e.status.Store(composeStatusKey(e.topic, key), item)

	// Notify subscribers if channel exists
	if ch, ok := e.subscribers.Load(e.topic); ok {
		select {
		case ch <- Change{
			Operation: Modify,
			Key:       key,
			Value:     item,
		}:
		default:
			// Channel full or closed, skip
		}
	}

	return nil
}

// Unpublish function
func (e *MemoryDriverPublisher) Unpublish(key string) error {
	e.status.Delete(composeStatusKey(e.topic, key))

	// Notify subscribers if channel exists
	if ch, ok := e.subscribers.Load(e.topic); ok {
		select {
		case ch <- Change{
			Operation: Delete,
			Key:       key,
			Value:     nil,
		}:
		default:
			// Channel full or closed, skip
		}
	}

	return nil
}

// Restart function
func (e *MemoryDriverPublisher) Restart(_ int) error {
	return nil
}

// Stop function
func (e *MemoryDriverPublisher) Stop() error {
	return nil
}

// LargeDirName where to put large fields
func (e *MemoryDriverPublisher) LargeDirName() string {
	return tmpDir
}

// MemoryDriverSubscriber struct
type MemoryDriverSubscriber struct {
	topic       string
	status      *generics.LockedMap[string, []byte]
	subscribers *generics.LockedMap[string, chan Change]
	changeChan  chan Change
}

// Start function
func (e *MemoryDriverSubscriber) Start() error {
	return nil
}

// Load function
func (e *MemoryDriverSubscriber) Load() (map[string][]byte, int, error) {
	res := make(map[string][]byte)
	e.status.Range(func(k string, v []byte) bool {
		topic, realKey := decomposeStatusKey(k)
		if topic != e.topic {
			// Skipping topics which are not related
			return true
		}
		res[realKey] = v
		return true
	})
	return res, 0, nil
}

// Stop function
func (e *MemoryDriverSubscriber) Stop() error {
	// Unregister the subscriber channel
	e.subscribers.Delete(e.topic)
	return nil
}

// LargeDirName where to put large fields
func (e *MemoryDriverSubscriber) LargeDirName() string {
	return tmpDir
}
