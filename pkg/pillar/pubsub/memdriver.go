// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// MemoryDriver structure
type MemoryDriver struct {
	status *generics.LockedMap[string, []byte]
}

const tmpDir = "/tmp"

// NewMemoryDriver to create MemoryDriver and properly initialize it
func NewMemoryDriver() *MemoryDriver {
	return &MemoryDriver{
		status: generics.NewLockedMap[string, []byte](),
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
		topic:  topic,
		status: e.status,
	}, nil
}

// Subscriber function
func (e *MemoryDriver) Subscriber(_ bool, _, topic string, _ bool, _ chan Change) (DriverSubscriber, error) {
	return &MemoryDriverSubscriber{
		topic:  topic,
		status: e.status,
	}, nil
}

// DefaultName function
func (e *MemoryDriver) DefaultName() string {
	return "memory"
}

// MemoryDriverPublisher struct
type MemoryDriverPublisher struct {
	topic  string
	status *generics.LockedMap[string, []byte]
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
	return nil
}

// Unpublish function
func (e *MemoryDriverPublisher) Unpublish(key string) error {
	e.status.Delete(composeStatusKey(e.topic, key))
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
	topic  string
	status *generics.LockedMap[string, []byte]
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
	return nil
}

// LargeDirName where to put large fields
func (e *MemoryDriverSubscriber) LargeDirName() string {
	return ""
}
