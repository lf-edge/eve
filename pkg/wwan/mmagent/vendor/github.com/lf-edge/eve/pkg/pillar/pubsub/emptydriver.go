// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

// Enable testing of pubsub when no actual work is needed.

// EmptyDriver struct
type EmptyDriver struct{}

// Publisher function
func (e *EmptyDriver) Publisher(global bool, name, topic string, persistent bool, updaterList *Updaters, restarted Restarted, differ Differ) (DriverPublisher, error) {
	return &EmptyDriverPublisher{}, nil
}

// Subscriber function
func (e *EmptyDriver) Subscriber(global bool, name, topic string, persistent bool, C chan Change) (DriverSubscriber, error) {
	return &EmptyDriverSubscriber{}, nil
}

// DefaultName function
func (e *EmptyDriver) DefaultName() string {
	return "empty"
}

// EmptyDriverPublisher struct
type EmptyDriverPublisher struct{}

// Start function
func (e *EmptyDriverPublisher) Start() error {
	return nil
}

// Load function
func (e *EmptyDriverPublisher) Load() (map[string][]byte, int, error) {
	return make(map[string][]byte), 0, nil
}

// CheckMaxSize function
func (e *EmptyDriverPublisher) CheckMaxSize(key string, val []byte) error {
	return nil
}

// Publish function
func (e *EmptyDriverPublisher) Publish(key string, item []byte) error {
	return nil
}

// Unpublish function
func (e *EmptyDriverPublisher) Unpublish(key string) error {
	return nil
}

// Restart function
func (e *EmptyDriverPublisher) Restart(restartCounter int) error {
	return nil
}

// Stop function
func (e *EmptyDriverPublisher) Stop() error {
	return nil
}

// LargeDirName where to put large fields
func (e *EmptyDriverPublisher) LargeDirName() string {
	return "/tmp"
}

// EmptyDriverSubscriber struct
type EmptyDriverSubscriber struct{}

// Start function
func (e *EmptyDriverSubscriber) Start() error {
	return nil
}

// Load function
func (e *EmptyDriverSubscriber) Load() (map[string][]byte, int, error) {
	res := make(map[string][]byte)
	return res, 0, nil
}

// Stop function
func (e *EmptyDriverSubscriber) Stop() error {
	return nil
}

// LargeDirName where to put large fields
func (e *EmptyDriverSubscriber) LargeDirName() string {
	return "/tmp"
}
