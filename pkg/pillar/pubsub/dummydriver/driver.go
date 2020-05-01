// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dummydriver

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

const (
	fixedName = "zededa"
)

// DummyDriver driver for pubsub for testing
type DummyDriver struct {
}

// Publisher return an implementation of `pubsub.DriverPublisher` for
// `DummyDriver`
func (s *DummyDriver) Publisher(global bool, name, topic string, persistent bool, updaterList *pubsub.Updaters, restarted pubsub.Restarted, differ pubsub.Differ) (pubsub.DriverPublisher, error) {

	return &Publisher{
		name:  name,
		topic: topic,
	}, nil
}

// Subscriber return an implementation of `pubsub.DriverSubscriber` for
// `DummyDriver`
func (s *DummyDriver) Subscriber(global bool, name, topic string, persistent bool, C chan pubsub.Change) (pubsub.DriverSubscriber, error) {
	return &Subscriber{
		name:  name,
		topic: topic,
		C:     C,
	}, nil
}

// DefaultName default name for an agent when none is provided
func (s *DummyDriver) DefaultName() string {
	return fixedName
}

// Publisher implementation of `pubsub.DriverPublisher` for `DummyDriver`.
type Publisher struct {
	name  string
	topic string
}

// Load load entire persisted data set into a map
func (s *Publisher) Load() (map[string][]byte, bool, error) {
	items := make(map[string][]byte)
	return items, false, nil
}

// Start start publishing
func (s *Publisher) Start() error {
	return nil
}

// Publish publish a key-value pair
func (s *Publisher) Publish(key string, item []byte) error {
	return nil
}

// Unpublish delete a key and publish its deletion
func (s *Publisher) Unpublish(key string) error {
	return nil
}

// Restart indicate that the topic is restarted, or clear it
func (s *Publisher) Restart(restarted bool) error {
	return nil
}

// Subscriber implementation of `pubsub.DriverSubscriber` for `DummyDriver`.
type Subscriber struct {
	name  string
	topic string
	C     chan<- pubsub.Change
}

// Load load entire persisted data set into a map
func (s *Subscriber) Load() (map[string][]byte, bool, error) {
	items := make(map[string][]byte)
	return items, false, nil
}

// Start start the subscriber listening on the given name and topic
func (s *Subscriber) Start() error {
	return nil
}
