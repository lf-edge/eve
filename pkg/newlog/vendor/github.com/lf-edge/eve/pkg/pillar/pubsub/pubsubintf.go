// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// pubsub Interface.

package pubsub

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// Getter - Interface for pub/sub
type Getter interface {
	Get(key string) (interface{}, error)
}

// Publication - Interface to be implemented by a Publication
type Publication interface {
	// CheckMaxSize returns an error if the item is too large
	CheckMaxSize(key string, item interface{}) error
	// Publish - Publish an object
	Publish(key string, item interface{}) error
	// Unpublish - Delete / UnPublish an object
	Unpublish(key string) error
	// SignalRestarted - Signal the publisher has started one more time
	SignalRestarted() error
	// ClearRestarted clear the restarted flag
	ClearRestarted() error
	// Get - Lookup an object
	Get(key string) (interface{}, error)
	// GetAll - Get a copy of the objects.
	GetAll() map[string]interface{}
	// Iterate - Perform some action on all items
	Iterate(function base.StrMapFunc)
	// Close - delete the publisher
	Close() error
}

// Subscription - Interface to be implemented by a Subscription
type Subscription interface {
	// Get - get / lookup an object by key
	Get(key string) (interface{}, error)
	// GetAll - Get a copy of the objects.
	GetAll() map[string]interface{}
	// Iterate - Perform some action on all items
	Iterate(function base.StrMapFunc)
	// Restarted report if this subscription has been marked as restarted
	Restarted() bool
	// RestartCounter reports how many times this subscription has been restarted
	RestartCounter() int
	// Synchronized report if this subscription has received initial items
	Synchronized() bool
	// ProcessChange - Invoked on the string msg from Subscription Channel
	ProcessChange(change Change)
	// MsgChan - Message Channel for Subscription
	MsgChan() <-chan Change
	// Activate starts the subscription
	Activate() error
	// Close stops the subscription and removes the state
	Close() error
}
