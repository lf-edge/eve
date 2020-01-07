// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// pubsub Interface.

package pubsub

// Publication - Interface to be implemented by a Publication
type Publication interface {
	// Publish - Publish an object
	Publish(key string, item interface{}) error
	// Unpublish - Delete / UnPublish an object
	Unpublish(key string) error
	// SignalRestarted - Signal the publisher has started.
	SignalRestarted() error
	// Get - Lookup an object
	Get(key string) (interface{}, error)
	// GetAll - Get a copy of the objects.
	GetAll() map[string]interface{}
}

// Subscription - Interface to be implemented by a Subscription
type Subscription interface {
	// Get - get / lookup an object by key
	Get(key string) (interface{}, error)
	// GetAll - Get a copy of the objects.
	GetAll() map[string]interface{}
	// ProcessChange - Invoked on the string msg from Subscription Channel
	ProcessChange(change string)
	// MsgChan - Message Channel for Subscription
	MsgChan() <-chan string
}
