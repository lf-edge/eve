// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// pubsub Interface.

package pubsub

// PublicationIntf - Interface to be implemented by a Publication
type PublicationIntf interface {
	// Publish - Publish an object
	Publish(key string, item interface{}) error
	// Unpublish - Delete / UnPublish an object
	Unpublish(key string) error
	// Get - Lookup an object
	Get(key string) (interface{}, error)
	// GetAll - Get a copy of the objects.
	GetAll() map[string]interface{}
}

// SubscriptionIntf - Interface to be implemented by a Subscription
type SubscriptionIntf interface {
	// Get - get / lookup an object by key
	Get(key string) (interface{}, error)
	// GetAll - Get a copy of the objects.
	GetAll() map[string]interface{}
}
