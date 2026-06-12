// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Test fixture: a persistent subscription to the persistent publication
// of pubagent/Foo.
package subscriber

func setup(ps PS) {
	ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:  "pubagent",
		TopicImpl:  types.Foo{},
		Persistent: true,
	})
}
