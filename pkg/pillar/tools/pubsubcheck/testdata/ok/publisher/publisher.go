// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Test fixture: a persistent publication of pubagent/Foo.
package publisher

const agentName = "pubagent"

func setup(ps PS) {
	ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  types.Foo{},
		Persistent: true,
	})
}
