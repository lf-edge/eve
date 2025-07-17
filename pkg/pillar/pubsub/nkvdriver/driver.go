// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/nkval/go-nkv/pkg/client"
)

const sockPath = "/run/nkv.sock"

type NkvDriver struct {
	socketPath string
	client     *client.Client
}

func NewNkvDriver(path string) *NkvDriver {
	if path == "" {
		path = sockPath
	}
	nkvClient := client.NewClient(path)

	return &NkvDriver{
		socketPath: sockPath,
		client:     nkvClient,
	}
}

// (global bool, name, topic string, persistent bool, updaterList *pubsub.Updaters, restarted pubsub.Restarted, differ pubsub.Differ) (pubsub.DriverPublisher, error) {
func (d *NkvDriver) Publisher(_ bool, name, topic string, _ bool, _ *pubsub.Updaters, _ pubsub.Restarted, _ pubsub.Differ) (pubsub.DriverPublisher, error) {
	return &Publisher{nkvClient: d.client, name: name, topic: topic}, nil
}

// TODO: perhaps channel is needed
func (d *NkvDriver) Subscriber(_ bool, _, topic string, _ bool, C chan pubsub.Change) (pubsub.DriverSubscriber, error) {
	return &Subscriber{nkvClient: d.client, topic: topic, C: C}, nil
}

func (d *NkvDriver) DefaultName() string {
	return "nkv"
}
