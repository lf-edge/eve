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

func NewNkvDriver() *NkvDriver {
	nkvClient := client.NewClient(sockPath)

	return &NkvDriver{
		socketPath: sockPath,
		client:     nkvClient,
	}
}

func (d *NkvDriver) Publisher(_ bool, _, topic string, _ bool, _ *pubsub.Updaters, _ pubsub.Restarted, _ pubsub.Differ) (pubsub.DriverPublisher, error) {
	return &Publisher{nkvClient: d.client, topic: topic}, nil
}

// TODO: perhaps channel is needed
func (d *NkvDriver) Subscriber(_ bool, _, topic string, _ bool, _ chan pubsub.Change) (pubsub.DriverSubscriber, error) {
	return &Subscriber{nkvClient: d.client, topic: topic}, nil
}

func (d *NkvDriver) DefaultName() string {
	return "nkv"
}
