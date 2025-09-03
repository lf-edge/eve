// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/nkval/go-nkv/pkg/client"
)

const sockPath = "/run/nkv.sock"

type NkvDriver struct {
	socketPath string
	client     *client.Client
}

func NewNkvDriver(path, uuid string) *NkvDriver {
	if path == "" {
		path = sockPath
	}

	nkvClient := client.NewClient(path, uuid)

	driver := NkvDriver{
		socketPath: sockPath,
		client:     nkvClient,
	}

	// driver.client.Delete(driver.pubDirName("*"))

	return &driver
}

// (global bool, name, topic string, persistent bool, updaterList *pubsub.Updaters, restarted pubsub.Restarted, differ pubsub.Differ) (pubsub.DriverPublisher, error) {
func (d *NkvDriver) Publisher(global bool, name, topic string, persistent bool, updaterList *pubsub.Updaters, restarted pubsub.Restarted, differ pubsub.Differ) (pubsub.DriverPublisher, error) {
	var (
		dirName      string
		publishToDir bool
	)
	switch {
	case persistent && global:
		// No longer supported
		return nil, errors.New("Persistent not supported for empty agentname")
	case persistent && !global:
		dirName = d.persistentDirName(name)
	case !persistent && publishToDir:
		// Special case for /run/global
		dirName = d.fixedDirName(name)
	default:
		dirName = d.pubDirName(name)
	}
	return &Publisher{
		nkvClient: d.client,
		name:      dirName,
		topic:     topic,
	}, nil
}

func (s *NkvDriver) pubDirName(name string) string {
	if name != "" {
		return fmt.Sprintf("runtime.%s", name)
	} else {
		return "default"
	}
}

func (s *NkvDriver) fixedDirName(name string) string {
	if name != "" {
		return fmt.Sprintf("runtime.fixeddir.%s", name)
	} else {
		return "runtime"
	}
}

func (s *NkvDriver) persistentDirName(name string) string {
	if name != "" {
		return fmt.Sprintf("persist.%s", name)
	} else {
		return "persist"
	}
}

// TODO: perhaps channel is needed
func (s *NkvDriver) Subscriber(global bool, name, topic string, persistent bool, C chan pubsub.Change) (pubsub.DriverSubscriber, error) {
	var (
		dirName      string
		publishToDir bool
	)
	switch {
	case persistent && global:
		// No longer supported
		return nil, errors.New("Persistent not supported for empty agentname")
	case persistent && !global:
		dirName = s.persistentDirName(name)
	case !persistent && publishToDir:
		// Special case for /run/global
		dirName = s.fixedDirName(name)
	default:
		dirName = s.pubDirName(name)
	}
	return &Subscriber{nkvClient: s.client, name: dirName, topic: topic, C: C}, nil
}

func (d *NkvDriver) DefaultName() string {
	return "global"
}

func stripKey(k string) string {
	// data is in format default.global.item.key1 -> value
	// we just need key1 -> value
	parts := strings.Split(k, ".")
	return parts[len(parts)-1]
}
