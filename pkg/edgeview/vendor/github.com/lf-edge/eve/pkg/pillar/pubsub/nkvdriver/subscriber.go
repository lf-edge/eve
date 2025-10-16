// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/nkval/go-nkv/pkg/client"
	p "github.com/nkval/go-nkv/pkg/protocol"
)

type Subscriber struct {
	nkvClient *client.Client
	name      string
	C         chan<- pubsub.Change
	topic     string
}

func (e *Subscriber) Start() error {
	restartKey := restartCounterKey(e.name)

	_, err := e.nkvClient.Subscribe(restartKey, func(n p.Notification) {
		if n.Type == p.NotificationUpdate {
			var valInt map[string]int
			json.Unmarshal(n.Data, &valInt)
			e.C <- pubsub.Change{Operation: pubsub.Restart, Key: strconv.Itoa(valInt["value"])}
		}
	})
	if err != nil {
		return err
	}

	resp, err := e.nkvClient.Get(e.name + ".*")
	if err != nil {
		return err
	}
	data, ok := resp.Data.(p.HashMapStringBytes)
	if !ok {
		return fmt.Errorf("Couldn't convert data to HashMap type")
	}
	done := make(chan int)
	go func() {
		for key, val := range data {
			e.C <- pubsub.Change{
				Operation: pubsub.Modify,
				Key:       stripKey(key),
				Value:     val,
			}
		}
		close(done)
	}()

	go func() {
		<-done // wait initial lookup to propagate
		_, _ = e.nkvClient.Subscribe(e.name, func(n p.Notification) {
			if n.Type == p.NotificationUpdate {
				e.C <- pubsub.Change{Operation: pubsub.Modify, Key: stripKey(n.Key), Value: n.Data}
			}
			if n.Type == p.NotificationClose {
				change := pubsub.Change{Operation: pubsub.Delete, Key: stripKey(n.Key)}
				e.C <- change
			}
		})
	}()

	restartResp, err := e.nkvClient.Get(restartKey)
	restartData, ok := restartResp.Data.(p.HashMapStringBytes)
	if !ok {
		return fmt.Errorf("Wrong convertion from HashMap type of restart counter")
	}
	// TODO: add handling with __sync__ counters
	go func() {
		var restartMap map[string]int
		json.Unmarshal(restartData[restartKey], &restartMap)
		e.C <- pubsub.Change{Operation: pubsub.Restart, Key: strconv.Itoa(restartMap["value"])}
		e.C <- pubsub.Change{Operation: pubsub.Sync, Key: "done"}
	}()
	return nil
}

func (e *Subscriber) Load() (map[string][]byte, int, error) {
	// nkv is server based solution, not p2p, so there's
	// no need for load, left for backward compatibility
	// with PubSub interface

	entries, err := e.nkvClient.Get(e.name + ".*")
	if err != nil {
		return nil, 1, err
	}
	data, ok := entries.Data.(p.HashMapStringBytes)
	if !ok {
		return nil, 1, fmt.Errorf("Couldn't convert data to HashMap type")
	}
	// data is in format default.global.item.key1 -> value
	// we just need key1 -> value
	ans := make(map[string][]byte)
	for k, v := range data {
		ans[stripKey(k)] = v
	}

	return ans, 1, nil
}

func (e *Subscriber) Stop() error { return nil }

func (e *Subscriber) LargeDirName() string { return "" }
