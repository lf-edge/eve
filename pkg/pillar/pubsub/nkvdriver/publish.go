// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"encoding/json"
	"fmt"

	"github.com/nkval/go-nkv/pkg/client"
	"github.com/nkval/go-nkv/pkg/protocol"
)

type Publisher struct {
	nkvClient *client.Client
	name      string
	topic     string
}

const RESTART_COUTNER_TOPIC = "__restart__"

func (p *Publisher) Start() error { return nil }

func (p *Publisher) Load() (map[string][]byte, int, error) {
	// nkv is server based solution, not p2p, so there's
	// no need for load, left for backward compatibility
	// with PubSub interface

	restartCounter, err := p.fetchRestartCounter()
	if err != nil {
		return nil, 0, err
	}

	entries, err := p.nkvClient.Get(p.name + ".*")
	if err != nil {
		return nil, restartCounter, err
	}

	data, ok := entries.Data.(protocol.HashMapStringBytes)
	if !ok {
		return nil, restartCounter, fmt.Errorf("Wrong response type")
	}

	// data is in format default.global.item.key1 -> value
	// we just need key1 -> value
	ans := make(map[string][]byte)
	for k, v := range data {
		ans[stripKey(k)] = v
	}

	return ans, restartCounter, nil
}

func (p *Publisher) Publish(key string, item []byte) error {
	k := p.name + "." + key
	_, err := p.nkvClient.Put(k, item)
	return err
}

func (s *Publisher) Unpublish(key string) error {
	k := s.name + "." + key
	_, err := s.nkvClient.Delete(k)
	return err
}

func (p *Publisher) Restart(restartCounter int) error {
	jsonBytes, err := json.Marshal(map[string]int{"value": restartCounter})
	if err != nil {
		return err
	}

	_, err = p.nkvClient.Put(restartCounterKey(p.name), jsonBytes)
	return err
}

func (p *Publisher) Stop() error { return nil /* no need */ }

func (p *Publisher) CheckMaxSize(_key string, _val []byte) error { return nil /* no limitations */ }

func (p *Publisher) LargeDirName() string { /* no need */
	return ""
}

func (p *Publisher) fetchRestartCounter() (int, error) {
	resp, err := p.nkvClient.Get(restartCounterKey(p.name))
	if err != nil {
		return 0, err
	}
	if !resp.Status {
		// populate expects JSON for each value
		jsonBytes, err := json.Marshal(map[string]int{"value": 1})
		if err != nil {
			return 0, err
		}
		p.nkvClient.Put(restartCounterKey(p.name), jsonBytes)
		return 0, nil
	}

	d, ok := resp.Data.(protocol.HashMapStringBytes)
	if !ok {
		return 0, fmt.Errorf("Failed to convert get to right data type")
	}
	valByte, ok := d[restartCounterKey(p.name)]
	if !ok {
		return 0, fmt.Errorf("Missing %s key in get response", restartCounterKey(p.name))
	}
	var valInt map[string]int
	if err := json.Unmarshal(valByte, &valInt); err != nil {
		return 0, fmt.Errorf("Failed to convert %s to int", string(valByte))
	}

	return valInt["value"], nil
}

func restartCounterKey(name string) string {
	return fmt.Sprintf("system.%s.%s", name, RESTART_COUTNER_TOPIC)
}
