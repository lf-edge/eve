// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"github.com/nkval/go-nkv/pkg/client"
)

type Publisher struct {
	nkvClient *client.Client
	topic     string
}

func (p *Publisher) Start() error { return nil }

func (p *Publisher) Load() (map[string][]byte, int, error) {
	// nkv is server based solution, not p2p, so there's
	// no need for load, left for backward compatibility
	// with PubSub interface

	entries, err := p.nkvClient.Get(p.topic + ".*")
	if err != nil {
		return nil, 0, err
	}

	return entries.Data, 0, nil
}

func (p *Publisher) Publish(key string, item []byte) error {
	_, err := p.nkvClient.Put(key, item)
	return err
}

func (s *Publisher) Unpublish(key string) error {
	_, err := s.nkvClient.Delete(key)
	return err
}

func (p *Publisher) Restart(restartCounter int) error { return nil /* no need */ }

func (p *Publisher) Stop() error { return nil /* no need */ }

func (p *Publisher) CheckMaxSize(_key string, _val []byte) error { return nil /* no limitations */ }

func (p *Publisher) LargeDirName() string { /* no need */
	return ""
}
