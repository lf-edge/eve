// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"strings"

	"github.com/nkval/go-nkv/pkg/client"
)

type Publisher struct {
	nkvClient *client.Client
	topic     string
	name      string
}

func (p *Publisher) Start() error { return nil }

func (p *Publisher) Load() (map[string][]byte, int, error) {
	// nkv is server based solution, not p2p, so there's
	// no need for load, left for backward compatibility
	// with PubSub interface

	entries, err := p.nkvClient.Get(p.name + ".*")
	if err != nil {
		return nil, 0, err
	}

	return entries.Data, 0, nil
}

func (p *Publisher) Publish(key string, item []byte) error {
	k := p.path() + "." + key
	// fmt.Printf("PUBLISHER %v %v", k, item)
	_, err := p.nkvClient.Put(k, item)
	return err
}

func (s *Publisher) Unpublish(key string) error {
	k := s.path() + "." + key
	_, err := s.nkvClient.Delete(k)
	return err
}

func (p *Publisher) Restart(restartCounter int) error { return nil /* no need */ }

func (p *Publisher) Stop() error { return nil /* no need */ }

func (p *Publisher) CheckMaxSize(_key string, _val []byte) error { return nil /* no limitations */ }

func (p *Publisher) LargeDirName() string { /* no need */
	return ""
}

// WARN: should be the same as Subscriber path
func (p *Publisher) path() string {
	t := strings.ReplaceAll(p.topic, "/", ".")
	n := strings.ReplaceAll(p.name, "/", ".")
	if t != "" && n != "" {
		return n + "." + t
	}
	if t != "" {
		return t
	}
	return n // may be "" if both are empty
}
