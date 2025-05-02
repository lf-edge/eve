// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"github.com/nkval/go-nkv/pkg/client"
)

type Subscriber struct {
	nkvClient *client.Client
	topic     string
}

func (e *Subscriber) Start() error { return nil }

func (e *Subscriber) Load() (map[string][]byte, int, error) {
	// nkv is server based solution, not p2p, so there's
	// no need for load, left for backward compatibility
	// with PubSub interface

	entries, err := e.nkvClient.Get(e.topic + ".*")
	if err != nil {
		return nil, 0, err
	}

	return entries.Data, 0, nil
}

func (e *Subscriber) Stop() error { return nil }

func (e *Subscriber) LargeDirName() string { return "" }
