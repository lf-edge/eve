// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nkvdriver

import (
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/nkval/go-nkv/pkg/client"
	p "github.com/nkval/go-nkv/pkg/protocol"
)

type Subscriber struct {
	nkvClient *client.Client
	name      string
	topic     string
	C         chan<- pubsub.Change
}

func (e *Subscriber) Start() error {
	e.C <- pubsub.Change{Operation: pubsub.Sync, Key: "done"}
	_, err := e.nkvClient.Subscribe(e.path()+".*", func(n p.Notification) {
		if n.Type == p.NotificationUpdate {
			e.C <- pubsub.Change{Operation: pubsub.Modify, Key: n.Key, Value: n.Data}
		}
		if n.Type == p.NotificationClose {
			e.C <- pubsub.Change{Operation: pubsub.Delete, Key: n.Key}
		}
	})
	if err != nil {
		return err
	}
	resp, err := e.nkvClient.Get(e.path() + ".*")
	if err != nil {
		return err
	}
	// if len(resp.Data) > 1 {
	// fmt.Errorf("More data that needed")
	// }
	for key, val := range resp.Data {
		e.C <- pubsub.Change{Operation: pubsub.Modify, Key: key, Value: val}
	}
	e.C <- pubsub.Change{Operation: pubsub.Sync, Key: "done"}
	return nil
}

func (e *Subscriber) Load() (map[string][]byte, int, error) {
	// nkv is server based solution, not p2p, so there's
	// no need for load, left for backward compatibility
	// with PubSub interface

	entries, err := e.nkvClient.Get(e.path() + ".*")
	if err != nil {
		return nil, 0, err
	}

	return entries.Data, 1, nil
}

func (e *Subscriber) Stop() error { return nil }

func (e *Subscriber) LargeDirName() string { return "" }

// WARN: should be the same as Publisher path
//
//	func (s *Subscriber) path() string {
//		t := strings.ReplaceAll(s.topic, "/", ".")
//		n := strings.ReplaceAll(s.name, "/", ".")
//		if t != "" && n != "" {
//			return n + "." + t
//		}
//		if t != "" {
//			return t
//		}
//		return n // may be "" if both are empty
//	}
func (s *Subscriber) path() string {
	t := strings.ReplaceAll(s.topic, "/", ".")
	n := strings.ReplaceAll(s.name, "/", ".")
	if t != "" && n != "" {
		return n + "." + t
	}
	if t != "" {
		return t
	}
	return n // may be "" if both are empty
}
