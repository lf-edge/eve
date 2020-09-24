// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	// DefaultQueue default queue depth
	DefaultQueue = 5
)

// Opts options when creating workers
type Opts struct {
	// Queue depth of queue; if you try to submit more than the depth, it will reject with an error
	Queue int
	// Handlers handlers by type
	Handlers []Handler
	// Log log handler
	Log *base.LogObject
}

func (o *Opts) setDefaults() {
	if o.Queue == 0 {
		o.Queue = DefaultQueue
	}
}

// Validate check that this is a valid set of opts for our capabilities
func (o *Opts) Validate() error {
	var e []string
	if o.Queue == 0 {
		e = append(e, "queue size must be greater than 0")
	}
	if len(e) > 0 {
		return fmt.Errorf("%s", strings.Join(e, "; "))
	}
	return nil
}
