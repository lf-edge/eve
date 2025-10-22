// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package generics

import (
	"slices"
	"sync"
	"time"
)

type DeferredMapProcessor[C any] struct {
	delay    time.Duration
	callback LockedMapFunc[string, C]
	items    *LockedMap[string, C]

	mu      sync.Mutex
	timer   *time.Timer
	running bool
}

func NewDeferredMapProcessor[C any](
	delay time.Duration,
	callback LockedMapFunc[string, C],
) *DeferredMapProcessor[C] {
	return &DeferredMapProcessor[C]{
		delay:    delay,
		callback: callback,
		items:    NewLockedMap[string, C](),
	}
}

func (d *DeferredMapProcessor[C]) Delete(key string) {
	d.items.Delete(key)
}

func (d *DeferredMapProcessor[C]) Add(key string, val C) {
	d.items.Store(key, val)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		// already scheduled -- do nothing
		return
	}

	d.running = true
	d.timer = time.AfterFunc(d.delay, func() {
		d.run()
	})
}

func (d *DeferredMapProcessor[C]) Contains(key string) bool {
	return slices.Contains(d.items.Keys(), key)
}

func (d *DeferredMapProcessor[C]) run() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items.Drain(d.callback)
	d.running = false
}

func (d *DeferredMapProcessor[C]) Cancel() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}
	d.running = false
}
