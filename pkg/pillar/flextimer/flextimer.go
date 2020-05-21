// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide randomized timers - botn based on range and binary exponential
// backoff.
// Usage:
//  ticker := NewRangeTicker(min, max)
//  select ticker.C
//  ticker.UpdateRangeTicker(newmin, newmix)
//  ticker.StopTicker()
// Usage:
//  ticker := NewExpTicker(start, max, randomFactor)
//  select ticker.C
//  ticker.UpdateRangeTicker(newstart, newmax, newRandomFactor)
//  ticker.StopTicker()

package flextimer

import (
	"math/rand"
	"time"
)

// Take min, max, exp bool
// If exp false then [min, max] is random range
// If exp true then start at min and do binary exponential backoff
// until hitting max, then stay at max. Randomize +/- randomFactor
// When config is all zeros, then stop and close channel

// XXX test that it can handle the TCP timeout and space out the next timers
// based on processing time ...

// Ticker handle for caller
type FlexTickerHandle struct {
	C           <-chan time.Time
	privateChan chan<- time.Time
	configChan  chan<- flexTickerConfig
}

// Arguments fed over configChan
type flexTickerConfig struct {
	exponential  bool
	minTime      time.Duration
	maxTime      time.Duration
	randomFactor float64
}

func NewRangeTicker(minTime time.Duration, maxTime time.Duration) FlexTickerHandle {
	initialConfig := flexTickerConfig{minTime: minTime,
		maxTime: maxTime}
	configChan := make(chan flexTickerConfig, 1)
	tickChan := newFlexTicker(configChan)
	configChan <- initialConfig
	return FlexTickerHandle{C: tickChan, privateChan: tickChan, configChan: configChan}
}

func NewExpTicker(minTime time.Duration, maxTime time.Duration, randomFactor float64) FlexTickerHandle {
	initialConfig := flexTickerConfig{minTime: minTime,
		maxTime: maxTime, exponential: true,
		randomFactor: randomFactor}
	configChan := make(chan flexTickerConfig, 1)
	tickChan := newFlexTicker(configChan)
	configChan <- initialConfig
	return FlexTickerHandle{C: tickChan, configChan: configChan}
}

func (f FlexTickerHandle) UpdateRangeTicker(minTime time.Duration, maxTime time.Duration) {
	config := flexTickerConfig{minTime: minTime,
		maxTime: maxTime}
	f.configChan <- config
}

// Insert a tick now in addition to running timers
func (f FlexTickerHandle) TickNow() {
	// There is a case when flextimer thread queues next tick, but main
	// thread of service is doing something else and as part of what the
	// main service does at that point, calls flextimer.TickNow().
	// In such a case main service thread will get blocked and never gets
	// un-blocked (since privateChan only has one tick slot).
	//
	// Is there a better solution than trying to send on privateChannel
	// in a non-blocking fashion using select? Can this cause issues?
	select {
	case f.privateChan <- time.Now():
	default:
	}
}

// Note that the above member functions aren't always usable since the
// FlexTickerHandle type is not exported. Hence these functions help.
func UpdateRangeTicker(hdl interface{}, minTime time.Duration,
	maxTime time.Duration) {
	f := hdl.(FlexTickerHandle)
	f.UpdateRangeTicker(minTime, maxTime)
}

func TickNow(hdl interface{}) {
	f := hdl.(FlexTickerHandle)
	f.TickNow()
}

func (f FlexTickerHandle) UpdateExpTicker(minTime time.Duration, maxTime time.Duration, randomFactor float64) {
	config := flexTickerConfig{minTime: minTime,
		maxTime: maxTime, exponential: true,
		randomFactor: randomFactor}
	f.configChan <- config
}

func (f FlexTickerHandle) StopTicker() {
	f.configChan <- flexTickerConfig{}
}

// Implementation functions

func newFlexTicker(config <-chan flexTickerConfig) chan time.Time {
	tick := make(chan time.Time, 1)
	go flexTicker(config, tick)
	return tick
}

func flexTicker(config <-chan flexTickerConfig, tick chan<- time.Time) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	// Wait for initial config
	c := <-config
	expFactor := 1
	for {
		var d time.Duration
		if c.exponential {
			rf := c.randomFactor
			if rf == 0 {
				rf = 1.0
			} else if rf > 1.0 {
				rf = 1.0 / rf
			}
			min := float64(c.minTime) * float64(expFactor) * rf
			max := float64(c.minTime) * float64(expFactor) / rf
			base := float64(c.minTime) * float64(expFactor)
			if time.Duration(base) < c.maxTime {
				expFactor *= 2
			}
			if max == min {
				d = time.Duration(min)
			} else {
				r := r1.Int63n(int64(max-min)) + int64(min)
				d = time.Duration(r)
			}
		} else {
			r := r1.Int63n(int64(c.maxTime-c.minTime)) + int64(c.minTime)
			d = time.Duration(r)
		}
		timer := time.NewTimer(d)
		select {
		case <-timer.C:
			// this channel can not block, otherwise the config channel will block
			// causing deadlock in zedagent
			// this means only one timer trigger is taking effect (the first one), the later
			// timer trigger will be ignored. This is fine since we get into block because even
			// the first one can not be served yet, there is no need to trigger it to serve again.
			select {
			case tick <- time.Now():
			default:
			}
		case c = <-config:
			// Replace current parameters without
			// looking at when current timer would fire
			timer.Stop()
			expFactor = 1
			if c.maxTime == 0 && c.minTime == 0 {
				close(tick)
				return
			}
		}
	}
}
