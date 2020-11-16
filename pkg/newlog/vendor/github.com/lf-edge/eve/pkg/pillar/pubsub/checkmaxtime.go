// Copyright (c) 2017,2018,2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// Debug info to tell how often/late we call stillRunning; keyed by agentName
var lockedLastStillMap = base.NewLockedStringMap()

// StillRunning touches a file per agentName to signal the event loop is still running
// Those files are observed by the watchdog
func (p *PubSub) StillRunning(agentName string, warnTime time.Duration, errTime time.Duration) {
	log := p.log
	log.Tracef("StillRunning(%s)\n", agentName)

	if lsValue, found := lockedLastStillMap.Load(agentName); !found {
		lockedLastStillMap.Store(agentName, time.Now())
	} else {
		ls, ok := lsValue.(time.Time)
		if !ok {
			log.Fatalf("Unexpected type from lockedLastStillMap: wanted time.Time, got %T", lsValue)
		}
		elapsed := time.Since(ls)
		if elapsed > errTime {
			log.Errorf("StillRunning(%s) XXX took a long time: %d",
				agentName, elapsed/time.Second)
		} else if elapsed > warnTime {
			log.Warnf("StillRunning(%s) took a long time: %d",
				agentName, elapsed/time.Second)
		}
		lockedLastStillMap.Store(agentName, time.Now())
	}

	filename := fmt.Sprintf("/run/%s.touch", agentName)
	_, err := os.Stat(filename)
	if err != nil {
		file, err := os.Create(filename)
		if err != nil {
			log.Functionf("StillRunning: %s\n", err)
			return
		}
		file.Close()
	}
	_, err = os.Stat(filename)
	if err != nil {
		log.Errorf("StilRunning: %s\n", err)
		return
	}
	now := time.Now()
	err = os.Chtimes(filename, now, now)
	if err != nil {
		log.Errorf("StillRunning: %s\n", err)
		return
	}
}

// CheckMaxTimeTopic verifies if the time for a call has exeeded a reasonable
// number.
func (p *PubSub) CheckMaxTimeTopic(agentName string, topic string, start time.Time,
	warnTime time.Duration, errTime time.Duration) {

	elapsed := time.Since(start)
	if elapsed > errTime && errTime != 0 {
		p.log.Errorf("%s handler in %s XXX took a long time: %d",
			topic, agentName, elapsed/time.Second)
	} else if elapsed > warnTime && warnTime != 0 {
		p.log.Warnf("%s handler in %s took a long time: %d",
			topic, agentName, elapsed/time.Second)
	}
}

// RegisterFileWatchdog tells the watchdog about the touch file
func (p *PubSub) RegisterFileWatchdog(agentName string) {
	p.log.Noticef("RegisterFileWatchdog(%s)", agentName)
	wdFile := fmt.Sprintf("%s/%s.touch", base.WatchdogFileDir, agentName)
	base.TouchFile(p.log, wdFile)
}

// RegisterPidWatchdog tells the watchdog about the pid file
func (p *PubSub) RegisterPidWatchdog(agentName string) {
	p.log.Noticef("RegisterPidWatchdog(%s)", agentName)
	wdFile := fmt.Sprintf("%s/%s.pid", base.WatchdogPidDir, agentName)
	base.TouchFile(p.log, wdFile)
}
