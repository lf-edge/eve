// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Provide for a pubsub mechanism for config and status which is
// backed by an IPC mechanism such as connected sockets.

package pubsub

import (
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// CheckMaxTimeTopic verifies if the time for a call has exeeded a reasonable
// number.
// XXX move to legacy? Change all callers to use member function?
func CheckMaxTimeTopic(agentName string, topic string, start time.Time,
	warnTime time.Duration, errTime time.Duration) {
	pid := os.Getpid()
	log := base.NewSourceLogObject(agentName, pid)
	ps := New(&EmptyDriver{}, log)
	ps.CheckMaxTimeTopic(agentName, topic, start, warnTime, errTime)
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
