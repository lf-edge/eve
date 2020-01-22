// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Wait for being able to connect to the syslog service for
// at most maxTime
package waitforsyslog

import (
	"fmt"
	"log/syslog"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
)

const (
	agentName   = "waitforsyslog"
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
	maxTime     = 300 * time.Second
)

func Run() {
	fmt.Printf("Starting %s\n", agentName)
	startTime := time.Now()

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		fmt.Printf("Fatal error for %s: %s\n", agentName, err)
	}
	agentlog.StillRunning(agentName, warningTime, errorTime)

	syslogFlags := syslog.LOG_INFO | syslog.LOG_DEBUG | syslog.LOG_ERR |
		syslog.LOG_NOTICE | syslog.LOG_WARNING | syslog.LOG_CRIT |
		syslog.LOG_ALERT | syslog.LOG_EMERG

	// Run a periodic timer so we always update StillRunning
	// Use this timer to retry the hook as well
	stillRunning := time.NewTicker(5 * time.Second)

	for {
		fmt.Printf("NewSyslogHook called for %s\n", agentName)
		_, err := lSyslog.NewSyslogHook("", "", syslogFlags, agentName)
		elapsed := time.Since(startTime)
		if err == nil {
			fmt.Printf("NewSyslogHook success for %s\n", agentName)
			fmt.Printf("%s DONE after %d seconds\n", agentName,
				elapsed/time.Second)
			return
		}
		fmt.Printf("NewSyslogHook failed for %s: %s\n", agentName, err)
		if elapsed > maxTime {
			fmt.Printf("%s giving up after %d seconds\n",
				agentName, elapsed/time.Second)
			os.Exit(1)
		}
		fmt.Printf("%s has %d seconds remaining\n", agentName,
			(maxTime-elapsed)/time.Second)
		<-stillRunning.C
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}
