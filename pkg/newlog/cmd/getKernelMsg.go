// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync/atomic"
	"time"

	"github.com/euank/go-kmsg-parser/kmsgparser"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// getKernelMsg - goroutine to get from /dev/kmsg
func getKernelMsg(loggerChan chan inputEntry) {
	parser, err := kmsgparser.NewParser()
	if err != nil {
		log.Fatalf("unable to create kmsg parser: %v", err)
	}
	defer parser.Close()

	kmsg := parser.Parse()
	for msg := range kmsg {
		entry := inputEntry{
			source:    "kernel",
			severity:  types.SyslogKernelDefaultLogLevel,
			content:   msg.Message,
			timestamp: msg.Timestamp.Format(time.RFC3339Nano),
		}
		if msg.Priority >= 0 {
			entry.severity = types.SyslogKernelLogLevelStr[msg.Priority%8]
		}
		if suppressMsg(entry, atomic.LoadUint32(&kernelPrio)) {
			continue
		}

		entry.sendToRemote = types.SyslogKernelLogLevelNum[entry.severity] <= atomic.LoadUint32(&kernelRemotePrio)

		logmetrics.NumKmessages++
		logmetrics.DevMetrics.NumInputEvent++
		log.Tracef("getKmessages (%d) entry msg %s", logmetrics.NumKmessages, entry.content)

		loggerChan <- entry
	}
}
