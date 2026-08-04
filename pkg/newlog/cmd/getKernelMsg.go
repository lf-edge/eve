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
// Writes to a dedicated kernelChan to decouple kernel log reading from
// the main pipeline. This ensures that backpressure from downstream
// processing (vector sockets, disk I/O, gzip compression) does not
// prevent reading /dev/kmsg, which would cause the kernel ring buffer
// to overflow and silently drop early messages.
func getKernelMsg(kernelChan chan inputEntry) {
	parser, err := kmsgparser.NewParser()
	if err != nil {
		log.Fatalf("unable to create kmsg parser: %v", err)
	}
	defer parser.Close()

	lastSeqNum := -1

	kmsg := parser.Parse()
	for msg := range kmsg {
		// Detect gaps in kernel message sequence numbers.
		// /dev/kmsg assigns a monotonically increasing sequence number
		// to each message. A gap means the kernel ring buffer overflowed
		// and messages were lost (EPIPE from the reader's perspective).
		if lastSeqNum >= 0 && msg.SequenceNumber > lastSeqNum+1 {
			gap := uint64(msg.SequenceNumber - lastSeqNum - 1)
			logmetrics.NumKmsgDropped += gap
			log.Warnf("getKernelMsg: detected kernel log gap: %d messages lost (seq %d -> %d)",
				gap, lastSeqNum, msg.SequenceNumber)
		}
		lastSeqNum = msg.SequenceNumber

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

		// Non-blocking send to the dedicated kernel buffer channel.
		// If the kernel buffer is full (extremely unlikely with 500 slots),
		// log the drop and count it — but never block, so we keep
		// draining /dev/kmsg and prevent ring buffer overflow.
		select {
		case kernelChan <- entry:
		default:
			logmetrics.NumKmsgDropped++
			log.Warnf("getKernelMsg: kernel buffer channel full, dropping message: %s", entry.content)
		}
	}
	// If we get here, the kmsg parser channel was closed (read error or EOF).
	// Log this as an error — no more kernel messages will be collected.
	log.Errorf("getKernelMsg: kmsg parser channel closed, kernel log collection stopped")
}
