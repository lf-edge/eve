// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync/atomic"
	"time"

	"github.com/euank/go-kmsg-parser/v3/kmsgparser"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// kmsgRestartDelay is the backoff applied before restarting the kmsg parser,
// so a persistently failing /dev/kmsg does not spin this goroutine.
const kmsgRestartDelay = 10 * time.Second

// getKernelMsg - goroutine to get from /dev/kmsg
func getKernelMsg(loggerChan chan inputEntry) {
	// The parser terminates on any read or parse error and closes its channel.
	// Nothing else supervises this goroutine, so restart the parser instead of
	// silently losing all kernel messages until the next reboot.
	lastSeq := -1
	for {
		seq, err := collectKernelMsg(loggerChan, lastSeq)
		switch {
		case err != nil:
			log.Errorf("kernel log collection failed: %v", err)
		case seq == lastSeq:
			// Nothing was delivered, so the parser choked on the record right
			// after lastSeq. Skip it, or every restart hits the same record.
			seq++
		}
		lastSeq = seq
		log.Warnf("kmsg collection stopped, restarting in %v", kmsgRestartDelay)
		time.Sleep(kmsgRestartDelay)
	}
}

// collectKernelMsg reads /dev/kmsg into loggerChan until the parser stops, and
// returns the sequence number of the last record it handed over. Reopening
// /dev/kmsg replays the whole ring buffer, so records already seen are skipped.
func collectKernelMsg(loggerChan chan inputEntry, lastSeq int) (int, error) {
	parser, err := kmsgparser.NewParser(kmsgparser.WithLogger(logger))
	if err != nil {
		return lastSeq, err
	}
	defer parser.Close()

	kmsg := make(chan kmsgparser.Message, 1)
	go func() {
		if err := parser.Parse(kmsg); err != nil {
			log.Errorf("kmsg parser stopped: %v", err)
		}
	}()

	for msg := range kmsg {
		if msg.SequenceNumber <= lastSeq {
			continue
		}
		lastSeq = msg.SequenceNumber

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

	return lastSeq, nil
}
