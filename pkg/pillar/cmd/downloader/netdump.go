// Copyright (c) 2019-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/netdump"
)

const (
	// Topic for netdumps of successful download requests.
	netDumpOKTopic = agentName + "-ok"
	// Topic for netdumps of failed download requests.
	netDumpFailTopic = agentName + "-fail"
)

// Publish netdump containing traces of executed download requests.
func publishNetdump(ctx *downloaderContext,
	downloadSucceeded bool, tracedDownloadReqs []netdump.TracedNetRequest) {
	netDumper := ctx.netDumper
	if netDumper == nil {
		return
	}
	var topic string
	if downloadSucceeded {
		topic = netDumpOKTopic
	} else {
		topic = netDumpFailTopic
	}
	filename, err := netDumper.Publish(topic, tracedDownloadReqs...)
	if err != nil {
		log.Warnf("Failed to publish netdump for topic %s: %v", topic, err)
	} else {
		log.Noticef("Published netdump for topic %s: %s", topic, filename)
	}
}
