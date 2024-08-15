/*
 * Copyright (c) 2021. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package types

import "sync"

// FlowlogCounters encapsulates counters for published/dropped flowlog
// messages/flows or DNS requests.
type FlowlogCounters struct {
	Success        uint64
	Drops          uint64
	FailedAttempts uint64
}

// FlowlogMetrics contains flowlog metrics as collected by flowlogTask of zedagent.
type FlowlogMetrics struct {
	sync.Mutex
	Messages FlowlogCounters
	Flows    FlowlogCounters
	DNSReqs  FlowlogCounters
}
