// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// ZbootConfig contains information fed from zedagent to baseosmgr.
// Only used to indicate that the testing of the image/partition is complete.
type ZbootConfig struct {
	PartitionLabel string
	TestComplete   bool
}

// Key returns the key used in pubsub for ZbootConfig
func (status ZbootConfig) Key() string {
	return status.PartitionLabel
}

type ZbootStatus struct {
	PartitionLabel   string
	PartitionDevname string
	PartitionState   string
	ShortVersion     string
	LongVersion      string
	CurrentPartition bool
	TestComplete     bool
}

func (status ZbootStatus) Key() string {
	return status.PartitionLabel
}
