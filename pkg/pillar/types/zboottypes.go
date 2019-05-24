// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

type ZbootConfig struct {
	PartitionLabel string
	TestComplete   bool
}

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
