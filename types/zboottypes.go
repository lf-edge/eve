// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

type ZbootStatus struct {
	PartitionLabel   string
	PartitionDevname string
	PartitionState   string
	ShortVersion     string
	LongVersion      string
	CurrentPartition bool
}

func (status ZbootStatus) Key() string {
	return status.PartitionLabel
}
