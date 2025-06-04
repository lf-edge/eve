// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sort"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

var (
	// device source input bytes written to log file
	devSourceBytes *base.LockedStringMap
	// last number of bytes from call to calculate ranks
	lastDevNumBytesWrite uint64
)

func rankByInputCount(Frequencies *base.LockedStringMap) pairList {
	pl := pairList{}
	clb := func(key string, val interface{}) bool {
		pl = append(pl, pair{key, val.(uint64)})
		return true
	}
	Frequencies.Range(clb)
	sort.Sort(sort.Reverse(pl))
	return pl
}

type pair struct {
	Key   string
	Value uint64
}

type pairList []pair

func (p pairList) Len() int           { return len(p) }
func (p pairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// getDevTop10Inputs generates top 10 contributor in total bytes from services
// we calculate ranks from the last call and cleanup devSourceBytes
func getDevTop10Inputs() {
	if logmetrics.DevMetrics.NumBytesWrite-lastDevNumBytesWrite == 0 {
		return
	}

	top10 := make(map[string]uint32)
	pl := rankByInputCount(devSourceBytes)
	for i, p := range pl {
		if i >= 10 {
			break
		}
		top10[p.Key] = uint32(p.Value * 100 / (logmetrics.DevMetrics.NumBytesWrite - lastDevNumBytesWrite))
	}
	logmetrics.DevTop10InputBytesPCT = top10
	lastDevNumBytesWrite = logmetrics.DevMetrics.NumBytesWrite
	devSourceBytes = base.NewLockedStringMap()
}
