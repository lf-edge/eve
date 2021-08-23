// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Record failure and successes around object encryption

package cipher

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus" // OK for logrus.Fatal
	"sync"
	"time"
)

// agentMetrics has one entry per agentName aka LogObject
// Makes it usable when multiple agents are running in the same process aka zedbox
type agentMetrics struct {
	metrics types.CipherMetricsMap
}

type allMetricsMap map[*base.LogObject]agentMetrics

var allMetrics = make(allMetricsMap)
var mutex = &sync.Mutex{}

// RecordSuccess records that the decryption succeeded
func RecordSuccess(log *base.LogObject, agentName string) {
	log.Functionf("RecordSuccess(%s)", agentName)
	mutex.Lock()
	defer mutex.Unlock()
	m := getMetrics(log, agentName)
	m.SuccessCount++
	m.LastSuccess = time.Now()
	updateMetrics(log, agentName, m)
}

// RecordFailure records that the decryption failed or did something
// unexpected like fall back to cleartext
// If the errcode is NoData we just increment the NoData counter but
// not record as a failure.
func RecordFailure(log *base.LogObject, agentName string, errcode types.CipherError) {
	log.Functionf("RecordFailure(%s, %v)", agentName, errcode)
	mutex.Lock()
	defer mutex.Unlock()
	m := getMetrics(log, agentName)
	if errcode != types.NoData {
		m.FailureCount++
		m.LastFailure = time.Now()
	}
	m.TypeCounters[errcode]++
	updateMetrics(log, agentName, m)
}

func getMetrics(log *base.LogObject, agentName string) types.CipherMetrics {
	if allMetrics == nil {
		logrus.Fatal("no allMetrics")
	}
	if _, ok := allMetrics[log]; !ok {
		allMetrics[log] = agentMetrics{metrics: make(types.CipherMetricsMap)}
	}
	metrics := allMetrics[log].metrics
	if _, ok := metrics[agentName]; !ok {
		log.Noticef("maybeInit(%s) allocate for agent", agentName)
		metrics[agentName] = types.CipherMetrics{
			TypeCounters: make([]uint64, types.MaxCipherError),
		}
		allMetrics[log] = agentMetrics{metrics: metrics}
	}
	return metrics[agentName]
}

func updateMetrics(log *base.LogObject, agentName string, m types.CipherMetrics) {
	if allMetrics == nil {
		logrus.Fatal("no allMetrics")
	}
	if _, ok := allMetrics[log]; !ok {
		logrus.Fatal("allMetrics not initialized")
	}
	metrics := allMetrics[log].metrics
	metrics[agentName] = m
	allMetrics[log] = agentMetrics{metrics: metrics}
}

// GetCipherMetrics returns the metrics for this agent aka log pointer.
// Note that the caller can not safely use this directly since the map
// might be modified by other goroutines. But the output can be Append'ed to
// a map owned by the caller.
// Recommended usage:
// cms := cipher.Append(types.CipherMetricsMap{}, cipher.GetCipherMetrics(log))
func GetCipherMetrics(log *base.LogObject) types.CipherMetricsMap {
	if allMetrics == nil {
		logrus.Fatal("no allMetrics")
	}
	if _, ok := allMetrics[log]; !ok {
		allMetrics[log] = agentMetrics{metrics: make(types.CipherMetricsMap)}
	}
	return allMetrics[log].metrics
}

// Append concatenates potentially overlappping CipherMetricsMaps to
// return a union/sum.
// Append concatenates different interfaces and URLs into a union map
// Assumes the caller has exclusive access to cms. Uses mutex to serialize
// access to cms1
func Append(cms types.CipherMetricsMap, cms1 types.CipherMetricsMap) types.CipherMetricsMap {
	mutex.Lock()
	defer mutex.Unlock()
	for agentName, cm1 := range cms1 {
		cm, ok := cms[agentName]
		if !ok {
			// New agentName; take all but need to deepcopy
			cm = types.CipherMetrics{}
		}
		if cm.LastFailure.IsZero() {
			// Don't care if cm1 is zero
			cm.LastFailure = cm1.LastFailure
		} else if !cm1.LastFailure.IsZero() &&
			cm1.LastFailure.Sub(cm.LastFailure) > 0 {
			cm.LastFailure = cm1.LastFailure
		}
		if cm.LastSuccess.IsZero() {
			// Don't care if cm1 is zero
			cm.LastSuccess = cm1.LastSuccess
		} else if !cm1.LastSuccess.IsZero() &&
			cm1.LastSuccess.Sub(cm.LastSuccess) > 0 {
			cm.LastSuccess = cm1.LastSuccess
		}
		cm.FailureCount += cm1.FailureCount
		cm.SuccessCount += cm1.SuccessCount
		if cm.TypeCounters == nil {
			cm.TypeCounters = make([]uint64, types.MaxCipherError)
		}
		for i := range cm1.TypeCounters {
			cm.TypeCounters[i] += cm1.TypeCounters[i]
		}
		cms[agentName] = cm
	}
	return cms
}
