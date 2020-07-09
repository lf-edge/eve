// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Record failure and successes around object encryption

package cipher

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

var metrics = make(types.CipherMetricsMap)
var mutex = &sync.Mutex{}

// RecordSuccess records that the decryption succeeded
func RecordSuccess(agentName string) {
	mutex.Lock()
	defer mutex.Unlock()
	maybeInit(agentName)
	m := metrics[agentName]
	m.SuccessCount++
	m.LastSuccess = time.Now()
	metrics[agentName] = m
}

// RecordFailure records that the decryption failed or did something
// unexpected like fall back to cleartext
func RecordFailure(agentName string, errcode types.CipherError) {
	mutex.Lock()
	defer mutex.Unlock()
	maybeInit(agentName)
	m := metrics[agentName]
	m.FailureCount++
	m.LastFailure = time.Now()
	m.TypeCounters[errcode]++
	metrics[agentName] = m
}

func maybeInit(agentName string) {
	if metrics == nil {
		log.Fatal("no cipher map")
	}
	if _, ok := metrics[agentName]; !ok {
		log.Debugf("create zedcloudmetric for %s\n", agentName)
		metrics[agentName] = types.CipherMetrics{
			TypeCounters: make([]uint64, types.MaxCipherError),
		}
	}
}

// GetCipherMetrics returns the metrics for this agent
func GetCipherMetrics() types.CipherMetricsMap {
	return metrics
}

// Append concatenates potentially overlappping CipherMetricsMaps to
// return a union/sum.
func Append(cms types.CipherMetricsMap, cms1 types.CipherMetricsMap) types.CipherMetricsMap {
	for agentName, cm1 := range cms1 {
		cm, ok := cms[agentName]
		if !ok {
			// New agentName; take all
			cms[agentName] = cm
			continue
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
