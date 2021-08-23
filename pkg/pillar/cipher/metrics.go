// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Record failure and successes around object encryption

package cipher

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus" // OK for logrus.Fatal
	"sync"
	"time"
)

// agentName is the key to this map hence can be used in zedbox
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
		logrus.Fatal("no cipher map")
	}
	if _, ok := metrics[agentName]; !ok {
		metrics[agentName] = types.CipherMetrics{
			AgentName:    agentName,
			TypeCounters: make([]uint64, types.MaxCipherError),
		}
	}
}

// GetCipherMetrics returns the metrics for agentName
func GetCipherMetrics(agentName string) types.CipherMetrics {
	mutex.Lock()
	defer mutex.Unlock()
	maybeInit(agentName)
	return metrics[agentName]
}
