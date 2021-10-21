// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Record failure and successes around object encryption for a single agent.

package cipher

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"sync"
	"time"
)

// AgentMetrics stores encryption related metrics for one agent (microservice).
// Able to properly handle concurrent access.
type AgentMetrics struct {
	sync.Mutex
	metrics types.CipherMetrics
}

// NewAgentMetrics creates instance of AgentMetrics.
func NewAgentMetrics(agentName string) *AgentMetrics {
	am := &AgentMetrics{}
	am.metrics = types.CipherMetrics{
		AgentName:    agentName,
		TypeCounters: make([]uint64, types.MaxCipherError),
	}
	return am
}

func (am *AgentMetrics) acquire(log *base.LogObject) (release func()) {
	if am == nil {
		log.Fatal("undefined AgentMetrics")
	}
	am.Lock()
	return func() { am.Unlock() }
}

// RecordSuccess records that a decryption succeeded.
func (am *AgentMetrics) RecordSuccess(log *base.LogObject) {
	release := am.acquire(log)
	defer release()
	log.Functionf("RecordSuccess(%s)", am.metrics.AgentName)
	am.metrics.SuccessCount++
	am.metrics.LastSuccess = time.Now()
}

// RecordFailure records that a decryption failed or did something
// unexpected like fall back to cleartext.
// If the errcode is NoData we just increment the NoData counter but
// not record as a failure.
func (am *AgentMetrics) RecordFailure(log *base.LogObject, errcode types.CipherError) {
	release := am.acquire(log)
	defer release()
	log.Functionf("RecordFailure(%s, %v)", am.metrics.AgentName, errcode)
	if errcode != types.NoData {
		am.metrics.FailureCount++
		am.metrics.LastFailure = time.Now()
	}
	am.metrics.TypeCounters[errcode]++
}

// Publish the recorded metrics through the given publisher.
func (am *AgentMetrics) Publish(log *base.LogObject, publication pubsub.Publication, key string) error {
	release := am.acquire(log)
	defer release()
	return publication.Publish(key, am.metrics)
}
