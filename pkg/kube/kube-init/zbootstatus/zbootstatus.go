// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package zbootstatus subscribes to pillar's ZbootStatus topic
// (published by baseosmgr, one entry per A/B partition label) and
// answers the one question kube-init needs of it: has the running
// partition been committed, or can EVE still revert to the other one?
//
// That distinction gates anything destructive that assumes the new
// release is here to stay. While an upgrade is under test the current
// partition is "inprogress"; the old rootfs is still bootable and still
// needs the state the new release has superseded. Only once the
// partition reaches "active" is a revert no longer the default path.
//
// API shape:
//
//   - Register(m) hands the subscription to the shared
//     pubsubclient.Manager. Call once at startup from main.go before
//     m.Run is started.
//   - CurrentPartitionCommitted() reports whether the running partition
//     is committed. It is deliberately conservative: no delivery yet, or
//     no entry flagged CurrentPartition, both read as "not committed".
package zbootstatus

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// SubscriptionLabel is the Manager label kube-init registers the
// ZbootStatus subscription under.
const SubscriptionLabel = "ZbootStatus"

// publisherAgentName is baseosmgr — the pillar agent that owns
// ZbootStatus. Hard-coded because topic ownership is a pillar-side
// architectural decision, not a kube-init config.
const publisherAgentName = "baseosmgr"

// partStateActive is the partition state that means "committed". The
// other states a current partition can be in are "inprogress" (under
// test, revert still possible) and "updating". Mirrors the strings
// pillar's zboot package writes.
const partStateActive = "active"

// byLabel holds the latest status per partition label (IMGA/IMGB).
// ZbootStatus is a keyed topic, so both partitions are delivered and
// only the one flagged CurrentPartition describes what is running.
var (
	mu      sync.RWMutex
	byLabel = make(map[string]types.ZbootStatus)
)

// Register creates the ZbootStatus subscription on the supplied
// Manager.
func Register(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName,
		TopicImpl:     types.ZbootStatus{},
		Persistent:    false,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

// pubsub delivers Create on the first observation of a key and Modify
// afterwards; both mean the same thing here — "this is the latest
// status for that partition".
func handleCreate(_ interface{}, key string, val interface{}) {
	store(key, val.(types.ZbootStatus))
}

func handleModify(_ interface{}, key string, val interface{}, _ interface{}) {
	store(key, val.(types.ZbootStatus))
}

func handleDelete(_ interface{}, key string, _ interface{}) {
	mu.Lock()
	delete(byLabel, key)
	mu.Unlock()
}

func store(key string, st types.ZbootStatus) {
	mu.Lock()
	byLabel[key] = st
	mu.Unlock()
}

// Current returns the status of the partition EVE is running from, and
// whether such an entry has been delivered at all.
func Current() (types.ZbootStatus, bool) {
	mu.RLock()
	defer mu.RUnlock()
	for _, st := range byLabel {
		if st.CurrentPartition {
			return st, true
		}
	}
	return types.ZbootStatus{}, false
}

// CurrentPartitionCommitted reports whether the running partition has
// been committed, i.e. EVE will not fall back to the other partition on
// the next boot.
//
// Gated on PartitionState rather than TestComplete because the two
// answer different questions. TestComplete marks the moment a test
// finished and is only meaningful during an upgrade; PartitionState
// describes the standing situation, and so is also correct on the far
// more common boot where no upgrade is in flight at all and the
// partition has been active for months.
//
// Returns false until the first delivery arrives, so a caller that runs
// early simply does nothing and tries again on the next tick.
func CurrentPartitionCommitted() bool {
	st, ok := Current()
	return ok && st.PartitionState == partStateActive
}
