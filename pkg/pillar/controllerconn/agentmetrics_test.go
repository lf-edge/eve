// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn_test

import (
	"fmt"
	"net/http"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// urlCountersWiggle mirrors the unexported constant of the same name in
// controllerconn/agentmetrics.go: the amount of headroom above
// types.MaxURLCounters that is let through before a batch of oldest
// entries gets evicted.
const urlCountersWiggle = 15

func testLogObject() *base.LogObject {
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.TraceLevel)
	return base.NewSourceLogObject(logger, "unittest", 1234)
}

func TestAgentMetricsURLCountersUnderLimit(t *testing.T) {
	g := NewGomegaWithT(t)
	log := testLogObject()
	am := controllerconn.NewAgentMetrics()

	am.RecordSuccess(log, "eth0", "/url/a", 10, 10, 1, false)
	am.RecordFailure(log, "eth0", "/url/b", 10, 10, false)

	toMap := types.MetricsMap{}
	am.AddInto(log, toMap)
	cm := toMap["eth0"]

	g.Expect(len(cm.URLCounters)).To(Equal(2))
	g.Expect(cm.URLCounterRedactedCount).To(Equal(uint64(0)))
}

func TestAgentMetricsURLCountersLimit(t *testing.T) {
	g := NewGomegaWithT(t)
	log := testLogObject()
	am := controllerconn.NewAgentMetrics()

	// Stay right at the high watermark: no eviction should have happened
	// yet, and every recorded URL should still be present.
	highWatermark := types.MaxURLCounters + urlCountersWiggle
	for i := 0; i < highWatermark; i++ {
		am.RecordSuccess(log, "eth0", fmt.Sprintf("/url/%d", i), 10, 10, 1, false)
	}

	toMap := types.MetricsMap{}
	am.AddInto(log, toMap)
	cm := toMap["eth0"]
	g.Expect(len(cm.URLCounters)).To(Equal(highWatermark))
	g.Expect(cm.URLCounterRedactedCount).To(Equal(uint64(0)))

	// One more entry crosses the high watermark: a batch of the oldest
	// (urlCountersWiggle) entries must be evicted, bringing the total back
	// down to the low watermark (MaxURLCounters) plus the new entry.
	am.RecordSuccess(log, "eth0", "/url/new", 10, 10, 1, false)

	toMap = types.MetricsMap{}
	am.AddInto(log, toMap)
	cm = toMap["eth0"]
	g.Expect(len(cm.URLCounters)).To(Equal(types.MaxURLCounters + 1))
	g.Expect(cm.URLCounterRedactedCount).To(Equal(uint64(urlCountersWiggle)))

	// The oldest entries (recorded first) must be the ones evicted.
	for i := 0; i < urlCountersWiggle; i++ {
		g.Expect(cm.URLCounters).NotTo(HaveKey(fmt.Sprintf("/url/%d", i)))
	}
	// The most recently recorded entries, including the new one, must
	// still be present.
	g.Expect(cm.URLCounters).To(HaveKey(fmt.Sprintf("/url/%d", highWatermark-1)))
	g.Expect(cm.URLCounters).To(HaveKey("/url/new"))
}

func TestAgentMetricsURLCountersLimitAcrossInterfaces(t *testing.T) {
	g := NewGomegaWithT(t)
	log := testLogObject()
	am := controllerconn.NewAgentMetrics()

	// The limit is combined across all interfaces, not per interface.
	// n0+n1 lands exactly on the high watermark, so the extra entry
	// recorded below is the one that crosses it.
	highWatermark := types.MaxURLCounters + urlCountersWiggle
	n0 := highWatermark / 2
	n1 := highWatermark - n0
	for i := 0; i < n0; i++ {
		am.RecordSuccess(log, "eth0", fmt.Sprintf("/eth0/%d", i), 10, 10, 1, false)
	}
	for i := 0; i < n1; i++ {
		am.RecordSuccess(log, "eth1", fmt.Sprintf("/eth1/%d", i), 10, 10, 1, false)
	}

	total := func(m types.MetricsMap) int {
		return len(m["eth0"].URLCounters) + len(m["eth1"].URLCounters)
	}

	toMap := types.MetricsMap{}
	am.AddInto(log, toMap)
	g.Expect(total(toMap)).To(Equal(highWatermark))

	// One more entry, on either interface, must cross the combined high
	// watermark and evict the globally oldest entries (recorded first, on
	// eth0), not just entries local to eth1.
	am.RecordSuccess(log, "eth1", "/eth1/new", 10, 10, 1, false)

	toMap = types.MetricsMap{}
	am.AddInto(log, toMap)
	g.Expect(total(toMap)).To(Equal(types.MaxURLCounters + 1))
	g.Expect(toMap["eth0"].URLCounters).NotTo(HaveKey("/eth0/0"))
	g.Expect(toMap["eth1"].URLCounters).To(HaveKey("/eth1/new"))
	g.Expect(toMap["eth0"].URLCounterRedactedCount).To(Equal(uint64(urlCountersWiggle)))
}

// RecordAnswer splits answered requests into accepted, refused-for-now and
// rejected, which is what tells an operator whether the controller is having
// trouble or is turning the payload away.
func TestAgentMetricsRecordAnswer(t *testing.T) {
	g := NewGomegaWithT(t)
	log := testLogObject()
	am := controllerconn.NewAgentMetrics()

	answers := []int{
		http.StatusOK, http.StatusNoContent, // accepted
		http.StatusServiceUnavailable, http.StatusTooManyRequests,
		http.StatusForbidden,                       // worth offering again
		http.StatusBadRequest, http.StatusNotFound, // rejected
		http.StatusFound, // neither
	}
	for _, status := range answers {
		am.RecordSuccess(log, "eth0", "/url/a", 10, 10, 1, false)
		am.RecordAnswer(log, "eth0", "/url/a", status)
	}

	toMap := types.MetricsMap{}
	am.AddInto(log, toMap)
	um := toMap["eth0"].URLCounters["/url/a"]

	g.Expect(um.SentMsgCount).To(Equal(int64(len(answers))))
	g.Expect(um.DeliveredMsgCount).To(Equal(int64(2)))
	g.Expect(um.RetriableErrCount).To(Equal(int64(3)))
	g.Expect(um.RejectedErrCount).To(Equal(int64(2)))
}
