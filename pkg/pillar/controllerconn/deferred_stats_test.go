// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// deferItem queues one message under its own key, so that a test can build a
// backlog of independent items.
func deferItem(queue *DeferredQueue, key, url string, opts DeferredItemOpts) {
	queue.SetDeferred(key, bytes.NewBufferString(key), url, nil, opts)
}

func TestDeferredQueueStatsBacklog(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	// No answer at all: the controller is unreachable, so nothing leaves.
	sender.respond("url", fakeOutcome{status: 1})
	queue := newTestQueue(sender, nil)

	before := time.Now()
	deferItem(queue, "first", "url", DeferredItemOpts{})
	time.Sleep(10 * time.Millisecond)
	deferItem(queue, "second", "url", DeferredItemOpts{})
	queue.handleDeferred()

	stats := queue.Stats()
	t.Expect(stats.Undelivered).To(BeEquivalentTo(2))
	t.Expect(stats.OldestUndelivered).To(BeTemporally(">=", before))
	t.Expect(stats.OldestUndelivered).To(BeTemporally("<",
		queue.deferredItems[1].createdAt))
	t.Expect(stats.Rejected).To(BeEquivalentTo(0))
	t.Expect(stats.Superseded).To(BeEquivalentTo(0))
	t.Expect(stats.LastDropped.IsZero()).To(BeTrue())
}

// A message the controller rejects is given up on, and is counted as such
// rather than silently disappearing from the backlog.
func TestDeferredQueueStatsRejected(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond("url", fakeOutcome{statusCode: http.StatusBadRequest})
	queue := newTestQueue(sender, nil)

	before := time.Now()
	deferItem(queue, "rejected", "url", DeferredItemOpts{})
	queue.handleDeferred()

	stats := queue.Stats()
	t.Expect(stats.Undelivered).To(BeEquivalentTo(0))
	t.Expect(stats.Rejected).To(BeEquivalentTo(1))
	t.Expect(stats.Superseded).To(BeEquivalentTo(0))
	t.Expect(stats.LastDropped).To(BeTemporally(">=", before))
}

// A payload the next periodic publication supersedes is given up on for a
// reason of its own, whether or not the controller answered.
func TestDeferredQueueStatsSuperseded(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond("answered", fakeOutcome{statusCode: http.StatusServiceUnavailable})
	sender.respond("unreachable", fakeOutcome{status: 1})
	queue := newTestQueue(sender, nil)

	deferItem(queue, "answered", "answered",
		DeferredItemOpts{DiscardOnFailure: true})
	queue.handleDeferred()
	deferItem(queue, "unreachable", "unreachable",
		DeferredItemOpts{DiscardOnFailure: true})
	queue.handleDeferred()

	stats := queue.Stats()
	t.Expect(stats.Undelivered).To(BeEquivalentTo(0))
	t.Expect(stats.Superseded).To(BeEquivalentTo(2))
	t.Expect(stats.Rejected).To(BeEquivalentTo(0))
}

// Republishing an object whose reported state has not changed must not make
// the message look newer than it is: how long the controller has been waiting
// is the whole point of the age.
func TestDeferredQueueStatsAgeSurvivesRepublish(test *testing.T) {
	t := NewGomegaWithT(test)
	sender := newFakeSender()
	sender.respond("url", fakeOutcome{status: 1})
	queue := newTestQueue(sender, nil)

	deferItem(queue, "key", "url", DeferredItemOpts{})
	queue.handleDeferred()
	firstAge := queue.Stats().OldestUndelivered

	time.Sleep(10 * time.Millisecond)
	deferItem(queue, "key", "url", DeferredItemOpts{})
	t.Expect(queue.Stats().OldestUndelivered).To(Equal(firstAge))

	// Different content is a different message, so it starts its own clock.
	queue.SetDeferred("key", bytes.NewBufferString("changed"), "url", nil,
		DeferredItemOpts{})
	t.Expect(queue.Stats().OldestUndelivered).To(BeTemporally(">", firstAge))
}

func TestDeferredQueueStatsAdd(test *testing.T) {
	t := NewGomegaWithT(test)
	older := time.Now().Add(-time.Hour)
	newer := time.Now()

	stats := DeferredQueueStats{
		Undelivered:       1,
		OldestUndelivered: newer,
		Rejected:          2,
		Superseded:        3,
		LastDropped:       older,
	}
	stats.Add(DeferredQueueStats{
		Undelivered:       4,
		OldestUndelivered: older,
		Rejected:          5,
		Superseded:        6,
		LastDropped:       newer,
	})

	t.Expect(stats.Undelivered).To(BeEquivalentTo(5))
	t.Expect(stats.Rejected).To(BeEquivalentTo(7))
	t.Expect(stats.Superseded).To(BeEquivalentTo(9))
	t.Expect(stats.OldestUndelivered).To(Equal(older))
	t.Expect(stats.LastDropped).To(Equal(newer))

	// An empty queue must not make the aggregate look like it has a message
	// waiting since the zero time.
	stats.Add(DeferredQueueStats{})
	t.Expect(stats.OldestUndelivered).To(Equal(older))
	t.Expect(stats.LastDropped).To(Equal(newer))
}
