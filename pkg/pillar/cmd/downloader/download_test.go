// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve-libs/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "downloader-test", 0)
	os.Exit(m.Run())
}

// refusingPost returns a post function that refuses its first refusals calls
// with zedUpload.SyncerRetry, the way the transport does while its request
// queue is full, and returns finalErr from then on. calls counts the calls.
func refusingPost(refusals int, finalErr error) (post func() error, calls *int) {
	calls = new(int)
	post = func() error {
		*calls++
		if *calls <= refusals {
			return zedUpload.SyncerRetry
		}
		return finalErr
	}
	return post, calls
}

func TestPostWithRetryAcceptsAtOnce(t *testing.T) {
	post, calls := refusingPost(0, nil)
	if err := postWithRetry(context.Background(), post, time.Minute, "blob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("post called %d times, want 1", *calls)
	}
}

func TestPostWithRetryRetriesWhileQueueIsFull(t *testing.T) {
	post, calls := refusingPost(2, nil)
	start := time.Now()
	if err := postWithRetry(context.Background(), post, time.Minute, "blob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *calls != 3 {
		t.Fatalf("post called %d times, want 3", *calls)
	}
	// Two refusals cost the first two backoff delays.
	if minWait := postRetryMinDelay * 3; time.Since(start) < minWait {
		t.Fatalf("retried after %v, want at least %v of backoff", time.Since(start), minWait)
	}
}

func TestPostWithRetryDoesNotRetryOtherErrors(t *testing.T) {
	boom := errors.New("boom")
	post, calls := refusingPost(0, boom)
	err := postWithRetry(context.Background(), post, time.Minute, "blob")
	if !errors.Is(err, boom) {
		t.Fatalf("got error %v, want %v", err, boom)
	}
	if *calls != 1 {
		t.Fatalf("post called %d times, want 1", *calls)
	}
}

func TestPostWithRetryGivesUpWhenQueueStaysFull(t *testing.T) {
	post, calls := refusingPost(1<<30, nil)
	err := postWithRetry(context.Background(), post, 300*time.Millisecond, "blob")
	if !errors.Is(err, zedUpload.SyncerRetry) {
		t.Fatalf("got error %v, want one wrapping %v", err, zedUpload.SyncerRetry)
	}
	if *calls < 2 {
		t.Fatalf("post called %d times, want at least 2", *calls)
	}
}

func TestPostWithRetryStopsWhenCancelled(t *testing.T) {
	post, _ := refusingPost(1<<30, nil)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	err := postWithRetry(ctx, post, time.Hour, "blob")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got error %v, want one wrapping %v", err, context.Canceled)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("cancellation took %v to be noticed", time.Since(start))
	}
}

func TestAwaitResponseDeliversMessages(t *testing.T) {
	respChan := make(chan *zedUpload.DronaRequest, 1)
	want := &zedUpload.DronaRequest{}
	respChan <- want
	stallCheck := make(chan time.Time)
	got, err := awaitResponse(respChan, stallCheck, time.Now(), "blob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %p, want %p", got, want)
	}
}

func TestAwaitResponseFailsOnClosedChannel(t *testing.T) {
	respChan := make(chan *zedUpload.DronaRequest)
	close(respChan)
	stallCheck := make(chan time.Time)
	if _, err := awaitResponse(respChan, stallCheck, time.Now(), "blob"); err == nil {
		t.Fatal("expected an error for a closed response channel")
	}
}

func TestAwaitResponseFailsWithoutAnyMessage(t *testing.T) {
	// A request the transport never picked up sends nothing, ever.
	respChan := make(chan *zedUpload.DronaRequest)
	stallCheck := time.NewTicker(10 * time.Millisecond)
	defer stallCheck.Stop()
	longAgo := time.Now().Add(-2 * maxStalledTime)
	_, err := awaitResponse(respChan, stallCheck.C, longAgo, "blob")
	if err == nil {
		t.Fatal("expected a stall error when no message arrives at all")
	}
}

func TestAwaitResponseKeepsWaitingWhileNotStalled(t *testing.T) {
	respChan := make(chan *zedUpload.DronaRequest, 1)
	stallCheck := time.NewTicker(10 * time.Millisecond)
	defer stallCheck.Stop()
	time.AfterFunc(100*time.Millisecond, func() { respChan <- &zedUpload.DronaRequest{} })
	if _, err := awaitResponse(respChan, stallCheck.C, time.Now(), "blob"); err != nil {
		t.Fatalf("stall reported although progress was recent: %v", err)
	}
}
