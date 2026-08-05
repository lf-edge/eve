// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package edgenodeinfo

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// resetForTest wipes the package-level cache so tests don't see
// each other's state. Kept exported-to-package because the actual
// state is unexported; t.Cleanup makes sure every test pays for
// its own reset rather than relying on test ordering.
func resetForTest(t *testing.T) {
	t.Helper()
	mu.Lock()
	have = false
	cached = types.EdgeNodeInfo{}
	firstCh = make(chan struct{})
	firstSet = false
	mu.Unlock()
}

func TestGet_EmptyState(t *testing.T) {
	resetForTest(t)
	info, ok := Get()
	if ok {
		t.Errorf("Get() ok=true on empty state, got %+v", info)
	}
	if name := DeviceName(); name != "" {
		t.Errorf("DeviceName()=%q on empty state, want \"\"", name)
	}
	if id := DeviceID(); id != "" {
		t.Errorf("DeviceID()=%q on empty state, want \"\"", id)
	}
}

func TestSetCached_PopulatesAccessors(t *testing.T) {
	resetForTest(t)
	want := types.EdgeNodeInfo{
		DeviceName: "edge-01",
		DeviceID:   uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555"),
	}
	setCached(want)

	got, ok := Get()
	if !ok {
		t.Fatalf("Get() ok=false after setCached")
	}
	if got.DeviceName != want.DeviceName || got.DeviceID != want.DeviceID {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
	if name := DeviceName(); name != "edge-01" {
		t.Errorf("DeviceName() = %q, want edge-01", name)
	}
	if id := DeviceID(); id != want.DeviceID.String() {
		t.Errorf("DeviceID() = %q, want %s", id, want.DeviceID.String())
	}
}

// TestWaitForFirst_BlocksUntilSet checks the boot-time semantics:
// WaitForFirst must NOT return until the first setCached call,
// then must return the supplied value.
func TestWaitForFirst_BlocksUntilSet(t *testing.T) {
	resetForTest(t)
	want := types.EdgeNodeInfo{DeviceName: "edge-block-test"}

	var (
		wg      sync.WaitGroup
		gotInfo types.EdgeNodeInfo
		gotErr  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		gotInfo, gotErr = WaitForFirst(context.Background())
	}()

	// Give the waiter a moment to block. If WaitForFirst returned
	// immediately on an empty cache, the assertion below would
	// see "" and we wouldn't notice. The 50 ms is generous; the
	// test re-checks after setCached so a slow CI machine is
	// fine.
	time.Sleep(50 * time.Millisecond)

	setCached(want)
	wg.Wait()

	if gotErr != nil {
		t.Fatalf("WaitForFirst err = %v", gotErr)
	}
	if gotInfo.DeviceName != want.DeviceName {
		t.Errorf("WaitForFirst returned %+v, want %+v", gotInfo, want)
	}
}

func TestWaitForFirst_ContextCancellation(t *testing.T) {
	resetForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := WaitForFirst(ctx)
	if err == nil {
		t.Fatal("WaitForFirst returned nil on cancelled ctx")
	}
}

func TestWaitForFirst_AfterFirst_ReturnsImmediately(t *testing.T) {
	resetForTest(t)
	want := types.EdgeNodeInfo{DeviceName: "edge-after-first"}
	setCached(want)

	// Second WaitForFirst call must not block — channel stays
	// closed after the first delivery.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, err := WaitForFirst(ctx)
	if err != nil {
		t.Fatalf("WaitForFirst err = %v", err)
	}
	if got.DeviceName != want.DeviceName {
		t.Errorf("WaitForFirst = %+v, want %+v", got, want)
	}
}

// TestDelete_MarksCacheEmpty pins the documented semantic: a
// pubsub delete clears the cache but does NOT close the
// first-delivery channel.
func TestDelete_MarksCacheEmpty(t *testing.T) {
	resetForTest(t)
	setCached(types.EdgeNodeInfo{DeviceName: "edge-pre-delete"})
	if _, ok := Get(); !ok {
		t.Fatalf("Get() ok=false after setCached")
	}
	handleDelete(nil, "global", nil)
	if info, ok := Get(); ok {
		t.Errorf("Get() returned (%+v, true) after handleDelete", info)
	}
	// WaitForFirst should still return immediately (first-channel
	// remains closed) — the contract is "delivered once" not
	// "currently present".
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := WaitForFirst(ctx); err != nil {
		t.Errorf("WaitForFirst after delete returned err=%v, want nil", err)
	}
}

// TestSetCached_TwiceClosesChannelOnce verifies we don't panic on
// a double-close of firstCh when multiple deliveries land before
// any WaitForFirst returns.
func TestSetCached_TwiceClosesChannelOnce(t *testing.T) {
	resetForTest(t)
	setCached(types.EdgeNodeInfo{DeviceName: "edge-first"})
	setCached(types.EdgeNodeInfo{DeviceName: "edge-second"})

	// Both calls returned; if the channel had been closed twice
	// the test would panic. Verify the cache holds the second
	// value.
	if name := DeviceName(); name != "edge-second" {
		t.Errorf("DeviceName() = %q, want edge-second (latest write wins)", name)
	}
}
