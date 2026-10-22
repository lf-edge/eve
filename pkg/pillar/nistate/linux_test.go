// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nistate

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const testTimeout = 5 * time.Second

func TestNotifyWatchersNeverBlocks(t *testing.T) {
	log := newTestCollector().log
	fullWatcher := make(chan int, 2)
	roomyWatcher := make(chan int, 10)
	watchers := []chan int{fullWatcher, roomyWatcher}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5; i++ {
			dropped := notifyWatchers(log, "test", watchers, i)
			if dropped != (i >= 2) {
				t.Errorf("unexpected result of notifyWatchers for update %d", i)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("notifyWatchers blocked on a watcher which is not reading")
	}
	// Updates which did not fit were dropped, others were not affected.
	if len(fullWatcher) != 2 || <-fullWatcher != 0 || <-fullWatcher != 1 {
		t.Fatal("unexpected updates received by the watcher with a full channel")
	}
	if len(roomyWatcher) != 5 {
		t.Fatalf("expected 5 updates, got %d", len(roomyWatcher))
	}
	for i := 0; i < 5; i++ {
		if got := <-roomyWatcher; got != i {
			t.Fatalf("expected %d, got %d", i, got)
		}
	}
}

// An IP assignment update dropped because a watcher is not keeping up must not leave
// the watcher out of sync: the full state is sent to it later.
func TestIPAssignmentsResyncAfterDroppedUpdate(t *testing.T) {
	lc := newTestCollector()
	niID := uuid.Must(uuid.NewV4())
	ni := &niInfo{}
	vif := &vifInfo{AppVIF: AppVIF{NI: niID, HostIfName: "nbu1x1"}}
	vif.addIP(net.ParseIP("10.0.0.5"), types.AddressSourceStatic,
		time.Now().Add(time.Hour))
	ni.vifs = []*vifInfo{vif}
	lc.nis[niID] = ni
	watcherCh := make(chan []VIFAddrsUpdate, 1)
	lc.ipAssignWatchers = []chan []VIFAddrsUpdate{watcherCh}

	// The watcher is full and misses the second update.
	lc.notifyIPAssignWatchers(lc.ipAssignWatchers, []VIFAddrsUpdate{{}})
	lc.notifyIPAssignWatchers(lc.ipAssignWatchers, []VIFAddrsUpdate{{}})
	if !lc.ipAssignResync {
		t.Fatal("dropped update should schedule a resync")
	}
	// Resync while the watcher is still full: tried again later.
	lc.resyncIPAssignments()
	if !lc.ipAssignResync {
		t.Fatal("resync should be retried if the watcher is still not keeping up")
	}
	<-watcherCh
	lc.resyncIPAssignments()
	if lc.ipAssignResync {
		t.Fatal("resync should be done")
	}
	select {
	case updates := <-watcherCh:
		if len(updates) != 1 || updates[0].New.VIF.HostIfName != "nbu1x1" ||
			len(updates[0].New.IPv4Addrs) != 1 ||
			!updates[0].New.IPv4Addrs[0].Address.Equal(net.ParseIP("10.0.0.5")) {
			t.Fatalf("unexpected state sent by resync: %+v", updates)
		}
	default:
		t.Fatal("full state was not sent to the watcher")
	}
	// Nothing to do without a dropped update.
	lc.resyncIPAssignments()
	select {
	case <-watcherCh:
		t.Fatal("unexpected resync")
	default:
	}
}

func newTestCollector() *LinuxCollector {
	logger := logrus.New()
	log := base.NewSourceLogObject(logger, "test", 1234)
	return &LinuxCollector{
		log:             log,
		nis:             make(map[uuid.UUID]*niInfo),
		capturedPackets: make(chan capturedPacket, 1),
	}
}

func TestSendCapturedPacketIsCancellable(t *testing.T) {
	lc := newTestCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !lc.sendCapturedPacket(ctx, capturedPacket{}) {
		t.Fatal("send to a channel with free capacity should succeed")
	}
	// The channel is now full and nobody is reading from it.
	result := make(chan bool, 1)
	go func() { result <- lc.sendCapturedPacket(ctx, capturedPacket{}) }()
	select {
	case <-result:
		t.Fatal("send should block while the channel is full")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case sent := <-result:
		if sent {
			t.Fatal("cancelled send should not report success")
		}
	case <-time.After(testTimeout):
		t.Fatal("send was not abandoned after the context was cancelled")
	}
}

// StopCollectingForNI (called by zedrouter) must not get stuck waiting for a PCAP
// Go routine blocked on a full capturedPackets channel, which is not being drained
// by the event loop.
func TestStopCollectingDoesNotDeadlockWithBusyEventLoop(t *testing.T) {
	lc := newTestCollector()
	niID := uuid.Must(uuid.NewV4())
	ni := &niInfo{config: types.NetworkInstanceConfig{UUIDandVersion: types.UUIDandVersion{UUID: niID}}}
	lc.nis[niID] = ni

	pcapCtx, cancelPCAP := context.WithCancel(context.Background())
	ni.cancelPCAP = cancelPCAP
	ni.pcapWG.Add(1)
	go func() {
		defer ni.pcapWG.Done()
		for {
			if !lc.sendCapturedPacket(pcapCtx, capturedPacket{}) {
				return
			}
		}
	}()
	// Let the PCAP Go routine fill the channel and block.
	time.Sleep(100 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- lc.StopCollectingForNI(niID) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("StopCollectingForNI is stuck waiting for PCAP")
	}
	if _, exists := lc.nis[niID]; exists {
		t.Fatal("NI was not removed")
	}
}

// PCAP must not give up when the interface to capture from does not exist (yet),
// e.g. when the mirror interface is created by the NI reconciler only after
// state collecting for the NI was started.
func TestPCAPRetriesUntilStopped(t *testing.T) {
	lc := newTestCollector()
	br := NIBridge{
		NI:           uuid.Must(uuid.NewV4()),
		BrNum:        1,
		BrIfName:     "nonexistent-br",
		MirrorIfName: "nonexistent-m",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go lc.sniffDNSandDHCP(ctx, &wg, br, types.NetworkInstanceTypeSwitch, true)

	exited := make(chan struct{})
	go func() {
		wg.Wait()
		close(exited)
	}()
	select {
	case <-exited:
		t.Fatal("PCAP Go routine gave up after failing to open the interface")
	case <-time.After(pcapRetryMinDelay + 500*time.Millisecond):
	}
	cancel()
	select {
	case <-exited:
	case <-time.After(testTimeout):
		t.Fatal("PCAP Go routine did not stop after the context was cancelled")
	}
}
