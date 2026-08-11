// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

func newTestVethConfigurator() *VethConfigurator {
	logger := logrus.New()
	log := base.NewSourceLogObject(logger, "test", 1234)
	return &VethConfigurator{Log: log}
}

// stubContainerPID replaces the containerd lookup for a test.
func stubContainerPID(t *testing.T, fn func(ctx context.Context, name string) (int, error)) {
	t.Helper()
	orig, origPeriod := lookupContainerPID, containerPollPeriod
	lookupContainerPID = fn
	containerPollPeriod = time.Millisecond
	t.Cleanup(func() {
		lookupContainerPID = orig
		containerPollPeriod = origPeriod
	})
}

func TestWaitForContainerRetriesUntilRunning(t *testing.T) {
	calls := 0
	stubContainerPID(t, func(context.Context, string) (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("no such container")
		}
		return 42, nil
	})
	c := newTestVethConfigurator()
	if err := c.waitForContainer(context.Background(), "witness"); err != nil {
		t.Fatalf("waitForContainer: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 lookups, got %d", calls)
	}
}

func TestWaitForContainerStopsOnCancel(t *testing.T) {
	stubContainerPID(t, func(context.Context, string) (int, error) {
		return 0, errContainerNotRunning
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	c := newTestVethConfigurator()
	err := c.waitForContainer(ctx, "witness")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestVethDeleteIsNoopWhenAlreadyGone(t *testing.T) {
	c := newTestVethConfigurator()

	t.Run("host-side link missing", func(t *testing.T) {
		item := Veth{Peer1: VethPeer{IfName: "no-such-veth0"}}
		if err := c.Delete(context.Background(), item); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	})

	t.Run("container task not running", func(t *testing.T) {
		stubContainerPID(t, func(context.Context, string) (int, error) {
			return 0, errContainerNotRunning
		})
		item := Veth{Peer1: VethPeer{IfName: "no-such-veth0", ContainerName: "witness"}}
		if err := c.Delete(context.Background(), item); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	})

	t.Run("containerd failure is reported", func(t *testing.T) {
		stubContainerPID(t, func(context.Context, string) (int, error) {
			return 0, errors.New("containerd unavailable")
		})
		item := Veth{Peer1: VethPeer{IfName: "no-such-veth0", ContainerName: "witness"}}
		if err := c.Delete(context.Background(), item); err == nil {
			t.Fatal("expected an error when containerd cannot be queried")
		}
	})
}
