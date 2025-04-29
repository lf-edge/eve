// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestLotsOfRequests(t *testing.T) {
	loAddr := netlink.Addr{
		IPNet: &net.IPNet{
			IP:   []byte{192, 168, 100, 1},
			Mask: []byte{255, 255, 255, 0},
		},
	}

	createDummyInterface(loAddr)
	defer delDummyInterface()

	listendns("")

	dm := startDnsmasq(loAddr.IP)
	defer dm.Stop()

	time.Sleep(time.Second)

	parallelLookup(20, 100, "google.com", "127.0.0.1:1054")

	count := 0
	time.Sleep(time.Second)
	for i := 0; i < 500; i++ {
		resolvedIP := lookup("127.0.0.1:1054", "google.com")
		count++
		if resolvedIP != nil {
			break
		}
		time.Sleep(time.Second / 2)
	}

	t.Logf("count: %d", count)
	if count > 70 {
		t.Fatalf("expected less ignored DNS requests until success, got %d", count)
	}

}
