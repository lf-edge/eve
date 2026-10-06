// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nistate

import (
	"net"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// TestReaddedVIFDoesNotInheritRemovedVIFLease verifies that the IP lease
// cached for a VIF is dropped when the VIF is removed from the network
// instance, so that a VIF added back later with the same application and MAC
// address is not reported with the old address.
func TestReaddedVIFDoesNotInheritRemovedVIFLease(t *testing.T) {
	g := NewWithT(t)
	lc := &LinuxCollector{
		log: base.NewSourceLogObject(logrus.StandardLogger(), "nistate_test", 0),
		nis: make(map[uuid.UUID]*niInfo),
	}
	niUUID := uuid.Must(uuid.NewV4())
	appUUID := uuid.Must(uuid.NewV4())
	niConfig := types.NetworkInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: niUUID},
		Type:           types.NetworkInstanceTypeLocal,
	}
	bridge := NIBridge{NI: niUUID, BrNum: 1, BrIfName: "bn1"}
	mac, err := net.ParseMAC("02:16:3e:00:00:02")
	g.Expect(err).ToNot(HaveOccurred())
	vif := AppVIF{
		App:            appUUID,
		NI:             niUUID,
		AppNum:         1,
		NetAdapterName: "vif1",
		HostIfName:     "nbu2x1",
		GuestIfMAC:     mac,
	}
	g.Expect(lc.StartCollectingForNI(niConfig, bridge, []AppVIF{vif}, false)).To(Succeed())
	ni := lc.nis[niUUID]

	// The guest leased an address on the VIF: dnsmasq wrote the lease into
	// its lease file and the collector loaded it from there.
	leasedIP := net.ParseIP("10.11.12.3")
	ni.ipLeases, _ = ni.ipLeases.addOrUpdateLease(dnsmasqIPLease{
		brIfName:  bridge.BrIfName,
		leaseTime: time.Now().Add(time.Hour),
		macAddr:   mac,
		ipAddr:    leasedIP,
		hostname:  appUUID.String(),
	})
	g.Expect(lc.processIPLeases(ni)).To(HaveLen(1))
	g.Expect(ni.vifs[0].hasIP(leasedIP)).To(BeTrue())

	// The VIF is removed from the NI. zedrouter prunes its lease from the
	// dnsmasq lease file, which the collector notes when it reloads the file.
	for i := range ni.ipLeases {
		ni.ipLeases[i].removedAt = time.Now()
	}
	g.Expect(lc.UpdateCollectingForNI(niConfig, nil, false)).To(Succeed())

	// The VIF is added back with the same application and MAC address, and
	// the next lease file event makes the collector process the leases again.
	g.Expect(lc.UpdateCollectingForNI(niConfig, []AppVIF{vif}, false)).To(Succeed())
	g.Expect(lc.processIPLeases(ni)).To(BeEmpty(),
		"the lease of the removed VIF was assigned to the re-added VIF")
	g.Expect(ni.vifs[0].hasIP(leasedIP)).To(BeFalse())
}
