// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nistate

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const leaseGCTime = 5 * time.Minute

// IP lease granted to an application by dnsmasq.
type dnsmasqIPLease struct {
	brIfName  string
	removedAt time.Time // For garbage collection, zero if still present in the file.
	purge     bool      // Marked for removal inside gcIPLeases.

	// From leases file
	leaseTime time.Time // Time when it will expire.
	macAddr   net.HardwareAddr
	ipAddr    net.IP
	hostname  string
}

// Equal returns true if this and the other lease are equal
// in all its attributes (excluding those used by State Collector for GC purposes).
func (l dnsmasqIPLease) Equal(l2 dnsmasqIPLease) bool {
	return l.brIfName == l2.brIfName &&
		l.leaseTime.Equal(l2.leaseTime) &&
		bytes.Equal(l.macAddr, l2.macAddr) &&
		l.ipAddr.Equal(l2.ipAddr) &&
		l.hostname == l2.hostname
}

// dnsmasqIPLeases is a list of IP leases granted to apps by dnsmasq.
type dnsmasqIPLeases []dnsmasqIPLease

// findLease returns a pointer so the caller can update the lease information.
// Ignores a lease which has expired if ignoreExpired is set.
func (leases dnsmasqIPLeases) findLease(
	hostname string, macAddr net.HardwareAddr, ignoreExpired bool) *dnsmasqIPLease {
	for i := range leases {
		l := &leases[i]
		if l.hostname != hostname {
			continue
		}
		if !bytes.Equal(l.macAddr, macAddr) {
			continue
		}
		if ignoreExpired && l.leaseTime.Before(time.Now()) {
			log.Warnf("%s: Ignoring expired lease: %v", LogAndErrPrefix, *l)
			return nil
		}
		return l
	}
	return nil
}

func (leases dnsmasqIPLeases) addOrUpdateLease(
	lease dnsmasqIPLease) (newSlice dnsmasqIPLeases, changed bool) {
	l := leases.findLease(lease.hostname, lease.macAddr, false)
	if l == nil {
		return append(leases, lease), true
	} else if !l.Equal(lease) {
		*l = lease
		return leases, true
	}
	// Lease reloaded from file without change.
	l.purge = false
	l.removedAt = time.Time{}
	return leases, false
}

// updateLeases updates the set of IP leases maintained by the State Collector
// for the given NI/bridge.
// However, do not remove leases that disappeared right away, only after they have
// not been seen for at least 5 minutes (this is to handle file truncation/rewrite
// by dnsmasq).
func (lc *LinuxCollector) reloadIPLeases(br NIBridge) (changed bool) {
	leases, err := lc.readIPLeases(br)
	if err != nil {
		log.Warnf("%s: readIPLeases (br: %v) failed: %v", LogAndErrPrefix, br, err)
		return false
	}
	niInfo := lc.nis[br.NI]
	// Those leases which just disappeared from the file will have removedAt
	// set to the current time.
	now := time.Now()
	for i := range niInfo.ipLeases {
		l := &niInfo.ipLeases[i]
		if l.removedAt.IsZero() {
			l.removedAt = now
		}
	}
	// Add any new ones or update existing.
	for _, l := range leases {
		var updated bool
		if niInfo.ipLeases, updated = niInfo.ipLeases.addOrUpdateLease(l); updated {
			changed = true
		}
	}
	return changed
}

// Process reloaded dnsmasq leases and update IPv4 and IPv6 addresses of VIFs inside
// L3 networks accordingly.
func (lc *LinuxCollector) processIPLeases(niInfo *niInfo) (
	addrUpdates []VIFAddrsUpdate) {
	if niInfo.config.Type == types.NetworkInstanceTypeSwitch {
		// Should be unreachable.
		log.Warnf("%s: processIPLeases called on switch NI (%v)",
			LogAndErrPrefix, niInfo)
		return nil
	}
	for i := range niInfo.vifs {
		vifAddrs := &niInfo.vifs[i]
		vif := vifAddrs.VIF
		if !vif.Activated {
			continue
		}
		ipLease := niInfo.ipLeases.findLease(vif.App.String(), vif.GuestIfMAC, true)
		if ipLease == nil && vifAddrs.IPv4Addr != nil {
			prevAddrs := *vifAddrs
			vifAddrs.IPv4Addr = nil
			newAddrs := *vifAddrs
			addrUpdates = append(addrUpdates, VIFAddrsUpdate{
				Prev: prevAddrs,
				New:  newAddrs,
			})
		} else if ipLease != nil && !ipLease.ipAddr.Equal(vifAddrs.IPv4Addr) {
			prevAddrs := *vifAddrs
			vifAddrs.IPv4Addr = ipLease.ipAddr
			newAddrs := *vifAddrs
			addrUpdates = append(addrUpdates, VIFAddrsUpdate{
				Prev: prevAddrs,
				New:  newAddrs,
			})
		}
	}
	return addrUpdates
}

// gcIPLeases removes leases that were removed from the file and expired
// more than 5 minutes ago.
func (lc *LinuxCollector) gcIPLeases(niInfo *niInfo) (purgedAny bool) {
	for i := range niInfo.ipLeases {
		l := &niInfo.ipLeases[i]
		if l.removedAt.IsZero() ||
			time.Since(l.removedAt) <= leaseGCTime ||
			time.Since(l.leaseTime) <= leaseGCTime {
			continue
		}
		l.purge = true
		purgedAny = true
	}
	if purgedAny {
		var newLeases dnsmasqIPLeases
		for _, l := range niInfo.ipLeases {
			if !l.purge {
				newLeases = append(newLeases, l)
			}
			lc.log.Noticef("%s: purged lease: %+v", LogAndErrPrefix, l)
		}
		niInfo.ipLeases = newLeases
	}
	return purgedAny
}

// readIPLeases returns a slice of dnsmasqLease structs, containing MAC, IP, app UUID.
// Example line from a lease file:
// 1560664900 00:16:3e:00:01:01 10.1.0.3 63120af3-42c4-4d84-9faf-de0582d496c2 *
func (lc *LinuxCollector) readIPLeases(br NIBridge) ([]dnsmasqIPLease, error) {
	var leases []dnsmasqIPLease
	leasesFile := devicenetwork.DnsmasqLeaseFilePath(br.BrIfName)
	fileDesc, err := os.Open(leasesFile)
	if err != nil {
		return leases, err
	}
	reader := bufio.NewReader(fileDesc)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return leases, err
			}
			break
		}
		// remove trailing "/n" from line
		line = line[0 : len(line)-1]
		// Should have 5 space-separated fields. We only use 4.
		tokens := strings.Split(line, " ")
		if len(tokens) < 4 {
			log.Errorf("%s: less than 4 fields in leases file: %v",
				LogAndErrPrefix, tokens)
			continue
		}
		i, err := strconv.ParseInt(tokens[0], 10, 64)
		if err != nil {
			log.Errorf("%s: bad unix time %s from IP lease (%s): %s",
				LogAndErrPrefix, tokens[0], line, err)
			i = 0
		}
		macAddr, err := net.ParseMAC(tokens[1])
		if err != nil {
			log.Errorf("%s: bad MAC address %s from IP lease (%s): %s",
				LogAndErrPrefix, tokens[1], line, err)
			continue
		}
		ipAddr := net.ParseIP(tokens[2])
		if ipAddr == nil {
			log.Errorf("%s: bad IP address %s from IP lease (%s): %s",
				LogAndErrPrefix, tokens[2], line, err)
			continue
		}
		lease := dnsmasqIPLease{
			brIfName:  br.BrIfName,
			leaseTime: time.Unix(i, 0),
			macAddr:   macAddr,
			ipAddr:    ipAddr,
			hostname:  tokens[3],
		}
		leases = append(leases, lease)
	}
	return leases, nil
}
