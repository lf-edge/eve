// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmonitor

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netclone"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	netlinkSubBufSize = 128 * 1024 // bytes
	eventChanBufSize  = 64         // number of events

	// Give subscriber some time to receive notification.
	// This is used despite the fact that the subscription channel
	// is buffered, in order to not lose any notification during bursts
	// of events (e.g. after node reboot).
	publishTimeout = 3 * time.Second
)

// LinuxNetworkMonitor implements NetworkMonitor for the Linux network stack.
type LinuxNetworkMonitor struct {
	Log *base.LogObject
	// Disable netlink watcher. This is used only in unit tests, which are not run
	// with sufficient privileges to subscribe for netlink notifications.
	DisableWatcher bool

	// Subscribers (watching network events)
	eventSubs []subscriber
	// Cache and the list of subscribers are protected by separate locks
	// so that publishing will not get delayed by a subscriber trying to obtain
	// cached data during event processing.
	subsLock sync.Mutex

	// Cache
	cacheLock      sync.Mutex
	initialized    bool
	ifNameToIndex  map[string]int
	ifIndexToAttrs map[int]IfAttrs
	ifIndexToAddrs map[int]ifAddrs
	ifIndexToDNS   map[int]DNSInfo
	ifIndexToDHCP  map[int]DHCPInfo
	ifIndexToGWs   map[int][]net.IP
}

type ifAddrs struct {
	hwAddr  net.HardwareAddr
	ipAddrs []*net.IPNet
}

type subscriber struct {
	name   string
	events chan Event
	done   <-chan struct{}
}

// Init should be called first to prepare the monitor.
func (m *LinuxNetworkMonitor) init() {
	if m.initialized {
		m.Log.Fatal("Already initialized")
	}
	m.initCache()
	if !m.DisableWatcher {
		go m.watcher()
	}
	m.initialized = true
}

func (m *LinuxNetworkMonitor) initCache() {
	m.ifNameToIndex = make(map[string]int)
	m.ifIndexToAttrs = make(map[int]IfAttrs)
	m.ifIndexToAddrs = make(map[int]ifAddrs)
	m.ifIndexToDNS = make(map[int]DNSInfo)
	m.ifIndexToDHCP = make(map[int]DHCPInfo)
	m.ifIndexToGWs = make(map[int][]net.IP)
}

// ListInterfaces returns all interfaces present in the Linux network stack
// (in the namespaces of the caller process).
// ListInterfaces is not backed by the cache.
func (m *LinuxNetworkMonitor) ListInterfaces() (ifNames []string, err error) {
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, intf := range intfs {
		ifNames = append(ifNames, intf.Name)
	}
	return ifNames, nil
}

// GetInterfaceIndex returns index of the interface.
func (m *LinuxNetworkMonitor) GetInterfaceIndex(ifName string) (ifIndex int, exists bool, err error) {
	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()
	if !m.initialized {
		m.init()
	}
	if ifIndex, cached := m.ifNameToIndex[ifName]; cached {
		return ifIndex, true, nil
	}
	var link netlink.Link
	if link, err = netlink.LinkByName(ifName); err != nil {
		if _, notFound := err.(netlink.LinkNotFoundError); notFound {
			return -1, false, nil
		}
		return -1, false, err
	}
	ifIndex = link.Attrs().Index
	m.ifNameToIndex[ifName] = ifIndex
	return ifIndex, true, nil
}

// GetInterfaceAttrs returns interface attributes.
func (m *LinuxNetworkMonitor) GetInterfaceAttrs(ifIndex int) (attrs IfAttrs, err error) {
	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()
	if !m.initialized {
		m.init()
	}
	return m.getInterfaceAttrs(ifIndex)
}

func (m *LinuxNetworkMonitor) getInterfaceAttrs(ifIndex int) (attrs IfAttrs, err error) {
	if attrs, cached := m.ifIndexToAttrs[ifIndex]; cached {
		return attrs, nil
	}
	var link netlink.Link
	if link, err = netlink.LinkByIndex(ifIndex); err != nil {
		return attrs, err
	}
	attrs = m.ifAttrsFromLink(link)
	m.ifIndexToAttrs[ifIndex] = attrs
	return attrs, nil
}

func (m *LinuxNetworkMonitor) ifAttrsFromLink(link netlink.Link) IfAttrs {
	var lowerUP bool
	switch link.Attrs().OperState {
	case netlink.OperUnknown:
		// It is common for cellular modems that the operating state is not reported,
		// whereas lower-layer IFF_* flags are available and can be used to determine
		// link status.
		lowerUP = link.Attrs().RawFlags&unix.IFF_LOWER_UP != 0
	case netlink.OperUp:
		lowerUP = true
	default:
		lowerUP = false
	}
	return IfAttrs{
		IfIndex:       link.Attrs().Index,
		IfName:        link.Attrs().Name,
		IfType:        link.Type(),
		IsLoopback:    (link.Attrs().Flags & net.FlagLoopback) != 0,
		WithBroadcast: (link.Attrs().Flags & net.FlagBroadcast) != 0,
		AdminUp:       (link.Attrs().Flags & net.FlagUp) != 0,
		LowerUp:       lowerUP,
		Enslaved:      link.Attrs().MasterIndex != 0,
		MasterIfIndex: link.Attrs().MasterIndex,
		MTU:           uint16(link.Attrs().MTU),
	}
}

// GetInterfaceAddrs returns IP addresses and the HW address assigned
// to the interface.
func (m *LinuxNetworkMonitor) GetInterfaceAddrs(ifIndex int) ([]*net.IPNet, net.HardwareAddr, error) {
	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()
	if !m.initialized {
		m.init()
	}
	if addrs, cached := m.ifIndexToAddrs[ifIndex]; cached {
		return addrs.ipAddrs, addrs.hwAddr, nil
	}
	var (
		err            error
		link           netlink.Link
		addrs4, addrs6 []netlink.Addr
	)
	if link, err = netlink.LinkByIndex(ifIndex); err != nil {
		return nil, nil, err
	}
	if addrs4, err = netlink.AddrList(link, netlink.FAMILY_V4); err != nil {
		return nil, nil, err
	}
	if addrs6, err = netlink.AddrList(link, netlink.FAMILY_V6); err != nil {
		return nil, nil, err
	}
	addrs := ifAddrs{hwAddr: link.Attrs().HardwareAddr}
	for _, addr := range addrs4 {
		addrs.ipAddrs = append(addrs.ipAddrs, ipNetFromNetlinkAddr(addr))
	}
	for _, addr := range addrs6 {
		addrs.ipAddrs = append(addrs.ipAddrs, ipNetFromNetlinkAddr(addr))
	}
	m.ifIndexToAddrs[ifIndex] = addrs
	return addrs.ipAddrs, addrs.hwAddr, nil
}

// GetInterfaceDNSInfo returns DNS info for the interface obtained
// from resolv.conf file.
func (m *LinuxNetworkMonitor) GetInterfaceDNSInfo(ifIndex int) (info DNSInfo, err error) {
	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()
	if !m.initialized {
		m.init()
	}
	if info, cached := m.ifIndexToDNS[ifIndex]; cached {
		return info, nil
	}
	attrs, err := m.getInterfaceAttrs(ifIndex)
	if err != nil {
		return info, err
	}
	ifName := attrs.IfName
	resolvConf := types.IfnameToResolvConf(ifName)
	if resolvConf == "" {
		// Interface without IP is expected to not have resolv.conf file.
		// We should be therefore careful about the log level here to avoid
		// many log messages.
		m.Log.Functionf("No resolv.conf for %s", ifName)
		return info, nil
	}
	info = m.parseDNSInfo(resolvConf)
	m.ifIndexToDNS[ifIndex] = info
	return info, nil
}

func (m *LinuxNetworkMonitor) parseDNSInfo(resolvConf string) (info DNSInfo) {
	info.ResolvConfPath = resolvConf
	dc := netclone.DnsReadConfig(resolvConf)
	for _, server := range dc.Servers {
		// Might have port number
		s := strings.Split(server, ":")
		ip := net.ParseIP(s[0])
		if ip == nil {
			m.Log.Warnf("failed to parse %s", server)
			continue
		}
		info.DNSServers = append(info.DNSServers, ip)
	}
	for _, dn := range dc.Search {
		info.Domains = append(info.Domains, dn)
	}
	return info
}

// GetInterfaceDHCPInfo returns DHCP info for the interface obtained
// from dhcpcd.
func (m *LinuxNetworkMonitor) GetInterfaceDHCPInfo(ifIndex int) (info DHCPInfo, err error) {
	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()
	if !m.initialized {
		m.init()
	}
	if info, cached := m.ifIndexToDHCP[ifIndex]; cached {
		return info, nil
	}
	attrs, err := m.getInterfaceAttrs(ifIndex)
	if err != nil {
		return info, err
	}
	ifName := attrs.IfName
	// XXX Getting error -1 unless we add argument -4.
	// XXX Add IPv6 support.
	m.Log.Functionf("Calling dhcpcd -U -4 %s\n", ifName)
	stdoutStderr, err := base.Exec(m.Log, "dhcpcd", "-U", "-4", ifName).CombinedOutput()
	if err != nil {
		if strings.Contains(string(stdoutStderr), "dhcp_dump: No such file or directory") {
			// DHCP is not configured for this interface. Return empty DHCPInfo.
			err = nil
		} else {
			err = fmt.Errorf("dhcpcd -U failed: %s: %s", string(stdoutStderr), err)
		}
		return
	}
	m.Log.Tracef("dhcpcd -U got %v\n", string(stdoutStderr))
	lines := strings.Split(string(stdoutStderr), "\n")
	var masklen int
	var subnet net.IP
	for _, line := range lines {
		items := strings.Split(line, "=")
		if len(items) != 2 {
			continue
		}
		m.Log.Tracef("Got <%s> <%s>\n", items[0], items[1])
		switch items[0] {
		case "network_number":
			network := trimQuotes(items[1])
			m.Log.Functionf("GetDhcpInfo(%s) network_number %s\n", ifName,
				network)
			ip := net.ParseIP(network)
			if ip == nil {
				m.Log.Errorf("Failed to parse %s\n", network)
				continue
			}
			subnet = ip
		case "subnet_cidr":
			str := trimQuotes(items[1])
			m.Log.Functionf("GetDhcpInfo(%s) subnet_cidr %s\n", ifName,
				str)
			masklen, err = strconv.Atoi(str)
			if err != nil {
				m.Log.Errorf("Failed to parse masklen %s\n", str)
				continue
			}
		case "ntp_servers":
			str := trimQuotes(items[1])
			m.Log.Functionf("GetDhcpInfo(%s) ntp_servers %s\n", ifName,
				str)
			servers := strings.Split(str, " ")
			for _, server := range servers {
				ip := net.ParseIP(server)
				if ip != nil {
					info.NtpServers = append(info.NtpServers, ip)
				}
			}
		}
	}
	info.Subnet = &net.IPNet{IP: subnet, Mask: net.CIDRMask(masklen, 32)}
	m.ifIndexToDHCP[ifIndex] = info
	return info, nil
}

// GetInterfaceDefaultGWs return a list of IP addresses of default gateways
// used by the given interface. This is based on routes from the main routing table.
func (m *LinuxNetworkMonitor) GetInterfaceDefaultGWs(ifIndex int) (gws []net.IP, err error) {
	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()
	if !m.initialized {
		m.init()
	}
	if info, cached := m.ifIndexToGWs[ifIndex]; cached {
		return info, nil
	}
	table := syscall.RT_TABLE_MAIN
	// Note that a default route is represented as nil Dst
	filter := netlink.Route{Table: table, LinkIndex: ifIndex, Dst: nil}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	fflags |= netlink.RT_FILTER_DST
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC, &filter, fflags)
	if err != nil {
		return nil, err
	}
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifIndex != 0 && rt.LinkIndex != ifIndex {
			continue
		}
		gws = append(gws, rt.Gw)
	}
	m.ifIndexToGWs[ifIndex] = gws
	return gws, nil
}

// ListRoutes returns routes currently present in the routing tables.
// The set of routes to list can be filtered.
// ListRoutes is not backed by the cache.
func (m *LinuxNetworkMonitor) ListRoutes(filters RouteFilters) (routes []Route, err error) {
	var fflags uint64
	filter := netlink.Route{}
	if filters.FilterByTable {
		fflags |= netlink.RT_FILTER_TABLE
		filter.Table = filters.Table
	}
	if filters.FilterByIf {
		fflags |= netlink.RT_FILTER_OIF
		filter.LinkIndex = filters.IfIndex
	}
	nlRoutes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC, &filter, fflags)
	if err != nil {
		err = fmt.Errorf("netlink.RouteListFiltered failed: %v", err)
		return nil, err
	}
	for _, nlRoute := range nlRoutes {
		routes = append(routes, Route{
			IfIndex: nlRoute.LinkIndex,
			Dst:     nlRoute.Dst,
			Gw:      nlRoute.Gw,
			Table:   nlRoute.Table,
			Data:    nlRoute,
		})
	}
	return routes, nil
}

// WatchEvents allows to subscribe to watch for events from the Linux network stack.
func (m *LinuxNetworkMonitor) WatchEvents(ctx context.Context, subName string) <-chan Event {
	m.cacheLock.Lock()
	if !m.initialized {
		m.init()
	}
	m.cacheLock.Unlock()
	m.subsLock.Lock()
	defer m.subsLock.Unlock()
	sub := subscriber{
		name:   subName,
		events: make(chan Event, eventChanBufSize),
		done:   ctx.Done(),
	}
	m.eventSubs = append(m.eventSubs, sub)
	return sub.events
}

// ClearCache clears cached state data.
func (m *LinuxNetworkMonitor) ClearCache() {
	m.cacheLock.Lock()
	defer m.cacheLock.Unlock()
	if !m.initialized {
		return
	}
	m.initCache()
}

func (m *LinuxNetworkMonitor) watcher() {
	doneChan := make(chan struct{})
	linkChan := m.linkSubscribe(doneChan)
	addrChan := m.addrSubscribe(doneChan)
	routeChan := m.routeSubscribe(doneChan)
	dnsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.Log.Fatal(err)
	}
	for _, resolvDir := range types.ResolveConfDirs {
		if err = m.createDir(resolvDir); err != nil {
			m.Log.Fatal(err)
		}
		if err = dnsWatcher.Add(resolvDir); err != nil {
			m.Log.Fatal(err)
		}
	}
	// Remember previously published IfChange notifications to avoid
	// spurious events.
	lastIfChange := make(map[int]IfChange)

	for {
		select {
		case linkUpdate, ok := <-linkChan:
			if !ok {
				m.Log.Warn("Link subscription was closed")
				linkChan = m.linkSubscribe(doneChan)
				continue
			}
			ifIndex := linkUpdate.Attrs().Index
			attrs := m.ifAttrsFromLink(linkUpdate)
			added := linkUpdate.Header.Type == syscall.RTM_NEWLINK
			deleted := linkUpdate.Header.Type == syscall.RTM_DELLINK
			event := IfChange{
				Attrs:   attrs,
				Added:   added,
				Deleted: deleted,
			}
			prevIfChange := lastIfChange[ifIndex]
			if prevIfChange.Equal(event) {
				continue
			}
			lastIfChange[ifIndex] = event
			m.cacheLock.Lock()
			// Clear previously cached attributes.
			delete(m.ifIndexToAttrs, ifIndex)
			// If added or deleted, remove this interface from the cache altogether.
			if added || deleted {
				for ifName2, ifIndex2 := range m.ifNameToIndex {
					if ifIndex2 == ifIndex {
						delete(m.ifNameToIndex, ifName2)
					}
				}
				delete(m.ifIndexToAddrs, ifIndex)
				delete(m.ifIndexToDNS, ifIndex)
				delete(m.ifIndexToDHCP, ifIndex)
			}
			m.cacheLock.Unlock()
			m.publishEvent(event)

		case addrUpdate, ok := <-addrChan:
			if !ok {
				m.Log.Warn("Address subscription was closed")
				addrChan = m.addrSubscribe(doneChan)
				continue
			}
			event := AddrChange{
				IfIndex:   addrUpdate.LinkIndex,
				IfAddress: &addrUpdate.LinkAddress,
				Deleted:   !addrUpdate.NewAddr,
			}
			m.cacheLock.Lock()
			// Remove cached addresses for this interface.
			delete(m.ifIndexToAddrs, addrUpdate.LinkIndex)
			delete(m.ifIndexToDHCP, addrUpdate.LinkIndex)
			m.cacheLock.Unlock()
			m.publishEvent(event)

		case routeChange, ok := <-routeChan:
			if !ok {
				m.Log.Warn("Route subscription was closed")
				routeChan = m.routeSubscribe(doneChan)
				continue
			}
			event := RouteChange{
				Route: Route{
					IfIndex: routeChange.LinkIndex,
					Dst:     routeChange.Dst,
					Gw:      routeChange.Gw,
					Table:   routeChange.Table,
					Data:    routeChange.Route,
				},
				Added:   routeChange.Type == syscall.RTM_NEWROUTE,
				Deleted: routeChange.Type == syscall.RTM_DELROUTE,
			}
			m.cacheLock.Lock()
			if routeChange.Table == syscall.RT_TABLE_MAIN && routeChange.Dst == nil {
				// The set of default gateways have changed -> remove cached entries.
				delete(m.ifIndexToGWs, routeChange.LinkIndex)
			}
			m.cacheLock.Unlock()
			m.publishEvent(event)

		case dnsChange := <-dnsWatcher.Events:
			switch dnsChange.Op {
			case fsnotify.Create, fsnotify.Remove, fsnotify.Write:
				ifName := types.ResolvConfToIfname(dnsChange.Name)
				if ifName == "" {
					continue
				}
				link, err := netlink.LinkByName(ifName)
				if err != nil {
					continue
				}
				ifIndex := link.Attrs().Index
				event := DNSInfoChange{
					IfIndex: ifIndex,
				}
				if dnsChange.Op != fsnotify.Remove {
					event.Info = m.parseDNSInfo(dnsChange.Name)
				}
				m.cacheLock.Lock()
				if dnsChange.Op == fsnotify.Remove {
					delete(m.ifIndexToDNS, ifIndex)
				} else {
					m.ifIndexToDNS[ifIndex] = event.Info
				}
				m.cacheLock.Unlock()
				m.publishEvent(event)
			}
		}
	}
}

func (m *LinuxNetworkMonitor) publishEvent(ev Event) {
	m.subsLock.Lock()
	defer m.subsLock.Unlock()
	var activeSubs []subscriber
	for _, sub := range m.eventSubs {
		select {
		case <-sub.done:
			// unsubscribe
			continue
		default:
			// continue subscription
		}
		select {
		case sub.events <- ev:
		case <-time.After(publishTimeout):
			m.Log.Warnf("Failed to deliver event %+v to subscriber %s: timeout (%v)",
				ev, sub.name, publishTimeout)
		}
		activeSubs = append(activeSubs, sub)
	}
	m.eventSubs = activeSubs
}

func (m *LinuxNetworkMonitor) linkSubscribe(doneChan chan struct{}) chan netlink.LinkUpdate {
	linkChan := make(chan netlink.LinkUpdate, eventChanBufSize)
	linkErrFunc := func(err error) {
		m.Log.Errorf("LinkSubscribe failed %s\n", err)
	}
	linkOpts := netlink.LinkSubscribeOptions{
		ErrorCallback: linkErrFunc,
		ListExisting:  true, // XXX: currently required by zedrouter (later will be removed)
	}
	if err := netlink.LinkSubscribeWithOptions(
		linkChan, doneChan, linkOpts); err != nil {
		m.Log.Fatal(err)
	}
	return linkChan
}

func (m *LinuxNetworkMonitor) addrSubscribe(doneChan chan struct{}) chan netlink.AddrUpdate {
	addrChan := make(chan netlink.AddrUpdate, eventChanBufSize)
	addrErrFunc := func(err error) {
		m.Log.Errorf("AddrSubscribe failed %s\n", err)
	}
	addrOpts := netlink.AddrSubscribeOptions{
		ErrorCallback:     addrErrFunc,
		ReceiveBufferSize: netlinkSubBufSize,
	}
	if err := netlink.AddrSubscribeWithOptions(
		addrChan, doneChan, addrOpts); err != nil {
		m.Log.Fatal(err)
	}
	return addrChan
}

func (m *LinuxNetworkMonitor) routeSubscribe(doneChan chan struct{}) chan netlink.RouteUpdate {
	routeChan := make(chan netlink.RouteUpdate, eventChanBufSize)
	routeErrFunc := func(err error) {
		m.Log.Errorf("RouteSubscribe failed %s\n", err)
	}
	routeOpts := netlink.RouteSubscribeOptions{
		ErrorCallback: routeErrFunc,
		ListExisting:  true, // XXX: currently required by zedrouter (later will be removed)
	}
	if err := netlink.RouteSubscribeWithOptions(
		routeChan, doneChan, routeOpts); err != nil {
		m.Log.Fatal(err)
	}
	return routeChan
}

func (m *LinuxNetworkMonitor) createDir(dirname string) error {
	if _, err := os.Stat(dirname); err != nil {
		if err = os.MkdirAll(dirname, 0700); err != nil {
			err = fmt.Errorf("failed to create directory %s: %w", dirname, err)
			return err
		}
	}
	return nil
}

// Remove single or double quotes.
func trimQuotes(str string) string {
	if len(str) < 2 {
		return str
	}
	c := str[len(str)-1]
	if (c == '"' || c == '\'') && str[0] == c {
		return str[1 : len(str)-1]
	} else {
		return str
	}
}

func ipNetFromNetlinkAddr(addr netlink.Addr) *net.IPNet {
	// For interfaces with a peer (like Point-to-Point, which in EVE is used for wwan),
	// we must take mask from the peer.
	// See: https://github.com/vishvananda/netlink/commit/b1cc70dea22210e3b9deca021a824f4edfd9dcf1
	mask := addr.Mask
	if addr.Peer != nil {
		mask = addr.Peer.Mask
	}
	return &net.IPNet{
		IP:   addr.IP,
		Mask: mask,
	}
}
