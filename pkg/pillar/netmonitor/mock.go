// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmonitor

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// MockNetworkMonitor is used for unit testing.
type MockNetworkMonitor struct {
	sync.Mutex
	Log    *base.LogObject
	MainRT int // inject syscall.RT_TABLE_MAIN for Linux network stack

	eventSubs  []subscriber
	interfaces map[int]MockInterface // key = ifIndex
	routes     []Route
}

// MockInterface : a simulated network interface and its state.
type MockInterface struct {
	Attrs   IfAttrs
	IPAddrs []*net.IPNet
	HwAddr  net.HardwareAddr
	DNS     DNSInfo
	DHCP    DHCPInfo
}

// AddOrUpdateInterface : allows to simulate an event of interface being added
// or updated.
func (m *MockNetworkMonitor) AddOrUpdateInterface(mockIf MockInterface) {
	m.Lock()
	defer m.Unlock()
	if m.interfaces == nil {
		m.interfaces = make(map[int]MockInterface)
	}
	ifIndex := mockIf.Attrs.IfIndex
	prev, existed := m.interfaces[ifIndex]
	m.interfaces[ifIndex] = mockIf
	// Interface add/update event.
	if !existed || !reflect.DeepEqual(mockIf.Attrs, prev.Attrs) {
		m.publishEvent(IfChange{
			Attrs: mockIf.Attrs,
			Added: !existed,
		})
	}
	// Interface IP address events.
	for _, addr := range mockIf.IPAddrs {
		var found bool
		for _, prevAddr := range prev.IPAddrs {
			if addr.IP.Equal(prevAddr.IP) &&
				bytes.Equal(addr.Mask, prevAddr.Mask) {
				found = true
				break
			}
		}
		if !found {
			m.publishEvent(AddrChange{
				IfIndex:   ifIndex,
				IfAddress: addr,
				Deleted:   false, // Added
			})
		}
	}
	for _, prevAddr := range prev.IPAddrs {
		var found bool
		for _, addr := range mockIf.IPAddrs {
			if addr.IP.Equal(prevAddr.IP) &&
				bytes.Equal(addr.Mask, prevAddr.Mask) {
				found = true
				break
			}
		}
		if !found {
			m.publishEvent(AddrChange{
				IfIndex:   ifIndex,
				IfAddress: prevAddr,
				Deleted:   true,
			})
		}
	}
	// Interface DNS change event.
	if !existed || !reflect.DeepEqual(mockIf.DNS, prev.DNS) {
		m.publishEvent(DNSInfoChange{
			IfIndex: ifIndex,
			Info:    mockIf.DNS,
		})
	}
}

// DelInterface : allows to simulate an event of removed interface.
func (m *MockNetworkMonitor) DelInterface(ifName string) {
	m.Lock()
	defer m.Unlock()
	ifIndex, exists := m.getIfIndex(ifName)
	if !exists {
		if m.Log != nil {
			m.Log.Fatal("failed to delete mock interface")
		}
		return
	}
	mockIf := m.interfaces[ifIndex]
	delete(m.interfaces, ifIndex)
	for _, ipAddr := range mockIf.IPAddrs {
		m.publishEvent(AddrChange{
			IfIndex:   ifIndex,
			IfAddress: ipAddr,
			Deleted:   true,
		})
	}
	m.publishEvent(DNSInfoChange{
		IfIndex: ifIndex,
		Info:    DNSInfo{},
	})
	m.publishEvent(IfChange{
		Attrs:   mockIf.Attrs,
		Deleted: true,
	})
}

// UpdateRoutes : allows to update the set of mock routes.
func (m *MockNetworkMonitor) UpdateRoutes(routes []Route) {
	m.Lock()
	defer m.Unlock()
	prev := m.routes
	m.routes = routes
	// Publish events for new routes.
	for _, route := range m.routes {
		var found bool
		for _, prevRoute := range prev {
			if reflect.DeepEqual(route, prevRoute) {
				found = true
				break
			}
		}
		if !found {
			m.publishEvent(RouteChange{
				Route:   route,
				Deleted: false,
			})
		}
	}
	// Publish events for removed routes.
	for _, prevRoute := range prev {
		var found bool
		for _, route := range m.routes {
			if reflect.DeepEqual(prevRoute, route) {
				found = true
				break
			}
		}
		if !found {
			m.publishEvent(RouteChange{
				Route:   prevRoute,
				Deleted: true,
			})
		}
	}
}

// ListInterfaces returns all mocked interfaces.
func (m *MockNetworkMonitor) ListInterfaces() (ifNames []string, err error) {
	m.Lock()
	defer m.Unlock()
	for _, mockIf := range m.interfaces {
		ifNames = append(ifNames, mockIf.Attrs.IfName)
	}
	// Sort to make output deterministic and easier to work with in unit tests.
	slices.Sort(ifNames)
	return ifNames, nil
}

// GetInterfaceIndex returns index of the mock interface.
func (m *MockNetworkMonitor) GetInterfaceIndex(ifName string) (
	ifIndex int, exists bool, err error) {
	m.Lock()
	defer m.Unlock()
	ifIndex, exists = m.getIfIndex(ifName)
	return ifIndex, exists, nil
}

// This method is run with the monitor in the locked state.
func (m *MockNetworkMonitor) getIfIndex(ifName string) (
	ifIndex int, exists bool) {
	for ifIndex, mockIf := range m.interfaces {
		if mockIf.Attrs.IfName == ifName {
			return ifIndex, true
		}
	}
	return -1, false
}

func (m *MockNetworkMonitor) ifNotFoundErr(ifIndex int) error {
	return fmt.Errorf("interface with index %d does not exist", ifIndex)
}

// GetInterfaceAttrs returns attributes of the mock interface.
func (m *MockNetworkMonitor) GetInterfaceAttrs(ifIndex int) (IfAttrs, error) {
	m.Lock()
	defer m.Unlock()
	mockIf, exists := m.interfaces[ifIndex]
	if !exists {
		return IfAttrs{}, m.ifNotFoundErr(ifIndex)
	}
	return mockIf.Attrs, nil
}

// GetInterfaceAddrs returns addresses assigned to the mock interface.
func (m *MockNetworkMonitor) GetInterfaceAddrs(ifIndex int) (
	[]*net.IPNet, net.HardwareAddr, error) {
	m.Lock()
	defer m.Unlock()
	mockIf, exists := m.interfaces[ifIndex]
	if !exists {
		return nil, nil, m.ifNotFoundErr(ifIndex)
	}
	return mockIf.IPAddrs, mockIf.HwAddr, nil
}

// GetInterfaceDNSInfo returns DNS info associated with the mock interface.
func (m *MockNetworkMonitor) GetInterfaceDNSInfo(ifIndex int) (DNSInfo, error) {
	m.Lock()
	defer m.Unlock()
	mockIf, exists := m.interfaces[ifIndex]
	if !exists {
		return DNSInfo{}, m.ifNotFoundErr(ifIndex)
	}
	return mockIf.DNS, nil
}

// GetInterfaceDHCPInfo returns DHCP info associated with the mock interface.
func (m *MockNetworkMonitor) GetInterfaceDHCPInfo(ifIndex int) (DHCPInfo, error) {
	m.Lock()
	defer m.Unlock()
	mockIf, exists := m.interfaces[ifIndex]
	if !exists {
		return DHCPInfo{}, m.ifNotFoundErr(ifIndex)
	}
	return mockIf.DHCP, nil
}

// GetInterfaceDefaultGWs returns default gateways associated with the mock interface.
func (m *MockNetworkMonitor) GetInterfaceDefaultGWs(ifIndex int) (gws []net.IP, err error) {
	m.Lock()
	defer m.Unlock()
	for _, route := range m.routes {
		if route.Table != m.MainRT {
			continue
		}
		if route.IfIndex != ifIndex {
			continue
		}
		if !route.IsDefaultRoute() {
			continue
		}
		gws = append(gws, route.Gw)
	}
	return gws, nil
}

// ListRoutes lists all mock routes.
func (m *MockNetworkMonitor) ListRoutes(filters RouteFilters) (rts []Route, err error) {
	m.Lock()
	defer m.Unlock()
	for _, route := range m.routes {
		if filters.FilterByIf {
			if route.IfIndex != filters.IfIndex {
				continue
			}
		}
		if filters.FilterByTable {
			if route.Table != filters.Table {
				continue
			}
		}
		rts = append(rts, route)
	}
	return rts, nil
}

// ClearCache does nothing.
func (m *MockNetworkMonitor) ClearCache() {}

// WatchEvents allows to watch for event created artificially using
// AddOrUpdateInterface, DelInterface and UpdateRoutes.
func (m *MockNetworkMonitor) WatchEvents(ctx context.Context, subName string) <-chan Event {
	m.Lock()
	defer m.Unlock()
	sub := subscriber{
		name:   subName,
		events: make(chan Event, eventChanBufSize),
		done:   ctx.Done(),
	}
	m.eventSubs = append(m.eventSubs, sub)
	return sub.events
}

// This method is run with the monitor in the locked state.
func (m *MockNetworkMonitor) publishEvent(ev Event) {
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
		default:
			if m.Log != nil {
				m.Log.Warnf("failed to deliver event %+v to subscriber %s",
					ev, sub.name)
			}
		}
		activeSubs = append(activeSubs, sub)
	}
	m.eventSubs = activeSubs
}
