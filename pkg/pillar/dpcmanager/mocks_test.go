// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager_test

import (
	"net"
	"sync"
	"time"

	"github.com/eriknordmark/ipinfo"
)

// MockWatchdog does absolutely nothing.
// Can be injected to DpcManager.Watchdog in UTs.
type MockWatchdog struct{}

// RegisterFileWatchdog does nothing.
func (m *MockWatchdog) RegisterFileWatchdog(string) {}

// StillRunning does nothing.
func (m *MockWatchdog) StillRunning(_ string, _, _ time.Duration) {}

// CheckMaxTimeTopic does nothing.
func (m *MockWatchdog) CheckMaxTimeTopic(_, _ string, _ time.Time, _, _ time.Duration) {}

// MockGeoService allows to simulate geolocation service.
// Can be injected to DpcManager.GeoService in UTs.
type MockGeoService struct {
	sync.Mutex
	geoInfo map[string]*ipinfo.IPInfo
}

// SetGeolocationInfo : associate IP address with a simulated geolocation information.
func (m *MockGeoService) SetGeolocationInfo(ipAddr net.IP, geoInfo *ipinfo.IPInfo) {
	m.Lock()
	defer m.Unlock()
	if m.geoInfo == nil {
		m.geoInfo = make(map[string]*ipinfo.IPInfo)
	}
	m.geoInfo[ipAddr.String()] = geoInfo
}

// GetGeolocationInfo tries to obtain geolocation information
// corresponding to the given IP address.
func (m *MockGeoService) GetGeolocationInfo(ipAddr net.IP) (*ipinfo.IPInfo, error) {
	m.Lock()
	defer m.Unlock()
	geoInfo := m.geoInfo[ipAddr.String()]
	return geoInfo, nil
}
