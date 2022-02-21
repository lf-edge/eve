// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager_test

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/eriknordmark/ipinfo"

	dpcmngr "github.com/lf-edge/eve/pkg/pillar/dpcmanager"
	"github.com/lf-edge/eve/pkg/pillar/types"
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

// MockWwanWatcher allows to simulate events coming from wwan microservice.
// Can be injected to DpcManager.WwanWatcher in UTs.
type MockWwanWatcher struct {
	sync.Mutex
	wwanStatus  types.WwanStatus
	wwanMetrics types.WwanMetrics
	wwanEvents  chan dpcmngr.WwanEvent
}

// UpdateStatus : simulate update of Wwan status.
func (m *MockWwanWatcher) UpdateStatus(status types.WwanStatus) {
	m.Lock()
	defer m.Unlock()

	m.wwanStatus = status
	if m.wwanEvents != nil {
		m.wwanEvents <- dpcmngr.WwanEventNewStatus
	}
}

// UpdateMetrics : simulate update of Wwan metrics.
func (m *MockWwanWatcher) UpdateMetrics(metrics types.WwanMetrics) {
	m.Lock()
	defer m.Unlock()

	m.wwanMetrics = metrics
	if m.wwanEvents != nil {
		m.wwanEvents <- dpcmngr.WwanEventNewMetrics
	}
}

// Watch for simulated wwan events.
func (m *MockWwanWatcher) Watch(context.Context) (<-chan dpcmngr.WwanEvent, error) {
	m.Lock()
	defer m.Unlock()
	if m.wwanEvents == nil {
		m.wwanEvents = make(chan dpcmngr.WwanEvent, 10)
	}
	return m.wwanEvents, nil
}

// LoadStatus returns last status submitted via UpdateStatus.
func (m *MockWwanWatcher) LoadStatus() (types.WwanStatus, error) {
	m.Lock()
	defer m.Unlock()
	return m.wwanStatus, nil
}

// LoadMetrics returns last metrics submitted via UpdateMetrics.
func (m *MockWwanWatcher) LoadMetrics() (types.WwanMetrics, error) {
	m.Lock()
	defer m.Unlock()
	return m.wwanMetrics, nil
}

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
