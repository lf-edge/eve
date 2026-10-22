// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"sync"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/profile"
)

// Config holds data that LPS sends back to EVE in responses.
type Config struct {
	ServerToken        string                      `json:"serverToken"`
	Profile            string                      `json:"profile"`
	RadioSilence       bool                        `json:"radioSilence"`
	AppCommands        []*profile.AppCommand       `json:"appCommands,omitempty"`
	DevCommand         *DevCmdConfig               `json:"devCommand,omitempty"`
	AppBootConfigs     []*profile.AppBootConfig    `json:"appBootConfigs,omitempty"`
	LocalNetworkConfig *profile.LocalNetworkConfig `json:"localNetworkConfig,omitempty"`
}

// DevCmdConfig holds a device command to be sent to EVE.
type DevCmdConfig struct {
	Timestamp uint64 `json:"timestamp"`
	Command   string `json:"command"`
}

// Received holds data that EVE posts to LPS.
type Received struct {
	RadioStatus *profile.RadioStatus      `json:"radioStatus,omitempty"`
	AppInfoList *profile.LocalAppInfoList `json:"appInfoList,omitempty"`
	DevInfo     *profile.LocalDevInfo     `json:"devInfo,omitempty"`
	Location    *eveinfo.ZInfoLocation    `json:"location,omitempty"`
	NetworkInfo *profile.NetworkInfo      `json:"networkInfo,omitempty"`
	AppBootInfo *profile.AppBootInfoList  `json:"appBootInfo,omitempty"`
}

// State is the shared in-memory state of the LPS.
type State struct {
	mu       sync.RWMutex
	broker   *Broker
	Config   Config   `json:"config"`
	Received Received `json:"received"`
}

// New creates a new State with default values.
func New() *State {
	return &State{broker: NewBroker()}
}

// Broker returns the shared notification broker used to drive the LPS
// Signal endpoint and the UI event stream.
func (s *State) Broker() *Broker {
	return s.broker
}

// GetConfig returns a copy of the current config.
func (s *State) GetConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Config
}

// SetServerToken sets the server token. The token is configured via the
// UI or /manage API and does not change the content of any config response,
// so we wake the UI subscribers (to refresh the visible config)
// but do not mark any endpoint pending.
func (s *State) SetServerToken(token string) {
	s.mu.Lock()
	s.Config.ServerToken = token
	if s.Config.LocalNetworkConfig != nil {
		s.Config.LocalNetworkConfig.ServerToken = token
	}
	s.mu.Unlock()
	s.broker.NotifyAny()
}

// SetProfile sets the local profile.
func (s *State) SetProfile(p string) {
	s.mu.Lock()
	s.Config.Profile = p
	s.mu.Unlock()
	s.broker.MarkPending(profile.ConfigEndpoint_CONFIG_ENDPOINT_LOCAL_PROFILE)
}

// SetRadioSilence sets the radio silence flag.
func (s *State) SetRadioSilence(on bool) {
	s.mu.Lock()
	s.Config.RadioSilence = on
	s.mu.Unlock()
	s.broker.MarkPending(profile.ConfigEndpoint_CONFIG_ENDPOINT_RADIO)
}

// SetAppCommands sets the app commands list.
func (s *State) SetAppCommands(cmds []*profile.AppCommand) {
	s.mu.Lock()
	s.Config.AppCommands = cmds
	s.mu.Unlock()
	s.broker.MarkPending(profile.ConfigEndpoint_CONFIG_ENDPOINT_APP_INFO)
}

// SetDevCommand sets the device command.
func (s *State) SetDevCommand(cmd *DevCmdConfig) {
	s.mu.Lock()
	s.Config.DevCommand = cmd
	s.mu.Unlock()
	s.broker.MarkPending(profile.ConfigEndpoint_CONFIG_ENDPOINT_DEV_INFO)
}

// SetAppBootConfigs sets the app boot configurations.
func (s *State) SetAppBootConfigs(configs []*profile.AppBootConfig) {
	s.mu.Lock()
	s.Config.AppBootConfigs = configs
	s.mu.Unlock()
	s.broker.MarkPending(profile.ConfigEndpoint_CONFIG_ENDPOINT_APP_BOOT_INFO)
}

// SetLocalNetworkConfig sets the local network configuration.
func (s *State) SetLocalNetworkConfig(cfg *profile.LocalNetworkConfig) {
	s.mu.Lock()
	s.Config.LocalNetworkConfig = cfg
	s.mu.Unlock()
	s.broker.MarkPending(profile.ConfigEndpoint_CONFIG_ENDPOINT_NETWORK)
}

// SetRadioStatus stores the radio status received from EVE.
func (s *State) SetRadioStatus(rs *profile.RadioStatus) {
	s.mu.Lock()
	s.Received.RadioStatus = rs
	s.mu.Unlock()
	s.broker.NotifyAny()
}

// SetAppInfoList stores the app info list received from EVE.
func (s *State) SetAppInfoList(info *profile.LocalAppInfoList) {
	s.mu.Lock()
	s.Received.AppInfoList = info
	s.mu.Unlock()
	s.broker.NotifyAny()
}

// SetDevInfo stores the device info received from EVE.
func (s *State) SetDevInfo(info *profile.LocalDevInfo) {
	s.mu.Lock()
	s.Received.DevInfo = info
	s.mu.Unlock()
	s.broker.NotifyAny()
}

// SetLocation stores the location received from EVE.
func (s *State) SetLocation(loc *eveinfo.ZInfoLocation) {
	s.mu.Lock()
	s.Received.Location = loc
	s.mu.Unlock()
	s.broker.NotifyAny()
}

// SetNetworkInfo stores the network info received from EVE.
func (s *State) SetNetworkInfo(info *profile.NetworkInfo) {
	s.mu.Lock()
	s.Received.NetworkInfo = info
	s.mu.Unlock()
	s.broker.NotifyAny()
}

// SetAppBootInfo stores the app boot info list received from EVE.
func (s *State) SetAppBootInfo(info *profile.AppBootInfoList) {
	s.mu.Lock()
	s.Received.AppBootInfo = info
	s.mu.Unlock()
	s.broker.NotifyAny()
}

// GetReceived returns a copy of all received data.
func (s *State) GetReceived() Received {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Received
}

// GetAll returns both config and received data.
func (s *State) GetAll() (Config, Received) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Config, s.Received
}
