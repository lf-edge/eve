// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package mmdbus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/sirupsen/logrus"
)

const (
	// UnavailSignalMetric : given signal metric is not available.
	UnavailSignalMetric = 1<<31 - 1 // 2147483647
	// UnavailLocAttribute : given location attribute is not available.
	UnavailLocAttribute = -(1 << 15) // -32768
)

const (
	notifChanBuffer            = 128
	dbusSigChanBuffer          = 256
	dbusCallTimeout            = 10 * time.Second
	scanProvidersTimeout       = 3 * time.Minute
	modemDisableTimeout        = 10 * time.Second
	changePrimarySIMTimeout    = 30 * time.Second
	changeInitEPSBearerTimeout = 20 * time.Second
)

const (
	// SIMStateAbsent : SIM card is not present in the SIM slot.
	SIMStateAbsent = "absent"
	// SIMStatePresent : SIM card is present in the SIM slot.
	SIMStatePresent = "present"
	// SIMStateInactive : SIM slot is not activated (SIM card presence is unknown).
	SIMStateInactive = "inactive"
	// SIMStateError = SIM slot/card is in failed state.
	SIMStateError = "error"
)

// Client provides methods for communicating with ModemManager via D-Bus.
type Client struct {
	mutex   sync.Mutex
	log     *base.LogObject
	conn    *dbus.Conn
	mmObj   dbus.BusObject
	lastMsg time.Time
	modems  map[string]*Modem // key: Modem.Path

	// Modem state monitoring
	notifChan         chan Notification
	monitorWG         sync.WaitGroup
	monitorCtx        context.Context
	monitorCancel     context.CancelFunc
	sigPollPeriodSecs uint32
}

// Modem encapsulates all properties of a cellular modem.
type Modem struct {
	// Modem object path in DBus.
	Path string
	// DBus paths of all bearers used by the modem.
	BearerPaths []string
	// DBus paths of all SIM slots/cards of the modem.
	SIMPaths []string
	// Note that LogicalLabel is not set or known by Client.
	// Similarly, ConfigError and ProbeError are updated by MMAgent,
	// Client leaves them empty.
	// Client also does not set VisibleProviders, but provides method
	// ScanVisibleProviders to get data for this field.
	Status  types.WwanNetworkStatus
	Metrics types.WwanNetworkMetrics
	// Location is only available if modem has GNSS receiver and location tracking
	// is enabled.
	Location types.WwanLocationInfo
}

// ConnectionArgs encapsulates all arguments for connection request.
type ConnectionArgs struct {
	types.CellularAccessPoint
	DecryptedUsername string
	DecryptedPassword string
}

// Event is used to signal change in modem state data.
type Event uint8

const (
	// EventUndefined : undefined event (never actually published).
	EventUndefined Event = iota
	// EventAddedModem : a new cellular modem was detected by ModemManager.
	EventAddedModem
	// EventRemovedModem : a previously existing cellular modem is no longer present.
	EventRemovedModem
	// EventUpdatedModemStatus : some properties inside Modem.Status have changed.
	EventUpdatedModemStatus
	// EventUpdatedModemMetrics : Modem.Metrics have been updated.
	EventUpdatedModemMetrics
	// EventUpdatedModemLocation : Modem.Location has been updated.
	EventUpdatedModemLocation
)

// Notification published to watcher (MMAgent).
type Notification struct {
	Event Event
	Modem Modem
}

// NewClient is a constructor for Client.
func NewClient(log *base.LogObject) (*Client, error) {
	var err error
	client := new(Client)
	client.log = log
	client.conn, err = dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	client.mmObj = client.conn.Object(MMInterface, MMObjectPath)
	return client, nil
}

// RunModemMonitoring starts Go routine that monitors changes in the state
// of cellular modems as reported by ModemManager, parses and stores obtained
// modem attributes into pillar's Wwan* types and publishes notifications
// summarizing the latest state to the agent.
// Returns initial state data for all modems and a channel through which state changes
// will be announced.
func (c *Client) RunModemMonitoring(signalPollPeriod time.Duration) (
	initialState []Modem, notifs <-chan Notification) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.notifChan = make(chan Notification, notifChanBuffer)
	c.startModemMonitor()
	c.reloadModems()
	c.setSignalPollPeriod(signalPollPeriod)
	for _, modem := range c.modems {
		c.setupSignalPolling(dbus.ObjectPath(modem.Path))
		initialState = append(initialState, *modem)
	}
	return initialState, c.notifChan
}

// Set rate for signal quality periodic polling.
// Zero poll period disables polling.
func (c *Client) setSignalPollPeriod(period time.Duration) {
	c.sigPollPeriodSecs = uint32(period.Seconds())
	if c.sigPollPeriodSecs == 0 && period > 0 {
		// Smallest support period.
		c.sigPollPeriodSecs = 1
	}
}

func (c *Client) setupSignalPolling(modemPath dbus.ObjectPath) {
	modemObj := c.conn.Object(MMInterface, modemPath)
	err := c.callDBusMethod(modemObj, SignalMethodSetup, nil, c.sigPollPeriodSecs)
	if err != nil {
		c.log.Errorf("failed to setup signal polling period %d secs for modem %s: %v",
			c.sigPollPeriodSecs, modemPath, err)
	}
}

// Starts a new Go routine for modem state monitoring.
// Client should be already locked by the caller.
func (c *Client) startModemMonitor() {
	c.monitorCtx, c.monitorCancel = context.WithCancel(context.Background())
	c.monitorWG.Add(1)
	go func() {
		defer c.monitorWG.Done()
		rule := fmt.Sprintf("type='signal', path_namespace='%s'", MMObjectPath)
		c.conn.BusObject().Call(DBusMethodAddMatch, 0, rule)
		sigChan := make(chan *dbus.Signal, dbusSigChanBuffer)
		defer close(sigChan)
		c.conn.Signal(sigChan)
		defer c.conn.RemoveSignal(sigChan)
		for {
			select {
			case <-c.monitorCtx.Done():
				return

			case signal := <-sigChan:
				c.mutex.Lock()
				c.lastMsg = time.Now()
				c.processDbusSignal(signal)
				c.mutex.Unlock()
			}
		}
	}()
}

func (c *Client) processDbusSignal(signal *dbus.Signal) {
	switch signal.Name {
	// See: https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-objectmanager
	case DBusSignalInterfacesAdded:
		if len(signal.Body) < 2 {
			c.log.Warnf("Unexpected body length for signal %s (%d)",
				DBusSignalInterfacesAdded, len(signal.Body))
			return
		}
		path, ok := signal.Body[0].(dbus.ObjectPath)
		if !ok {
			c.log.Warnf("Failed to convert path from signal %s (%v)",
				DBusSignalInterfacesAdded, signal.Body[0])
			return
		}
		if !strings.HasPrefix(string(path), ModemPathPrefix) {
			c.log.Warnf("Skipped signal %s for path %s",
				DBusSignalInterfacesAdded, path)
			return
		}
		modem, err := c.getModem(path)
		if err != nil {
			c.log.Error(err)
			return
		}
		prevModem, exists := c.modems[string(path)]
		if !exists {
			c.setupSignalPolling(path)
			c.modems[string(path)] = modem
			c.notifChan <- Notification{
				Event: EventAddedModem,
				Modem: *modem,
			}
		} else {
			// Not expecting new interfaces added under a modem path
			// other than the modem interface itself.
			c.log.Warnf("Received signal %s for already known modem: %+v",
				DBusSignalInterfacesAdded, signal)
			if !prevModem.Status.Equal(modem.Status) {
				c.notifChan <- Notification{
					Event: EventUpdatedModemStatus,
					Modem: *modem,
				}
			}
			if prevModem.Metrics != modem.Metrics {
				c.notifChan <- Notification{
					Event: EventUpdatedModemMetrics,
					Modem: *modem,
				}
			}
			if prevModem.Location != modem.Location {
				c.notifChan <- Notification{
					Event: EventUpdatedModemLocation,
					Modem: *modem,
				}
			}
			c.modems[string(path)] = modem
		}

	// See: https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-objectmanager
	case DBusSignalInterfacesRemoved:
		if len(signal.Body) < 2 {
			c.log.Warnf("Unexpected body length for signal %s (%d)",
				DBusSignalInterfacesRemoved, len(signal.Body))
			return
		}
		path, ok := signal.Body[0].(dbus.ObjectPath)
		if !ok {
			c.log.Warnf("Failed to convert path from signal %s (%v)",
				DBusSignalInterfacesRemoved, signal.Body[0])
			return
		}
		if !strings.HasPrefix(string(path), ModemPathPrefix) {
			c.log.Warnf("Skipped signal %s for path %s",
				DBusSignalInterfacesRemoved, path)
			return
		}
		removedIntfs, ok := signal.Body[1].([]string)
		if !ok {
			c.log.Warnf("Failed to convert list of interfaces removed (%v)",
				signal.Body[1])
			return
		}
		if !generics.ContainsItem(removedIntfs, ModemInterface) {
			c.log.Warnf("Modem %s has removed interfaces "+
				"but not including itself: %v", path, removedIntfs)
			return
		}
		modem, exists := c.modems[string(path)]
		if !exists {
			c.log.Warnf("Received signal %s for unknown modem %s",
				DBusSignalInterfacesRemoved, path)
			return
		}
		c.notifChan <- Notification{
			Event: EventRemovedModem,
			Modem: *modem,
		}
		delete(c.modems, string(path))

	// See: https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-properties
	case DBusSignalPropertiesChanged:
		if len(signal.Body) < 3 {
			c.log.Warnf("Unexpected body length for signal %s (%d)",
				DBusSignalPropertiesChanged, len(signal.Body))
			return
		}
		interfaceName, ok := signal.Body[0].(string)
		if !ok {
			c.log.Warnf("Failed to convert interface name from signal %s (%v)",
				DBusSignalPropertiesChanged, signal.Body[0])
			return
		}
		properties, ok := signal.Body[1].(map[string]dbus.Variant)
		if !ok {
			c.log.Warnf("Failed to convert properties from signal %s (%v)",
				DBusSignalPropertiesChanged, signal.Body[1])
			return
		}
		// Find out which modem(s) has/have changed and in what scope.
		var modemPaths []string
		var statusChanged, metricsChanged, locationChanged bool
		path := string(signal.Path)
		switch interfaceName {
		case ModemInterface:
			for property := range properties {
				switch property {
				case ModemPropertySignalQualityName:
					// Ignore this, we get signal metrics from SignalInterface.
					continue
				case ModemPropertyRATsName:
					// The set of RATs used changed, now we need to get metrics
					// from a different property.
					metricsChanged = true
					fallthrough
				default:
					statusChanged = true
				}
				modemPaths = generics.AppendIfNotDuplicate(modemPaths, path)
			}
		case Modem3GPPInterface:
			statusChanged = true
			modemPaths = generics.AppendIfNotDuplicate(modemPaths, path)
		case SignalInterface:
			metricsChanged = true
			modemPaths = generics.AppendIfNotDuplicate(modemPaths, path)
		case LocationInterface:
			for property := range properties {
				switch property {
				case LocationPropertyEnabledName, LocationPropertySignalsName:
					statusChanged = true
				case LocationPropertyName:
					locationChanged = true
				default:
					continue
				}
				modemPaths = generics.AppendIfNotDuplicate(modemPaths, path)
			}
		case BearerInterface:
			for property := range properties {
				switch property {
				case BearerPropertyConnectedName:
					statusChanged = true
					// When disconnected, metrics are cleared.
					// When connected, metrics are loaded.
					metricsChanged = true
				case BearerPropertyStatsName:
					metricsChanged = true
				default:
					statusChanged = true
				}
			}
			for _, modem := range c.modems {
				if generics.ContainsItem(modem.BearerPaths, path) {
					modemPaths = generics.AppendIfNotDuplicate(
						modemPaths, modem.Path)
				}
			}
		case SIMInterface:
			statusChanged = true
			for _, modem := range c.modems {
				if generics.ContainsItem(modem.SIMPaths, path) {
					modemPaths = generics.AppendIfNotDuplicate(
						modemPaths, modem.Path)
				}
			}
		}
		// Reload changed state data and publish notification(s).
		for _, modemPath := range modemPaths {
			modem := c.modems[modemPath]
			if modem == nil {
				c.log.Warnf("Received %s for unknown modem %s",
					DBusSignalPropertiesChanged, modemPath)
				continue
			}
			modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
			if statusChanged {
				status, bearers, sims, err := c.getModemStatus(modemObj)
				if err != nil {
					c.log.Error(err)
					continue
				}
				modem.BearerPaths = bearers
				modem.SIMPaths = sims
				if !modem.Status.Equal(status) {
					modem.Status = status
					c.notifChan <- Notification{
						Event: EventUpdatedModemStatus,
						Modem: *modem,
					}
				}
			}
			if metricsChanged {
				var metrics types.WwanNetworkMetrics
				if len(modem.Status.CurrentRATs) > 0 {
					metrics = c.getModemMetrics(modemObj,
						modem.Status.CurrentRATs[0])
				}
				metrics.PhysAddrs = modem.Status.PhysAddrs
				if modem.Metrics != metrics {
					modem.Metrics = metrics
					c.notifChan <- Notification{
						Event: EventUpdatedModemMetrics,
						Modem: *modem,
					}
				}
			}
			if locationChanged {
				location := c.getModemLocation(modemObj)
				if modem.Location != location {
					modem.Location = location
					c.notifChan <- Notification{
						Event: EventUpdatedModemLocation,
						Modem: *modem,
					}
				}
			}
		}
	}
}

// Reloads Client.modems with the latest state data obtained from the ModemManager.
// Client should be already locked by the caller.
func (c *Client) reloadModems() {
	c.modems = make(map[string]*Modem)
	err := c.callDBusMethod(c.mmObj, MMMethodScanDevices, nil)
	if err != nil {
		c.log.Warnf("Failed to trigger new scan for connected modem devices: %v", err)
	}
	managedObjects := make(map[dbus.ObjectPath]interface{})
	err = c.callDBusMethod(c.mmObj, DBusMethodManagedObjects, &managedObjects)
	if err != nil {
		c.log.Errorf("Failed to list modems: %v", err)
		return
	}
	for path := range managedObjects {
		modem, err := c.getModem(path)
		if err != nil {
			c.log.Error(err)
			continue
		}
		c.modems[string(path)] = modem
	}
}

func (c *Client) getModem(path dbus.ObjectPath) (*Modem, error) {
	modem := &Modem{Path: string(path)}
	modemObj := c.conn.Object(MMInterface, path)
	status, bearers, sims, err := c.getModemStatus(modemObj)
	if err != nil {
		return nil, err
	}
	modem.Status = status
	modem.BearerPaths = bearers
	modem.SIMPaths = sims
	if len(status.CurrentRATs) > 0 {
		modem.Metrics = c.getModemMetrics(modemObj, status.CurrentRATs[0])
	}
	modem.Metrics.PhysAddrs = status.PhysAddrs
	modem.Location = c.getModemLocation(modemObj)
	return modem, nil
}

// Get modem status.
// Only fails if it cannot determine modem physical addresses.
func (c *Client) getModemStatus(modemObj dbus.BusObject) (
	status types.WwanNetworkStatus, bearerPaths, simPaths []string, err error) {
	physAddrs, proto, err := c.getModemPhysAddrs(modemObj)
	if err != nil {
		err = fmt.Errorf("cannot determine modem %s physical addresses: %w",
			modemObj.Path(), err)
		return
	}
	status.PhysAddrs = physAddrs
	status.Module.ControlProtocol = proto
	// Get cellular module info.
	_ = getDBusProperty(c, modemObj, ModemPropertyModel, &status.Module.Model)
	_ = getDBusProperty(c, modemObj, ModemPropertyRevision, &status.Module.Revision)
	_ = getDBusProperty(c, modemObj, ModemPropertyManufacturer, &status.Module.Manufacturer)
	_ = getDBusProperty(c, modemObj, ModemPropertyIMEI, &status.Module.IMEI)
	status.Module.Name = status.Module.IMEI
	var modemState int32
	_ = getDBusProperty(c, modemObj, ModemPropertyState, &modemState)
	var failReason uint32
	switch modemState {
	case ModemStateUnknown:
		status.Module.OpMode = types.WwanOpModeUnrecognized
	case ModemStateRegistered, ModemStateConnecting:
		status.Module.OpMode = types.WwanOpModeOnline
	case ModemStateConnected:
		status.Module.OpMode = types.WwanOpModeConnected
	case ModemStateFailed:
		_ = getDBusProperty(c, modemObj, ModemPropertyStateFailReason, &failReason)
		fallthrough
	default:
		status.Module.OpMode = types.WwanOpModeOffline
	}
	var powerState uint32
	_ = getDBusProperty(c, modemObj, ModemPropertyPowerState, &powerState)
	if powerState == ModemPowerStateOff || powerState == ModemPowerStateLow {
		status.Module.OpMode = types.WwanOpModeRadioOff
	}
	// Get SIM info.
	var primarySIM uint32
	_ = getDBusProperty(c, modemObj, ModemPropertyPrimarySIMSlot, &primarySIM)
	if primarySIM == 0 {
		// Multiple SIM slots not supported on this modem.
		primarySIM = 1
	}
	var simSlots []dbus.ObjectPath
	_ = getDBusProperty(c, modemObj, ModemPropertySIMSlots, &simSlots)
	if len(simSlots) == 0 {
		// Multiple SIM slots not supported on this modem.
		var simSlot dbus.ObjectPath
		_ = getDBusProperty(c, modemObj, ModemPropertySIM, &simSlot)
		if simSlot.IsValid() {
			simSlots = append(simSlots, simSlot)
		}
	}
	for i, simPath := range simSlots {
		slot := uint8(i + 1)
		isPrimary := uint32(slot) == primarySIM
		simCard := types.WwanSimCard{
			SlotNumber:    slot,
			SlotActivated: isPrimary,
			State:         SIMStateAbsent,
		}
		if simPath.IsValid() && len(simPath) > 1 {
			simPaths = append(simPaths, string(simPath))
			// SIM card is present in this slot.
			// But note that even if SIM card is present but the slot is inactive,
			// ModemManager might report the card as absent, without providing any SIM
			// object path to work with.
			// On the other hand, with mbimcli we are able to distinguish between
			// missing and inactive SIM card:
			//     mbimcli -p -d /dev/cdc-wdm0 --ms-query-slot-info-status 0
			//     [/dev/cdc-wdm0] Slot info status retrieved:
			//	          Slot '0': 'state-off'
			// (as opposed to 'state-empty')
			// With qmicli we can also get this information:
			//     qmicli -p -d /dev/cdc-wdm0 --uim-get-slot-status
			//     [/dev/cdc-wdm0] 2 physical slots found:
			//       Physical slot 1:
			//          Card status: present
			//          Slot status: active
			//         Logical slot: 1
			//                ICCID: 894921003198100584
			//             Protocol: uicc
			//             Num apps: 0
			//             Is eUICC: no
			//       Physical slot 2:
			//          Card status: present
			//          Slot status: inactive
			//                ICCID: 89492029226029738490
			//             Protocol: uicc
			//             Num apps: 0
			//             Is eUICC: no
			// TODO: should we call mbimcli/qmicli ?
			simObj := c.conn.Object(MMInterface, simPath)
			_ = getDBusProperty(c, simObj, SIMPropertyActive, &simCard.SlotActivated)
			_ = getDBusProperty(c, simObj, SIMPropertyICCID, &simCard.ICCID)
			simCard.Name = simCard.ICCID
			_ = getDBusProperty(c, simObj, SIMPropertyIMSI, &simCard.IMSI)
			simCard.State = SIMStatePresent
			if !simCard.SlotActivated {
				simCard.State = SIMStateInactive
			}
			if isPrimary && modemState == ModemStateFailed {
				if failReason == ModemStateFailedReasonSimError {
					simCard.State = SIMStateError
				}
			}
		}
		status.SimCards = append(status.SimCards, simCard)
	}
	if len(status.SimCards) == 0 && modemState == ModemStateFailed &&
		failReason == ModemStateFailedReasonSimMissing {
		status.SimCards = append(status.SimCards,
			types.WwanSimCard{
				SlotNumber:    1,
				SlotActivated: true,
				State:         SIMStateAbsent,
			})
	}
	// Get RAT info.
	var currentRATs uint32
	_ = getDBusProperty(c, modemObj, ModemPropertyRATs, &currentRATs)
	if currentRATs&AccessTechnologies5G > 0 {
		status.CurrentRATs = append(status.CurrentRATs, types.WwanRAT5GNR)
	}
	if currentRATs&AccessTechnologies4G > 0 {
		status.CurrentRATs = append(status.CurrentRATs, types.WwanRATLTE)
	}
	if currentRATs&AccessTechnologies3G > 0 {
		status.CurrentRATs = append(status.CurrentRATs, types.WwanRATUMTS)
	}
	if currentRATs&AccessTechnologies2G > 0 {
		status.CurrentRATs = append(status.CurrentRATs, types.WwanRATGSM)
	}
	if currentRATs&^AccessTechnologiesSupported > 0 {
		c.log.Errorf("Modem %s is using unsupported RAT: %v",
			modemObj.Path(), currentRATs)
	}
	// Get info about the current provider.
	var regState uint32
	_ = getDBusProperty(c, modemObj, Modem3GPPPropertyRegistrationState, &regState)
	switch regState {
	case RegistrationStateDenied:
		status.CurrentProvider.Forbidden = true
	case RegistrationStateRoaming, RegistrationStateRoamingSmsOnly,
		RegistrationStateRoamingCsfbNotPreferred:
		status.CurrentProvider.Roaming = true
	}
	var plmn, providerName string
	_ = getDBusProperty(c, modemObj, Modem3GPPPropertyPLMN, &plmn)
	_ = getDBusProperty(c, modemObj, Modem3GPPPropertyProviderName, &providerName)
	if plmn != "" {
		status.CurrentProvider.CurrentServing = true
		status.CurrentProvider.PLMN = plmn
		status.CurrentProvider.Description = providerName
	}
	var bearers []dbus.ObjectPath
	_ = getDBusProperty(c, modemObj, ModemPropertyBearers, &bearers)
	for _, bearerPath := range bearers {
		if !bearerPath.IsValid() {
			continue
		}
		bearerPaths = append(bearerPaths, string(bearerPath))
		bearerObj := c.conn.Object(MMInterface, bearerPath)
		var connected bool
		_ = getDBusProperty(c, bearerObj, BearerPropertyConnected, &connected)
		if !connected {
			continue
		}
		var stats map[string]dbus.Variant
		_ = getDBusProperty(c, bearerObj, BearerPropertyStats, &stats)
		if value, ok := stats["start-date"].Value().(uint64); ok {
			status.ConnectedAt = value
		} else if value, ok := stats["duration"].Value().(uint32); ok {
			status.ConnectedAt = uint64(time.Now().Unix()) - uint64(value)
		}
		ipSettings, err := c.getBearerIPSettings(bearerObj)
		if err != nil {
			c.log.Error(err)
			break
		}
		status.IPSettings = ipSettings
		break
	}
	// Find out if location tracking is running for this modem.
	var locEnabled uint32
	_ = getDBusProperty(c, modemObj, LocationPropertyEnabled, &locEnabled)
	var locSignals bool
	_ = getDBusProperty(c, modemObj, LocationPropertySignals, &locSignals)
	status.LocationTracking = locSignals && (locEnabled&LocationSourceGpsRaw) > 0
	return
}

func (c *Client) getBearerIPSettings(bearerObj dbus.BusObject) (
	ipSettings types.WwanIPSettings, err error) {
	var ipConfig map[string]dbus.Variant
	var ipLen = net.IPv4len
	err = getDBusProperty(c, bearerObj, BearerPropertyIPv4Config, &ipConfig)
	if err != nil {
		// Try IPv6 config, but if it also fails, then return the error received
		// for the IPv4 config.
		err2 := getDBusProperty(c, bearerObj, BearerPropertyIPv6Config, &ipConfig)
		if err2 != nil {
			return
		}
		ipLen = net.IPv6len
	}
	if value, ok := ipConfig["method"].Value().(uint32); ok {
		if value != BearerIPMethodStatic {
			err = fmt.Errorf("connected to bearer %s using unsupported method: %d",
				bearerObj.Path(), value)
			return
		}
	}
	address, addressOK := ipConfig["address"].Value().(string)
	prefix, prefixOK := ipConfig["prefix"].Value().(uint32)
	if addressOK && prefixOK {
		mask := net.CIDRMask(int(prefix), ipLen*8)
		ip := net.ParseIP(address)
		if ip == nil {
			err = fmt.Errorf("failed to parse modem IP address: %v", address)
			return
		}
		ipSettings.Address = &net.IPNet{IP: ip, Mask: mask}
	}
	gateway, gatewayOK := ipConfig["gateway"].Value().(string)
	if gatewayOK {
		ip := net.ParseIP(gateway)
		if ip == nil {
			err = fmt.Errorf("failed to parse gateway IP address: %v", gateway)
			return
		}
		ipSettings.Gateway = ip
	}
	for _, dnsServerKey := range []string{"dns1", "dns2", "dns3"} {
		if dnsServer, ok := ipConfig[dnsServerKey].Value().(string); ok {
			ip := net.ParseIP(dnsServer)
			if ip == nil {
				err = fmt.Errorf("failed to parse DNS server IP address: %v", dnsServer)
				return
			}
			ipSettings.DNSServers = append(ipSettings.DNSServers, ip)
		}
	}
	if mtu, ok := ipConfig["mtu"].Value().(uint32); ok {
		ipSettings.MTU = uint16(mtu)
	}
	return
}

func (c *Client) getModemPhysAddrs(modemObj dbus.BusObject) (
	addrs types.WwanPhysAddrs, proto types.WwanCtrlProt, err error) {
	var primaryPort string
	// Find device file representing the modem (e.g. /dev/cdc-wdm0).
	err = getDBusProperty(c, modemObj, ModemPropertyPrimaryPort, &primaryPort)
	if err != nil {
		return addrs, proto, err
	}
	addrs.Dev = filepath.Join("/dev/", primaryPort)
	// Find path inside the /sys filesystem pointing to the USB port/interface
	// used to control the modem.
	devPathSymlink := filepath.Join("/sys/class/usbmisc", primaryPort, "device")
	devPath, err := filepath.EvalSymlinks(devPathSymlink)
	if err != nil {
		return addrs, proto, fmt.Errorf("failed to eval symlink %s: %w",
			devPathSymlink, err)
	}
	// Determine the network interface name.
	netPath := filepath.Join(devPath, "net")
	netInterfaces, err := os.ReadDir(netPath)
	if err != nil {
		return addrs, proto, fmt.Errorf("failed to read %s: %w", netPath, err)
	}
	if len(netInterfaces) > 0 {
		addrs.Interface = netInterfaces[0].Name()
	}
	// Determine USB address.
	parentPath := devPath
	subSysSymlink := filepath.Join(parentPath, "subsystem")
	for utils.FileExists(c.log, subSysSymlink) {
		subSysPath, err := filepath.EvalSymlinks(subSysSymlink)
		if err != nil {
			return addrs, proto, fmt.Errorf("failed to eval symlink %s: %w",
				subSysSymlink, err)
		}
		if filepath.Base(subSysPath) == "usb" {
			addrs.USB = strings.Split(filepath.Base(parentPath), ":")[0]
			addrs.USB = strings.ReplaceAll(addrs.USB, "-", ":")
			break
		}
		parentPath = filepath.Dir(parentPath)
		subSysSymlink = filepath.Join(parentPath, "subsystem")
	}
	// Determine PCI address.
	parentPath = devPath
	subSysSymlink = filepath.Join(parentPath, "subsystem")
	for utils.FileExists(c.log, subSysSymlink) {
		subSysPath, err := filepath.EvalSymlinks(subSysSymlink)
		if err != nil {
			return addrs, proto, fmt.Errorf(
				"failed to eval symlink %s: %w", subSysSymlink, err)
		}
		if filepath.Base(subSysPath) == "pci" {
			addrs.PCI = filepath.Base(parentPath)
			break
		}
		parentPath = filepath.Dir(parentPath)
		subSysSymlink = filepath.Join(parentPath, "subsystem")
	}
	// Find out which protocol is being used to control the modem.
	var ports [][]interface{}
	err = getDBusProperty(c, modemObj, ModemPropertyPorts, &ports)
	if err != nil {
		return addrs, proto, err
	}
	for _, port := range ports {
		if len(port) != 2 {
			continue
		}
		portName, ok := port[0].(string)
		if !ok {
			continue
		}
		portType, ok := port[1].(uint32)
		if !ok {
			continue
		}
		if portName == primaryPort {
			switch portType {
			case ModemPortTypeQMI:
				proto = types.WwanCtrlProtQMI
			case ModemPortTypeMBIM:
				proto = types.WwanCtrlProtMBIM
			}
			break
		}
	}
	return addrs, proto, nil
}

// Get modem metrics.
// Note that WwanNetworkMetrics.PhysAddrs is not filled in by this method.
func (c *Client) getModemMetrics(
	modemObj dbus.BusObject, rat types.WwanRAT) types.WwanNetworkMetrics {
	metrics := types.WwanNetworkMetrics{
		SignalInfo: types.WwanSignalInfo{
			RSSI: UnavailSignalMetric,
			RSRQ: UnavailSignalMetric,
			RSRP: UnavailSignalMetric,
			SNR:  UnavailSignalMetric,
		},
	}
	// Get signal info
	var signal map[string]dbus.Variant
	switch rat {
	case types.WwanRATGSM:
		_ = getDBusProperty(c, modemObj, SignalPropertyGSM, &signal)
	case types.WwanRATUMTS:
		_ = getDBusProperty(c, modemObj, SignalPropertyUMTS, &signal)
	case types.WwanRATLTE:
		_ = getDBusProperty(c, modemObj, SignalPropertyLTE, &signal)
	case types.WwanRAT5GNR:
		_ = getDBusProperty(c, modemObj, SignalProperty5G, &signal)
	}
	if value, ok := signal["rssi"].Value().(float64); ok {
		metrics.SignalInfo.RSSI = int32(value)
	}
	if value, ok := signal["rsrq"].Value().(float64); ok {
		metrics.SignalInfo.RSRQ = int32(value)
	}
	if value, ok := signal["rsrp"].Value().(float64); ok {
		metrics.SignalInfo.RSRP = int32(value)
	}
	if value, ok := signal["snr"].Value().(float64); ok {
		metrics.SignalInfo.SNR = int32(value)
	}
	// Get traffic stats.
	var bearers []dbus.ObjectPath
	_ = getDBusProperty(c, modemObj, ModemPropertyBearers, &bearers)
	for _, bearerPath := range bearers {
		if !bearerPath.IsValid() {
			continue
		}
		bearerObj := c.conn.Object(MMInterface, bearerPath)
		var connected bool
		_ = getDBusProperty(c, bearerObj, BearerPropertyConnected, &connected)
		if !connected {
			continue
		}
		var stats map[string]dbus.Variant
		_ = getDBusProperty(c, bearerObj, BearerPropertyStats, &stats)
		if value, ok := stats["rx-bytes"].Value().(uint64); ok {
			metrics.PacketStats.RxBytes = value
		}
		if value, ok := stats["tx-bytes"].Value().(uint64); ok {
			metrics.PacketStats.TxBytes = value
		}
		// TODO: Packet and drop counters are not available.
		//       Use qmicli/mbimcli to get them?
		break
	}
	return metrics
}

func (c *Client) getModemLocation(modemObj dbus.BusObject) types.WwanLocationInfo {
	location := types.WwanLocationInfo{
		Latitude:  UnavailLocAttribute,
		Longitude: UnavailLocAttribute,
		Altitude:  UnavailLocAttribute,
	}
	var locData map[uint32]dbus.Variant
	_ = getDBusProperty(c, modemObj, LocationProperty, &locData)
	if data, ok := locData[LocationSourceGpsRaw].Value().(map[string]dbus.Variant); ok {
		if value, ok := data["latitude"].Value().(float64); ok {
			location.Latitude = value
		}
		if value, ok := data["longitude"].Value().(float64); ok {
			location.Longitude = value
		}
		if value, ok := data["altitude"].Value().(float64); ok {
			location.Altitude = value
		}
		if value, ok := data["utc-time"].Value().(string); ok {
			timeInDay, err := time.Parse(LocationTimestampLayout, value)
			if err == nil {
				currentDate := time.Now().UTC()
				// Combine the date from currentDate with the parsed timeInDay.
				completeTime := time.Date(
					currentDate.Year(), currentDate.Month(), currentDate.Day(),
					timeInDay.Hour(), timeInDay.Minute(), timeInDay.Second(),
					timeInDay.Nanosecond(), time.UTC,
				)
				location.UTCTimestamp = uint64(completeTime.UnixMilli())
			} else {
				c.log.Errorf("Failed to parse time (%s) provided by GNSS module: %v",
					value, err)
			}
		}
	}
	return location
}

// PauseModemMonitoring pauses monitoring of modem state changes.
// Call returned function to resume monitoring and to obtain a checkpoint of the current
// modem state data, incl. metrics and location info, from which subsequent notifications
// will follow.
func (c *Client) PauseModemMonitoring() (resume func() (newInitialState []Modem)) {
	c.monitorCancel()
	c.monitorWG.Wait()
	return func() (modems []Modem) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.startModemMonitor()
		c.reloadModems()
		for _, modem := range c.modems {
			c.setupSignalPolling(dbus.ObjectPath(modem.Path))
			modems = append(modems, *modem)
		}
		return modems
	}
}

// LastSeenMM returns time when the ModemManager was last seen communicating
// over D-Bus.
func (c *Client) LastSeenMM() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.lastMsg
}

// GetMMVersion returns version of the ModemManager.
func (c *Client) GetMMVersion() (string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var version string
	err := getDBusProperty(c, c.mmObj, MMPropertyVersion, &version)
	return version, err
}

// SetMMLogLevel : set logging level of Modem Manager.
func (c *Client) SetMMLogLevel(level logrus.Level) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var mmLogLevel string
	switch level {
	case logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel:
		mmLogLevel = "ERR"
	case logrus.WarnLevel:
		mmLogLevel = "WARN"
	case logrus.InfoLevel:
		// Since 1.22, a new "MSG" (message) log verbosity level is introduced,
		// which is also the new default one if none explicitly defined. This level
		// takes the place of the old "INFO" level, as a level including the most
		// important messages that should be logged without needing to be warnings
		// or errors.
		mmLogLevel = "MSG"
	case logrus.DebugLevel:
		// Since 1.22, the new "INFO" level is more verbose than "MSG" but less
		// verbose than "DEBUG", and may be useful as default in systems where active
		// debugging of WWAN related issues is required. E.g. all user operations
		// triggered via DBus method calls are logged in "INFO" level.
		mmLogLevel = "INFO"
	case logrus.TraceLevel:
		// DEBUG is extremely verbose - every QMI/MBIM message is logged with multiple
		// lines, therefore we use it for the trace level only.
		mmLogLevel = "DEBUG"
	}
	return c.callDBusMethod(c.mmObj, MMMethodSetLogging, nil, mmLogLevel)
}

// EnableRadio enables radio transmission for the given modem.
func (c *Client) EnableRadio(modemPath string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
	var powerState uint32
	err := getDBusProperty(c, modemObj, ModemPropertyPowerState, &powerState)
	if err != nil {
		err = fmt.Errorf("failed to get the current power state: %w", err)
		c.log.Error(err)
		return err
	}
	if powerState != ModemPowerStateOn {
		// Modem must be disabled before we can make changes to the power state.
		// However, this is not always required. For example, if modem is in a failed
		// state, it might be possible to switch on the radio even if modem is enabled
		// (while attempt to disable it fails).
		err := c.callDBusMethod(modemObj, ModemMethodEnable, nil, false)
		if err != nil {
			c.log.Error(err)
		} else {
			err = c.waitForModemState(modemObj, ModemStateDisabled, modemDisableTimeout)
			if err != nil {
				c.log.Error(err)
			}
		}
		powerState = ModemPowerStateOn
		err = c.callDBusMethod(modemObj, ModemMethodSetPowerState, nil, powerState)
		if err != nil {
			return err
		}
	}
	var modemState int32
	_ = getDBusProperty(c, modemObj, ModemPropertyState, &modemState)
	if modemState == ModemStateDisabled {
		err := c.callDBusMethod(modemObj, ModemMethodEnable, nil, true)
		if err != nil {
			return err
		}
	}
	return nil
}

// DisableRadio disables radio transmission for the given modem.
func (c *Client) DisableRadio(modemPath string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
	// Modem should be disabled before turning down the power.
	// However, this is not always required. For example, if modem is in a failed
	// state, it might be possible to switch off the radio even if modem is enabled
	// (while attempt to disable it fails).
	err := c.callDBusMethod(modemObj, ModemMethodEnable, nil, false)
	if err != nil {
		c.log.Error(err)
	} else {
		err = c.waitForModemState(modemObj, ModemStateDisabled, modemDisableTimeout)
		if err != nil {
			c.log.Error(err)
		}
	}
	var powerState uint32
	err = getDBusProperty(c, modemObj, ModemPropertyPowerState, &powerState)
	if err != nil {
		err = fmt.Errorf("failed to get the current power state: %w", err)
		c.log.Error(err)
		return err
	}
	if powerState == ModemPowerStateOn {
		powerState = ModemPowerStateLow
		err = c.callDBusMethod(modemObj, ModemMethodSetPowerState, nil, powerState)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) waitForModemState(
	modemObj dbus.BusObject, requestedState int32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var modemState int32
	err := getDBusProperty(c, modemObj, ModemPropertyState, &modemState)
	if err != nil {
		err = fmt.Errorf("failed to get the current modem state: %w", err)
		c.log.Error(err)
		return err
	}
	for modemState != requestedState {
		if time.Now().After(deadline) {
			return fmt.Errorf("modem %s is not in the state %d (instead %d) even after %v",
				modemObj.Path(), requestedState, modemState, timeout)
		}
		time.Sleep(time.Second)
		err = getDBusProperty(c, modemObj, ModemPropertyState, &modemState)
		if err != nil {
			err = fmt.Errorf("failed to get the current modem state: %w", err)
			c.log.Error(err)
			return err
		}
	}
	return nil
}

// StartLocationTracking starts the process of periodically retrieving
// and publishing location information from a GNSS receiver of the given cellular modem.
func (c *Client) StartLocationTracking(modemPath string, publishInterval time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
	sources := uint32(LocationSourceGpsRaw)
	enableSignals := true
	err := c.callDBusMethod(modemObj, LocationMethodSetup, nil, sources, enableSignals)
	if err != nil {
		return err
	}
	refreshRate := uint32(publishInterval.Seconds())
	return c.callDBusMethod(modemObj, LocationMethodSetGpsRefreshRate, nil, refreshRate)
}

// StopLocationTracking stops the process of periodically retrieving
// and publishing location information from a GNSS receiver of the given cellular modem.
func (c *Client) StopLocationTracking(modemPath string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
	sources := uint32(LocationSourceNone)
	enableSignals := false
	return c.callDBusMethod(modemObj, LocationMethodSetup, nil, sources, enableSignals)
}

// Connect requests activation of a packet data connection.
// If successful, returns IP settings to be applied for the corresponding wwanX interface.
func (c *Client) Connect(
	modemPath string, args ConnectionArgs) (types.WwanIPSettings, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
	// Check if the modem is already connected.
	var modemState int32
	_ = getDBusProperty(c, modemObj, ModemPropertyState, &modemState)
	if modemState == ModemStateConnected {
		err := fmt.Errorf("modem %s is already connected", modemPath)
		return types.WwanIPSettings{}, err
	}
	// Activate the selected SIM slot if it is not already.
	if args.SIMSlot != 0 {
		var primarySIM uint32
		_ = getDBusProperty(c, modemObj, ModemPropertyPrimarySIMSlot, &primarySIM)
		if primarySIM == 0 {
			// Multiple ports not supported on this modem.
			primarySIM = 1
		}
		if args.SIMSlot != uint8(primarySIM) {
			c.log.Noticef("Changing primary SIM slot for modem %s from %d to %d",
				modemPath, primarySIM, args.SIMSlot)
			primarySIM = uint32(args.SIMSlot)
			err := c.callDBusMethod(modemObj, ModemMethodSetPrimarySimSlot, nil, primarySIM)
			if err != nil {
				return types.WwanIPSettings{}, err
			}
			err = c.waitForModemState(
				modemObj, ModemStateRegistered, changePrimarySIMTimeout)
			if err != nil {
				c.log.Error(err)
				// Continue, below we will try to change settings for the initial
				// EPS bearer.
			}
		}
	}
	// Set preferred access technologies and cellular network operators to use.
	// TODO: Not sure how to apply PreferredPLMNs with ModemManager.
	err := c.setPreferredRATs(modemObj, args.PreferredRATs)
	if err != nil {
		return types.WwanIPSettings{}, err
	}
	// Prepare connection settings.
	connProps := make(map[string]interface{})
	connProps["apn"] = args.APN
	var allowedAuth uint32
	switch args.AuthProtocol {
	case types.WwanAuthProtocolPAP:
		allowedAuth = BearerAllowedAuthPap
	case types.WwanAuthProtocolCHAP:
		allowedAuth = BearerAllowedAuthChap
	case types.WwanAuthProtocolPAPAndCHAP:
		allowedAuth = BearerAllowedAuthPap | BearerAllowedAuthChap
	default:
		allowedAuth = BearerAllowedAuthUnknown
	}
	connProps["allowed-auth"] = allowedAuth
	if args.DecryptedUsername != "" {
		connProps["user"] = args.DecryptedUsername
		//pragma: allowlist nextline secret
		connProps["password"] = args.DecryptedPassword
	}
	connProps["allow-roaming"] = !args.ForbidRoaming
	// Try to connect - first with IPv4-only IP-type.
	connProps["ip-type"] = uint32(BearerIPFamilyIPv4)
	ipSettings, err := c.runSimpleConnect(modemObj, connProps)
	if err == nil {
		return ipSettings, nil
	}
	origErr := err
	// Try to fix failing connection attempt.
	// First check if modem can even register.
	changed, err := c.reconfigureEpsBearerIfNotRegistered(modemObj, connProps)
	if changed && err == nil {
		// Retry connection attempt with the same parameters applied also for the initial
		// EPS bearer.
		ipSettings, err = c.runSimpleConnect(modemObj, connProps)
		if err == nil {
			return ipSettings, nil
		}
	}
	// Next try IPv4 and IPv6 dual-stack.
	connProps["ip-type"] = uint32(BearerIPFamilyIPv4v6)
	_, err = c.reconfigureEpsBearerIfNotRegistered(modemObj, connProps)
	if err == nil {
		ipSettings, err = c.runSimpleConnect(modemObj, connProps)
		if err == nil {
			return ipSettings, nil
		}
	}
	// Make the final attempt with IPv6 only.
	// This should be covered by IPv4v6 (network may return IPv6-only config
	// in that case), but we make this attempt still just in case.
	connProps["ip-type"] = uint32(BearerIPFamilyIPv6)
	_, err = c.reconfigureEpsBearerIfNotRegistered(modemObj, connProps)
	if err == nil {
		ipSettings, err = c.runSimpleConnect(modemObj, connProps)
		if err == nil {
			return ipSettings, nil
		}
	}
	// Revert back the modem profile back to the preferred IPv4-only mode.
	connProps["ip-type"] = uint32(BearerIPFamilyIPv4)
	_, _ = c.reconfigureEpsBearerIfNotRegistered(modemObj, connProps)
	// Return error from the first connection attempt (with IPv4-only).
	return ipSettings, origErr
}

func (c *Client) runSimpleConnect(modemObj dbus.BusObject,
	connProps map[string]interface{}) (types.WwanIPSettings, error) {
	var ipSettings types.WwanIPSettings
	var bearerPath dbus.ObjectPath
	modem := c.modems[string(modemObj.Path())]
	err := c.callDBusMethod(modemObj, SimpleMethodConnect, &bearerPath, connProps)
	if err != nil && strings.HasPrefix(err.Error(), "No such interface") && modem != nil {
		// Try to determine more useful connection failure reason.
		for _, simCard := range modem.Status.SimCards {
			if !simCard.SlotActivated {
				continue
			}
			switch simCard.State {
			case SIMStateAbsent:
				return ipSettings, errors.New("SIM card is absent")
			case SIMStateError:
				return ipSettings, errors.New("SIM card is in failed state")
			}
		}
		switch modem.Status.Module.OpMode {
		case types.WwanOpModeUnspecified, types.WwanOpModeOnline,
			types.WwanOpModeConnected:
			break
		default:
			return ipSettings, fmt.Errorf("modem is not online, current state: %v",
				modem.Status.Module.OpMode)
		}
	}
	if err == nil {
		bearerObj := c.conn.Object(MMInterface, bearerPath)
		ipSettings, err = c.getBearerIPSettings(bearerObj)
	}
	return ipSettings, err
}

func (c *Client) reconfigureEpsBearerIfNotRegistered(modemObj dbus.BusObject,
	newSettings map[string]interface{}) (changedConfig bool, err error) {
	var modemState int32
	_ = getDBusProperty(c, modemObj, ModemPropertyState, &modemState)
	if modemState >= ModemStateRegistered {
		return false, nil
	}
	var currentSettings map[string]dbus.Variant
	_ = getDBusProperty(c, modemObj, Modem3GPPPropertyInitialEpsBearer, &currentSettings)
	c.log.Warnf("Modem %s is failing to register, "+
		"trying to apply settings %+v for the initial EPS bearer (previously: %+v)",
		modemObj.Path(), newSettings, currentSettings)
	err = c.callDBusMethod(modemObj, Modem3GPPMethodSetInitialEpsBearer, nil, newSettings)
	if err != nil {
		err = fmt.Errorf(
			"failed to change initial EPS bearer settings for modem %s: %w",
			modemObj.Path(), err)
		c.log.Error(err)
		return false, err
	}
	return true, c.waitForModemState(
		modemObj, ModemStateRegistered, changeInitEPSBearerTimeout)
}

func (c *Client) setPreferredRATs(modemObj dbus.BusObject,
	preferredRATs []types.WwanRAT) error {
	var prefModes []uint32
	for _, rat := range preferredRATs {
		var mode uint32
		switch rat {
		case types.WwanRATGSM:
			mode = ModemMode2G
		case types.WwanRATUMTS:
			mode = ModemMode3G
		case types.WwanRATLTE:
			mode = ModemMode4G
		case types.WwanRAT5GNR:
			mode = ModemMode5G
		default:
			continue
		}
		prefModes = append(prefModes, mode)
	}
	if len(prefModes) == 0 {
		return nil
	}
	var supModes [][]interface{}
	err := getDBusProperty(c, modemObj, ModemPropertySupportedModes, &supModes)
	if len(supModes) == 0 {
		c.log.Warnf("Modem %s does not report any supported modes (2G/3G/...), "+
			"err: %v", modemObj.Path(), err)
		return nil
	}
	// Rate supported modes based on how close they are to preferred modes.
	rating := make([]int, len(supModes))
	for i, supMode := range supModes {
		if len(supMode) != 2 {
			c.log.Warnf("Invalid supported mode returned for modem %s: %+v",
				modemObj.Path(), supMode)
			rating[i] = math.MinInt
			continue
		}
		allowedSupModes, ok1 := supMode[0].(uint32)
		prefSupMode, ok2 := supMode[1].(uint32)
		if !ok1 || !ok2 {
			c.log.Warnf("Invalid supported mode returned for modem %s: %+v",
				modemObj.Path(), supMode)
			rating[i] = math.MinInt
			continue
		}
		for j, prefMode := range prefModes {
			// Order of PreferredRATs matter.
			// The first is the most preferred, second should be tried next, etc.
			var weight int
			switch j {
			case 0:
				weight = 4
			case 1:
				weight = 2
			default:
				weight = 1
			}
			if allowedSupModes&prefMode > 0 {
				rating[i] += weight
			}
			if prefSupMode == prefMode {
				rating[i] += weight
			}
		}
		for _, mode := range allModemModes {
			if !generics.ContainsItem(prefModes, mode) {
				if allowedSupModes&mode > 0 {
					// This allowed mode should not be used.
					rating[i] -= 10
				}
			}
		}
	}
	// Find the best rated supported mode.
	bestMode := 0
	for i := 1; i < len(supModes); i++ {
		if rating[i] > rating[bestMode] {
			bestMode = i
		}
	}
	if rating[bestMode] == math.MinInt {
		c.log.Warnf("All supported modes returned for modem %s are invalid",
			modemObj.Path())
		return nil
	}
	mode := struct {
		AllowedModes uint32
		PrefMode     uint32
	}{
		AllowedModes: supModes[bestMode][0].(uint32),
		PrefMode:     supModes[bestMode][1].(uint32),
	}
	c.log.Noticef("Setting mode %v for modem %s", mode, modemObj.Path())
	return c.callDBusMethod(modemObj, ModemMethodSetCurrentModes, nil, mode)
}

// Disconnect terminates the modem connection.
// If the modem is not connected, function does nothing and returns nil.
func (c *Client) Disconnect(modemPath string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
	anyBearer := dbus.ObjectPath("/")
	return c.callDBusMethod(modemObj, SimpleMethodDisconnect, nil, anyBearer)
}

// ScanVisibleProviders runs a fairly long operation (takes around 1 minute!)
// of scanning all visible cellular network providers.
func (c *Client) ScanVisibleProviders(modemPath string) ([]types.WwanProvider, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	startTime := time.Now()
	c.log.Noticef("Started scan of visible providers for modem %s", modemPath)
	defer func() {
		c.log.Noticef("Finished scan of visible providers for modem %s, took: %v",
			modemPath, time.Since(startTime))
	}()
	modemObj := c.conn.Object(MMInterface, dbus.ObjectPath(modemPath))
	var scanRaw interface{}
	err := c.callDBusMethodWithTimeout(modemObj, Modem3GPPMethodScan,
		scanProvidersTimeout, &scanRaw)
	if err != nil {
		return nil, err
	}
	scanData, ok := scanRaw.([]map[string]dbus.Variant)
	if !ok {
		return nil, fmt.Errorf("unexpected type of scan output: %T", scanRaw)
	}
	var providers []types.WwanProvider
	for _, providerScan := range scanData {
		var provider types.WwanProvider
		if value, ok := providerScan["operator-code"].Value().(string); ok {
			provider.PLMN = value
		} else {
			continue
		}
		if value, ok := providerScan["operator-long"].Value().(string); ok {
			provider.Description = value
		} else if value, ok = providerScan["operator-short"].Value().(string); ok {
			provider.Description = value
		}
		if value, ok := providerScan["status"].Value().(uint32); ok {
			// Note that status is usually unknown.
			switch value {
			case NetworkAvailabilityCurrent:
				provider.CurrentServing = true
			case NetworkAvailabilityForbidden:
				provider.Forbidden = true
			}
			// TODO: how to determine if connection would require roaming?
		}
		providers = append(providers, provider)
	}
	return providers, nil
}

// Call ModemManager method over dbus with the default timeout (dbusCallTimeout).
func (c *Client) callDBusMethod(obj dbus.BusObject, method string,
	outArg interface{}, inArgs ...interface{}) error {
	return c.callDBusMethodWithTimeout(obj, method, dbusCallTimeout, outArg, inArgs...)
}

func (c *Client) callDBusMethodWithTimeout(obj dbus.BusObject, method string,
	timeout time.Duration, outArg interface{}, inArgs ...interface{}) error {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if outArg != nil {
		err = obj.CallWithContext(ctx, method, 0, inArgs...).Store(outArg)
		c.log.Functionf("Executed DBus method %s, in args: %+v, out arg: %+v, err: %v",
			method, inArgs, outArg, err)
	} else {
		err = obj.CallWithContext(ctx, method, 0, inArgs...).Err
		c.log.Functionf("Executed DBus method %s, in args: %+v, err: %v",
			method, inArgs, err)
	}
	if err == nil {
		c.lastMsg = time.Now()
	}
	return err
}

func getDBusProperty[Type any](client *Client, obj dbus.BusObject,
	path string, dst *Type) error {
	variant, err := obj.GetProperty(path)
	if err != nil {
		err := fmt.Errorf("failed to get property %s: %w", path, err)
		client.log.Error(err)
		return err
	}
	client.lastMsg = time.Now()
	value, ok := variant.Value().(Type)
	if !ok {
		err := fmt.Errorf("unexpected value type for property %s: %T",
			path, variant.Value())
		client.log.Error(err)
		return err
	}
	*dst = value
	return nil
}
