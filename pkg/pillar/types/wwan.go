// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types defined for interaction between pillar and the wwan microservice.

package types

import (
	"fmt"
	"net"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

// WwanConfig is published by nim and consumed by the wwan service.
type WwanConfig struct {
	// Key of the DevicePortConfig from which WwanConfig was generated.
	DPCKey string
	// Timestamp of the DevicePortConfig from which WwanConfig was generated.
	DPCTimestamp time.Time
	// Timestamp of the RadioSilence config applied into this WwanConfig.
	RSConfigTimestamp time.Time
	// Radio silence is the act of disabling all radio transmission
	// for safety or security reasons
	RadioSilence bool
	// One entry for every cellular modem.
	Networks []WwanNetworkConfig
}

// GetNetworkConfig returns pointer to the network config corresponding to the modem
// with the given logical label.
func (wc WwanConfig) GetNetworkConfig(logicalLabel string) *WwanNetworkConfig {
	for i := range wc.Networks {
		if wc.Networks[i].LogicalLabel == logicalLabel {
			return &wc.Networks[i]
		}
	}
	return nil
}

// Equal compares two instances of WwanConfig for equality.
func (wc WwanConfig) Equal(wc2 WwanConfig) bool {
	if wc.DPCKey != wc2.DPCKey ||
		!wc.DPCTimestamp.Equal(wc2.DPCTimestamp) ||
		!wc.RSConfigTimestamp.Equal(wc2.RSConfigTimestamp) ||
		wc.RadioSilence != wc2.RadioSilence {
		return false
	}
	return generics.EqualSetsFn(wc.Networks, wc2.Networks,
		func(wnc1, wnc2 WwanNetworkConfig) bool {
			return wnc1.Equal(wnc2)
		})
}

// Key is used for pubsub
func (wc WwanConfig) Key() string {
	return "global"
}

// LogCreate :
func (wc WwanConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.WwanConfigLogType, "",
		nilUUID, wc.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Wwan config create")
}

// LogModify :
func (wc WwanConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.WwanConfigLogType, "",
		nilUUID, wc.LogKey())
	oldWc, ok := old.(WwanConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object passed is not of WwanConfig type")
	}
	logObject.CloneAndAddField("diff", cmp.Diff(oldWc, wc)).
		Metricf("Wwan config modify")
}

// LogDelete :
func (wc WwanConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.WwanConfigLogType, "",
		nilUUID, wc.LogKey())
	logObject.Metricf("Wwan config delete")
	base.DeleteLogObject(logBase, wc.LogKey())
}

// LogKey :
func (wc WwanConfig) LogKey() string {
	return string(base.WwanConfigLogType) + "-" + wc.Key()
}

// WwanNetworkConfig contains configuration for a single cellular network.
// In case there are multiple SIM cards/slots in the modem, WwanNetworkConfig
// contains config only for the activated one.
type WwanNetworkConfig struct {
	// Logical label in PhysicalIO.
	LogicalLabel string
	// Physical address of the cellular modem.
	PhysAddrs WwanPhysAddrs
	// Configuration of the activated Access point.
	AccessPoint CellularAccessPoint
	// Proxies configured for the cellular network.
	Proxies []ProxyEntry
	// Probe used to detect broken connection.
	Probe WwanProbe
	// Some LTE modems have GNSS receiver integrated and can be used
	// for device location tracking.
	// Enable this option to have location info periodically obtained
	// from this modem and published by wwan microservice via topic WwanLocationInfo.
	LocationTracking bool
}

// WwanAuthProtocol : authentication protocol used by cellular network.
type WwanAuthProtocol string

const (
	// WwanAuthProtocolNone : no authentication.
	WwanAuthProtocolNone WwanAuthProtocol = ""
	// WwanAuthProtocolPAP : Password Authentication Protocol.
	WwanAuthProtocolPAP WwanAuthProtocol = "pap"
	// WwanAuthProtocolCHAP : Challenge-Handshake Authentication Protocol.
	WwanAuthProtocolCHAP WwanAuthProtocol = "chap"
	// WwanAuthProtocolPAPAndCHAP : Both PAP and CHAP.
	WwanAuthProtocolPAPAndCHAP WwanAuthProtocol = "pap-and-chap"
)

// WwanRAT : Radio Access Technology.
type WwanRAT string

const (
	// WwanRATUnspecified : select RAT automatically.
	WwanRATUnspecified WwanRAT = ""
	// WwanRATGSM : Global System for Mobile Communications (2G).
	WwanRATGSM WwanRAT = "gsm"
	// WwanRATUMTS : Universal Mobile Telecommunications System (3G).
	WwanRATUMTS WwanRAT = "umts"
	// WwanRATLTE : Long-Term Evolution (4G).
	WwanRATLTE WwanRAT = "lte"
	// WwanRAT5GNR : 5th Generation New Radio (5G).
	WwanRAT5GNR WwanRAT = "5gnr"
)

// WwanProbe : cellular connectivity verification probe.
type WwanProbe struct {
	Disable bool
	// IP/FQDN address to periodically probe to determine connection status.
	Address string
}

// Equal compares two instances of WwanNetworkConfig for equality.
func (wnc WwanNetworkConfig) Equal(wnc2 WwanNetworkConfig) bool {
	if wnc.LogicalLabel != wnc2.LogicalLabel ||
		wnc.PhysAddrs != wnc2.PhysAddrs {
		return false
	}
	if !wnc.AccessPoint.Equal(wnc2.AccessPoint) {
		return false
	}
	if !generics.EqualLists(wnc.Proxies, wnc2.Proxies) {
		return false
	}
	if wnc.Probe != wnc2.Probe {
		return false
	}
	if wnc.LocationTracking != wnc2.LocationTracking {
		return false
	}
	return true
}

// WwanPhysAddrs is a physical address of a cellular modem.
// Not all fields have to be defined. Empty WwanPhysAddrs will match the first modem found in sysfs.
// With multiple LTE modems the USB address is the most unambiguous and reliable.
type WwanPhysAddrs struct {
	// Interface name.
	// For example: wwan0
	Interface string
	// USB address in the format "<BUS>:[<PORT>]", with nested ports separated by dots.
	// For example: 1:2.3
	USB string
	// PCI address in the long format.
	// For example: 0000:00:15.0
	PCI string
	// Dev : device file representing the modem (e.g. /dev/cdc-wdm0).
	// This address is only published as part of the wwan status
	// and can't be configured from the controller.
	Dev string
}

// WwanStatus is published by the wwan service and consumed by nim, zedagent and zedrouter.
type WwanStatus struct {
	// DPCKey is just copied from the last applied WwanConfig.
	DPCKey string
	// DPCTimestamp is just copied from the last applied WwanConfig.
	DPCTimestamp time.Time
	// RSConfigTimestamp is just copied from the last applied WwanConfig.
	RSConfigTimestamp time.Time
	// One entry for every cellular modem.
	Networks []WwanNetworkStatus
}

// Equal compares two instances of WwanStatus for equality.
func (ws WwanStatus) Equal(ws2 WwanStatus) bool {
	if ws.DPCKey != ws2.DPCKey ||
		!ws.DPCTimestamp.Equal(ws2.DPCTimestamp) ||
		!ws.RSConfigTimestamp.Equal(ws2.RSConfigTimestamp) {
		return false
	}
	return generics.EqualSetsFn(ws.Networks, ws2.Networks,
		func(wns1, wns2 WwanNetworkStatus) bool {
			return wns1.Equal(wns2)
		})
}

// GetNetworkStatus returns pointer to the network status corresponding to the modem
// with the given logical label.
func (ws WwanStatus) GetNetworkStatus(logicalLabel string) *WwanNetworkStatus {
	for i := range ws.Networks {
		if ws.Networks[i].LogicalLabel == logicalLabel {
			return &ws.Networks[i]
		}
	}
	return nil
}

// DoSanitize fills in logical names for cellular modules and SIM cards.
func (ws WwanStatus) DoSanitize() {
	uniqueModel := func(model string) bool {
		var counter int
		for i := range ws.Networks {
			if ws.Networks[i].Module.Model == model {
				counter++
			}
		}
		return counter == 1
	}
	for i := range ws.Networks {
		network := &ws.Networks[i]
		if network.Module.Name == "" {
			switch {
			case network.Module.IMEI != "":
				network.Module.Name = network.Module.IMEI
			case uniqueModel(network.Module.Model):
				network.Module.Name = network.Module.Model
			default:
				network.Module.Name = network.PhysAddrs.USB
			}
		}
		for j := range network.SimCards {
			simCard := &network.SimCards[j]
			if simCard.Name == "" {
				if simCard.ICCID != "" {
					simCard.Name = simCard.ICCID
				} else {
					simCard.Name = fmt.Sprintf("%s-SIM%d",
						network.Module.Name, simCard.SlotNumber)
				}
			}
		}
	}
}

// Key is used for pubsub
func (ws WwanStatus) Key() string {
	return "global"
}

// LogCreate :
func (ws WwanStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.WwanStatusLogType, "",
		nilUUID, ws.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Wwan status create")
}

// LogModify :
func (ws WwanStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.WwanStatusLogType, "",
		nilUUID, ws.LogKey())
	oldWs, ok := old.(WwanStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object passed is not of WwanStatus type")
	}
	logObject.CloneAndAddField("diff", cmp.Diff(oldWs, ws)).
		Metricf("Wwan status modify")
}

// LogDelete :
func (ws WwanStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.WwanStatusLogType, "",
		nilUUID, ws.LogKey())
	logObject.Metricf("Wwan status delete")
	base.DeleteLogObject(logBase, ws.LogKey())
}

// LogKey :
func (ws WwanStatus) LogKey() string {
	return string(base.WwanStatusLogType) + "-" + ws.Key()
}

// WwanNetworkStatus contains status information for a single cellular network
// (i.e. one modem but possibly multiple SIM slots/cards).
type WwanNetworkStatus struct {
	// Logical label of the cellular modem in PhysicalIO.
	// Can be empty if this device is not configured by the controller
	// (and hence logical label does not exist).
	LogicalLabel string
	PhysAddrs    WwanPhysAddrs
	Module       WwanCellModule
	// One entry for every SIM slot (incl. those without SIM card).
	SimCards []WwanSimCard
	// Non-empty if the wwan microservice failed to apply config submitted by NIM.
	ConfigError string
	// Error message from the last connectivity probing.
	ProbeError string
	// Network where the modem is currently registered.
	CurrentProvider WwanProvider
	// All networks that the modem is able to detect.
	// This will include the currently used provider as well as other visible networks.
	VisibleProviders []WwanProvider
	// The list of Radio Access Technologies (RATs) currently used for registering/connecting
	// to the network (typically just one).
	CurrentRATs []WwanRAT
	// Unix timestamp in seconds made when the current connection was established.
	// Zero value if the modem is not connected.
	ConnectedAt uint64
	// IP settings received from the network when connection is established.
	IPSettings WwanIPSettings
	// True if location tracking is successfully running.
	LocationTracking bool
}

// WwanCellModule contains cellular module specs.
type WwanCellModule struct {
	// Name is a module identifier. For example IMEI if available.
	// Guaranteed to be unique among all modems attached to the edge node.
	Name string
	// International Mobile Equipment Identity.
	IMEI         string
	Model        string
	Manufacturer string
	// Firmware version identifier.
	Revision string
	// QMI or MBIM.
	ControlProtocol WwanCtrlProt
	OpMode          WwanOpMode
}

// WwanSimCard describes either empty SIM slot or a slot with a SIM card inserted.
type WwanSimCard struct {
	// Name is a SIM card/slot identifier.
	// Guaranteed to be unique across all modems and their SIM slots attached
	// to the edge node.
	Name string
	// SIM slot number which this WwanSimCard instance describes.
	SlotNumber uint8
	// True if this SIM slot is activated, i.e. the inserted SIM card (if any) can be used
	// to connect to a cellular network.
	SlotActivated bool
	// Integrated Circuit Card Identifier.
	// Empty if no SIM card is inserted into the slot or if the SIM card is not recognized.
	ICCID string
	// International Mobile Subscriber Identity.
	// Empty if no SIM card is inserted into the slot or if the SIM card is not recognized.
	IMSI string
	// Type of the SIM card.
	Type SimType
	// The current state of the SIM card (absent, initialized, not recognized, etc.).
	// This state is not modeled using enum because the set of possible values differs
	// between QMI and MBIM protocols (used to control cellular modules) and there is
	// no 1:1 mapping between them.
	State string
}

// SimType : type of the SIM card.
type SimType int32

// The values here should be same as the ones defined in info.proto of EVE API.
const (
	// SimTypeUnspecified : SIM card type is not specified/known.
	SimTypeUnspecified SimType = iota
	// SimTypePhysical : physical SIM card.
	SimTypePhysical
	// SimTypeEmbedded : embedded SIM card (eSIM).
	SimTypeEmbedded
)

// WwanProvider contains information about a cellular connectivity provider.
type WwanProvider struct {
	// Public Land Mobile Network identifier.
	PLMN string
	// Human-readable label identifying the provider.
	Description string
	// True if this is the provider currently being used.
	CurrentServing bool
	// True if data roaming is ON.
	Roaming bool
	// True if this provider is forbidden by SIM card config.
	Forbidden bool
}

// WwanOpMode : wwan operating mode
type WwanOpMode string

const (
	// WwanOpModeUnspecified : operating mode is not specified
	WwanOpModeUnspecified WwanOpMode = ""
	// WwanOpModeOnline : modem is online but not connected
	WwanOpModeOnline WwanOpMode = "online"
	// WwanOpModeConnected : modem is online and connected
	WwanOpModeConnected WwanOpMode = "online-and-connected"
	// WwanOpModeRadioOff : modem has disabled radio transmission
	WwanOpModeRadioOff WwanOpMode = "radio-off"
	// WwanOpModeOffline : modem is offline
	WwanOpModeOffline WwanOpMode = "offline"
	// WwanOpModeUnrecognized : unrecognized operating mode
	WwanOpModeUnrecognized WwanOpMode = "unrecognized"
)

// WwanCtrlProt : wwan control protocol
type WwanCtrlProt string

const (
	// WwanCtrlProtUnspecified : control protocol is not specified
	WwanCtrlProtUnspecified WwanCtrlProt = ""
	// WwanCtrlProtQMI : modem is controlled using the QMI protocol
	WwanCtrlProtQMI WwanCtrlProt = "qmi"
	// WwanCtrlProtMBIM : modem is controlled using the MBIM protocol
	WwanCtrlProtMBIM WwanCtrlProt = "mbim"
)

// WwanIPSettings : IP settings received from the connected network.
type WwanIPSettings struct {
	Address    *net.IPNet
	Gateway    net.IP
	DNSServers []net.IP
	MTU        uint16
}

// Equal compares two instances of WwanIPSettings for equality.
func (wips WwanIPSettings) Equal(wips2 WwanIPSettings) bool {
	return netutils.EqualIPNets(wips.Address, wips2.Address) &&
		netutils.EqualIPs(wips.Gateway, wips2.Gateway) &&
		generics.EqualSetsFn(wips.DNSServers, wips2.DNSServers, netutils.EqualIPs) &&
		wips.MTU == wips2.MTU
}

// Equal compares two instances of WwanNetworkStatus for equality.
func (wns WwanNetworkStatus) Equal(wns2 WwanNetworkStatus) bool {
	if wns.LogicalLabel != wns2.LogicalLabel ||
		wns.PhysAddrs != wns2.PhysAddrs {
		return false
	}
	if wns.Module != wns2.Module {
		return false
	}
	if !generics.EqualSets(wns.SimCards, wns2.SimCards) {
		return false
	}
	if wns.ConfigError != wns2.ConfigError ||
		wns.ProbeError != wns2.ProbeError {
		return false
	}
	if wns.CurrentProvider != wns2.CurrentProvider ||
		!generics.EqualSets(wns.VisibleProviders, wns2.VisibleProviders) {
		return false
	}
	if !generics.EqualSets(wns.CurrentRATs, wns2.CurrentRATs) {
		return false
	}
	if wns.ConnectedAt != wns2.ConnectedAt ||
		!wns.IPSettings.Equal(wns2.IPSettings) ||
		wns.LocationTracking != wns2.LocationTracking {
		return false
	}
	return true
}

// WwanMetrics is published by the wwan service.
type WwanMetrics struct {
	Networks []WwanNetworkMetrics
}

// GetNetworkMetrics returns pointer to the network metrics corresponding to the modem
// with the given logical label.
func (wm WwanMetrics) GetNetworkMetrics(logicalLabel string) *WwanNetworkMetrics {
	for i := range wm.Networks {
		if wm.Networks[i].LogicalLabel == logicalLabel {
			return &wm.Networks[i]
		}
	}
	return nil
}

// Equal compares two instances of WwanMetrics for equality.
func (wm WwanMetrics) Equal(wm2 WwanMetrics) bool {
	return generics.EqualSets(wm.Networks, wm2.Networks)
}

// LookupNetworkMetrics returns metrics corresponding to the given cellular network.
func (wm WwanMetrics) LookupNetworkMetrics(logicalLabel string) (WwanNetworkMetrics, bool) {
	for _, metrics := range wm.Networks {
		if logicalLabel == metrics.LogicalLabel {
			return metrics, true
		}
	}
	return WwanNetworkMetrics{}, false
}

// Key is used for pubsub
func (wm WwanMetrics) Key() string {
	return "global"
}

// LogCreate :
func (wm WwanMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.WwanMetricsLogType, "",
		nilUUID, wm.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Wwan metrics create")
}

// LogModify :
func (wm WwanMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.WwanMetricsLogType, "",
		nilUUID, wm.LogKey())

	oldWm, ok := old.(WwanMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object passed is not of WwanMetrics type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldWm, wm)).
		Metricf("Wwan metrics modify")
}

// LogDelete :
func (wm WwanMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.WwanMetricsLogType, "",
		nilUUID, wm.LogKey())
	logObject.Metricf("Wwan metrics delete")

	base.DeleteLogObject(logBase, wm.LogKey())
}

// LogKey :
func (wm WwanMetrics) LogKey() string {
	return string(base.WwanMetricsLogType) + "-" + wm.Key()
}

// WwanNetworkMetrics contains metrics for a single cellular network.
type WwanNetworkMetrics struct {
	// Logical label of the cellular modem in PhysicalIO.
	// Can be empty if this device is not configured by the controller
	// (and hence logical label does not exist).
	LogicalLabel string
	PhysAddrs    WwanPhysAddrs
	PacketStats  WwanPacketStats
	SignalInfo   WwanSignalInfo
}

// WwanPacketStats contains packet statistics recorded by a cellular modem.
type WwanPacketStats struct {
	RxBytes   uint64
	RxPackets uint64
	RxDrops   uint64
	TxBytes   uint64
	TxPackets uint64
	TxDrops   uint64
}

// WwanSignalInfo contains cellular signal strength information.
// The maximum value of int32 (0x7FFFFFFF) represents unspecified/unavailable metric.
type WwanSignalInfo struct {
	// Received signal strength indicator (RSSI) measured in dBm (decibel-milliwatts).
	RSSI int32
	// Reference Signal Received Quality (RSRQ) measured in dB (decibels).
	RSRQ int32
	// Reference Signal Receive Power (RSRP) measured in dBm (decibel-milliwatts).
	RSRP int32
	// Signal-to-Noise Ratio (SNR) measured in dB (decibels).
	SNR int32
}

// WwanLocationInfo contains device location information obtained from a GNSS
// receiver integrated into an LTE modem.
type WwanLocationInfo struct {
	// Logical label of the device used to obtain this location information.
	LogicalLabel string
	// Latitude in the Decimal degrees (DD) notation.
	// Valid values are in the range <-90, 90>. Anything outside of this range
	// should be treated as an unavailable value.
	// Note that wwan microservice uses -32768 specifically when latitude is not known.
	Latitude float64
	// Longitude in the Decimal degrees (DD) notation.
	// Valid values are in the range <-180, 180>. Anything outside of this range
	// should be treated as an unavailable value.
	// Note that wwan microservice uses -32768 specifically when longitude is not known.
	Longitude float64
	// Altitude w.r.t. mean sea level in meters.
	// Negative value of -32768 is returned when altitude is not known.
	Altitude float64
	// Circular horizontal position uncertainty in meters.
	// Negative values are not valid and represent unavailable uncertainty.
	// Note that wwan microservice uses -32768 specifically when horizontal
	// uncertainty is not known.
	HorizontalUncertainty float32
	// Reliability of the provided information for latitude and longitude.
	HorizontalReliability LocReliability
	// Vertical position uncertainty in meters.
	// Negative values are not valid and represent unavailable uncertainty.
	// Note that wwan microservice uses -32768 specifically when vertical
	// uncertainty is not known.
	VerticalUncertainty float32
	// Reliability of the provided information for altitude.
	VerticalReliability LocReliability
	// Unix timestamp in milliseconds.
	// Zero value represents unavailable UTC timestamp.
	UTCTimestamp uint64
}

// Key is used for pubsub
func (wli WwanLocationInfo) Key() string {
	return "global"
}

// LogCreate :
func (wli WwanLocationInfo) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.WwanLocationInfoLogType, "",
		nilUUID, wli.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Wwan location info create")
}

// LogModify :
func (wli WwanLocationInfo) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.WwanLocationInfoLogType, "",
		nilUUID, wli.LogKey())

	oldWli, ok := old.(WwanLocationInfo)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object passed is not of WwanLocationInfo type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldWli, wli)).
		Metricf("Wwan location info modify")
}

// LogDelete :
func (wli WwanLocationInfo) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.WwanLocationInfoLogType, "",
		nilUUID, wli.LogKey())
	logObject.Metricf("Wwan location info delete")
	base.DeleteLogObject(logBase, wli.LogKey())
}

// LogKey :
func (wli WwanLocationInfo) LogKey() string {
	return string(base.WwanLocationInfoLogType) + "-" + wli.Key()
}

// LocReliability : reliability of location information.
type LocReliability string

const (
	// LocReliabilityUnspecified : reliability is not specified
	LocReliabilityUnspecified LocReliability = "not-set"
	// LocReliabilityVeryLow : very low reliability
	LocReliabilityVeryLow LocReliability = "very-low"
	// LocReliabilityLow : low reliability
	LocReliabilityLow LocReliability = "low"
	// LocReliabilityMedium : medium reliability
	LocReliabilityMedium LocReliability = "medium"
	// LocReliabilityHigh : high reliability
	LocReliabilityHigh LocReliability = "high"
)
