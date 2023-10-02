// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types defined for interaction between pillar and the wwan microservice.

//nolint:tagliatelle
package types

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// WwanConfig is published by nim and consumed by the wwan service.
type WwanConfig struct {
	RadioSilence bool `json:"radio-silence"`
	// Enable verbose logging in the wwan microservice.
	Verbose bool `json:"verbose"`
	// Enable to periodically obtain the set of visible network providers (for each modem)
	// and publish them under WwanNetworkStatus.VisibleProviders.
	// Use with caution because this operation may take quite some time (around 2 minutes)
	// and makes modem unmanageable for the time being. Therefore, even if enabled,
	// the period to query visible providers is quite long - 1 hour.
	// Note that WwanNetworkStatus always provides info about the currently used
	// network provider (CurrentProvider). Getting this info is not expensive so if you
	// do not need info about other providers in the area, leave this disabled.
	QueryVisibleProviders bool                `json:"query-visible-providers"`
	Networks              []WwanNetworkConfig `json:"networks"`
}

// Equal compares two instances of WwanConfig for equality.
func (wc WwanConfig) Equal(wc2 WwanConfig) bool {
	if wc.RadioSilence != wc2.RadioSilence ||
		wc.Verbose != wc2.Verbose ||
		wc.QueryVisibleProviders != wc2.QueryVisibleProviders {
		return false
	}
	return generics.EqualSetsFn(wc.Networks, wc2.Networks,
		func(wnc1, wnc2 WwanNetworkConfig) bool {
			return wnc1.Equal(wnc2)
		})
}

// WwanNetworkConfig contains configuration for a single cellular network.
// In case there are multiple SIM cards/slots in the modem, WwanNetworkConfig
// contains config only for the activated one.
type WwanNetworkConfig struct {
	// Logical label in PhysicalIO.
	LogicalLabel string        `json:"logical-label"`
	PhysAddrs    WwanPhysAddrs `json:"physical-addrs"`
	// Index of the SIM slot to activate and use for the connection.
	// Note that slots are indexed incrementally, starting with 1.
	// Zero value means that the slot is undefined and EVE will not change
	// SIM slot activation settings, meaning that the currently activated
	// slot will remain being used.
	SIMSlot uint8 `json:"sim-slot"`
	// Access Point Network to connect into.
	// By default, it is "internet".
	APN string `json:"apn"`
	// Some cellular networks require authentication.
	AuthProtocol WwanAuthProtocol `json:"auth-protocol"`
	Username     string           `json:"username,omitempty"`
	// User password (if provided) is encrypted using AES-256-GCM with key derived
	// by the PBKDF2 method, taking kernel-generated /proc/sys/kernel/random/boot_id
	// as the input.
	// Note that even though the config with the password is passed from NIM to the wwan
	// microservice using the *in-memory only* /run filesystem, we still encrypt the password
	// to avoid accidental exposure when the content of /run/wwan is dumped as part
	// of a customer issue report.
	EncryptedPassword string `json:"encrypted-password,omitempty"`
	// The set of cellular network operators that modem should preferably try to register
	// and connect into.
	// Network operator should be referenced by PLMN (Public Land Mobile Network) code,
	// consisting of 3-digits MCC (Mobile Country Code) and 2 or 3-digits MNC
	// (Mobile Network Code), separated by a dash, e.g. "310-260".
	// If empty, then modem will select the network automatically based on the SIM
	// card config.
	PreferredPLMNs []string `json:"preferred-plmns,omitempty"`
	// The list of preferred Radio Access Technologies (RATs) to use for connecting
	// to the network.
	// Order matters, first is the most preferred, second is tried next, etc.
	// Not listed technologies will not be tried.
	// If empty, then modem will select RAT automatically.
	PreferredRATs []WwanRAT `json:"preferred-rats,omitempty"`
	// Enable or disable data roaming.
	ForbidRoaming bool `json:"forbid-roaming"`
	// Proxies configured for the cellular network.
	Proxies []ProxyEntry `json:"proxies"`
	// Probe used to detect broken connection.
	Probe WwanProbe `json:"probe"`
	// Some LTE modems have GNSS receiver integrated and can be used
	// for device location tracking.
	// Enable this option to have location info periodically obtained
	// from this modem and published into /run/wwan/location.json by the wwan
	// microservice. This is further distributed to the controller and
	// to applications by zedagent.
	LocationTracking bool `json:"location-tracking"`
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
	Disable bool `json:"disable"`
	// IP/FQDN address to periodically probe to determine connection status.
	Address string `json:"address"`
}

// Equal compares two instances of WwanNetworkConfig for equality.
func (wnc WwanNetworkConfig) Equal(wnc2 WwanNetworkConfig) bool {
	if wnc.LogicalLabel != wnc2.LogicalLabel ||
		wnc.PhysAddrs != wnc2.PhysAddrs {
		return false
	}
	if wnc.SIMSlot != wnc2.SIMSlot ||
		wnc.APN != wnc2.APN {
		return false
	}
	if wnc.AuthProtocol != wnc2.AuthProtocol ||
		wnc.Username != wnc2.Username ||
		wnc.EncryptedPassword != wnc2.EncryptedPassword {
		return false
	}
	if !generics.EqualLists(wnc.PreferredPLMNs, wnc2.PreferredPLMNs) ||
		!generics.EqualLists(wnc.PreferredRATs, wnc2.PreferredRATs) ||
		wnc.ForbidRoaming != wnc2.ForbidRoaming {
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
	Interface string `json:"interface"`
	// USB address in the format "<BUS>:[<PORT>]", with nested ports separated by dots.
	// For example: 1:2.3
	USB string `json:"usb"`
	// PCI address in the long format.
	// For example: 0000:00:15.0
	PCI string `json:"pci"`
	// Dev : device file representing the modem (e.g. /dev/cdc-wdm0).
	// This address is only published as part of the wwan status
	// and can't be configured from the controller.
	Dev string `json:"dev,omitempty"`
}

// WwanStatus is published by the wwan service and consumed by nim.
type WwanStatus struct {
	Networks []WwanNetworkStatus `json:"networks"`
	// SHA256 hash of the corresponding WwanConfig (as config.json).
	ConfigChecksum string `json:"config-checksum,omitempty"`
}

// Equal compares two instances of WwanStatus for equality.
func (ws WwanStatus) Equal(ws2 WwanStatus) bool {
	if ws.ConfigChecksum != ws2.ConfigChecksum {
		return false
	}
	return generics.EqualSetsFn(ws.Networks, ws2.Networks,
		func(wns1, wns2 WwanNetworkStatus) bool {
			return wns1.Equal(wns2)
		})
}

// LookupNetworkStatus returns status corresponding to the given cellular network.
func (ws WwanStatus) LookupNetworkStatus(logicalLabel string) (WwanNetworkStatus, bool) {
	for _, status := range ws.Networks {
		if logicalLabel == status.LogicalLabel {
			return status, true
		}
	}
	return WwanNetworkStatus{}, false
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

// WwanNetworkStatus contains status information for a single cellular network
// (i.e. one modem but possibly multiple SIM slots/cards).
type WwanNetworkStatus struct {
	// Logical label of the cellular modem in PhysicalIO.
	// Can be empty if this device is not configured by the controller
	// (and hence logical label does not exist).
	LogicalLabel string         `json:"logical-label"`
	PhysAddrs    WwanPhysAddrs  `json:"physical-addrs"`
	Module       WwanCellModule `json:"cellular-module"`
	// One entry for every SIM slot (incl. those without SIM card).
	SimCards []WwanSimCard `json:"sim-cards"`
	// Non-empty if the wwan microservice failed to apply config submitted by NIM.
	ConfigError string `json:"config-error"`
	// Error message from the last connectivity probing.
	ProbeError string `json:"probe-error"`
	// Network where the modem is currently registered.
	CurrentProvider WwanProvider `json:"current-provider"`
	// All networks that the modem is able to detect.
	// This will include the currently used provider as well as other visible networks.
	VisibleProviders []WwanProvider `json:"visible-providers,omitempty"`
	// The list of Radio Access Technologies (RATs) currently used for registering/connecting
	// to the network (typically just one).
	CurrentRATs []WwanRAT `json:"current-rats"`
	// Unix timestamp in seconds made when the current connection was established.
	// Zero value if the modem is not connected.
	ConnectedAt uint64 `json:"connected-at"`
}

// WwanCellModule contains cellular module specs.
type WwanCellModule struct {
	// Name is a module identifier. For example IMEI if available.
	// Guaranteed to be unique among all modems attached to the edge node.
	Name string `json:"name,omitempty"`
	// International Mobile Equipment Identity.
	IMEI         string `json:"imei"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	// Firmware version identifier.
	Revision string `json:"revision"`
	// QMI or MBIM.
	ControlProtocol WwanCtrlProt `json:"control-protocol"`
	OpMode          WwanOpMode   `json:"operating-mode"`
}

// WwanSimCard describes either empty SIM slot or a slot with a SIM card inserted.
type WwanSimCard struct {
	// Name is a SIM card/slot identifier.
	// Guaranteed to be unique across all modems and their SIM slots attached
	// to the edge node.
	Name string `json:"name,omitempty"`
	// SIM slot number which this WwanSimCard instance describes.
	SlotNumber uint8 `json:"slot-number"`
	// True if this SIM slot is activated, i.e. the inserted SIM card (if any) can be used
	// to connect to a cellular network.
	SlotActivated bool `json:"slot-activated"`
	// Integrated Circuit Card Identifier.
	// Empty if no SIM card is inserted into the slot or if the SIM card is not recognized.
	ICCID string `json:"iccid,omitempty"`
	// International Mobile Subscriber Identity.
	// Empty if no SIM card is inserted into the slot or if the SIM card is not recognized.
	IMSI string `json:"imsi,omitempty"`
	// The current state of the SIM card (absent, initialized, not recognized, etc.).
	// This state is not modeled using enum because the set of possible values differs
	// between QMI and MBIM protocols (used to control cellular modules) and there is
	// no 1:1 mapping between them.
	State string `json:"state"`
}

// WwanProvider contains information about a cellular connectivity provider.
type WwanProvider struct {
	// Public Land Mobile Network identifier.
	PLMN string `json:"plmn"`
	// Human-readable label identifying the provider.
	Description string `json:"description"`
	// True if this is the provider currently being used.
	CurrentServing bool `json:"current-serving"`
	// True if data roaming is ON.
	Roaming bool `json:"roaming"`
	// True if this provider is forbidden by SIM card config.
	Forbidden bool `json:"forbidden"`
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
	// WwanOpModeUnrecognized : unrecongized operating mode
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
	if wns.ConnectedAt != wns2.ConnectedAt {
		return false
	}
	return true
}

// WwanMetrics is published by the wwan service.
type WwanMetrics struct {
	Networks []WwanNetworkMetrics `json:"networks"`
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
	LogicalLabel string          `json:"logical-label"`
	PhysAddrs    WwanPhysAddrs   `json:"physical-addrs"`
	PacketStats  WwanPacketStats `json:"packet-stats"`
	SignalInfo   WwanSignalInfo  `json:"signal-info"`
}

// WwanPacketStats contains packet statistics recorded by a cellular modem.
type WwanPacketStats struct {
	RxBytes   uint64 `json:"rx-bytes"`
	RxPackets uint64 `json:"rx-packets"`
	RxDrops   uint64 `json:"rx-drops"`
	TxBytes   uint64 `json:"tx-bytes"`
	TxPackets uint64 `json:"tx-packets"`
	TxDrops   uint64 `json:"tx-drops"`
}

// WwanSignalInfo contains cellular signal strength information.
// The maximum value of int32 (0x7FFFFFFF) represents unspecified/unavailable metric.
type WwanSignalInfo struct {
	// Received signal strength indicator (RSSI) measured in dBm (decibel-milliwatts).
	RSSI int32 `json:"rssi"`
	// Reference Signal Received Quality (RSRQ) measured in dB (decibels).
	RSRQ int32 `json:"rsrq"`
	// Reference Signal Receive Power (RSRP) measured in dBm (decibel-milliwatts).
	RSRP int32 `json:"rsrp"`
	// Signal-to-Noise Ratio (SNR) measured in dB (decibels).
	SNR int32 `json:"snr"`
}

// WwanLocationInfo contains device location information obtained from a GNSS
// receiver integrated into an LTE modem.
type WwanLocationInfo struct {
	// Logical label of the device used to obtain this location information.
	LogicalLabel string `json:"logical-label"`
	// Latitude in the Decimal degrees (DD) notation.
	// Valid values are in the range <-90, 90>. Anything outside of this range
	// should be treated as an unavailable value.
	// Note that wwan microservice uses -32768 specifically when latitude is not known.
	Latitude float64 `json:"latitude"`
	// Longitude in the Decimal degrees (DD) notation.
	// Valid values are in the range <-180, 180>. Anything outside of this range
	// should be treated as an unavailable value.
	// Note that wwan microservice uses -32768 specifically when longitude is not known.
	Longitude float64 `json:"longitude"`
	// Altitude w.r.t. mean sea level in meters.
	// Negative value of -32768 is returned when altitude is not known.
	Altitude float64 `json:"altitude"`
	// Circular horizontal position uncertainty in meters.
	// Negative values are not valid and represent unavailable uncertainty.
	// Note that wwan microservice uses -32768 specifically when horizontal
	// uncertainty is not known.
	HorizontalUncertainty float32 `json:"horizontal-uncertainty"`
	// Reliability of the provided information for latitude and longitude.
	HorizontalReliability LocReliability `json:"horizontal-reliability"`
	// Vertical position uncertainty in meters.
	// Negative values are not valid and represent unavailable uncertainty.
	// Note that wwan microservice uses -32768 specifically when vertical
	// uncertainty is not known.
	VerticalUncertainty float32 `json:"vertical-uncertainty"`
	// Reliability of the provided information for altitude.
	VerticalReliability LocReliability `json:"vertical-reliability"`
	// Unix timestamp in milliseconds.
	// Zero value represents unavailable UTC timestamp.
	UTCTimestamp uint64 `json:"utc-timestamp"`
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
