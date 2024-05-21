// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package mmdbus

// Standard D-Bus interfaces
const (
	DBusMethodManagedObjects    = "org.freedesktop.DBus.ObjectManager.GetManagedObjects"
	DBusSignalInterfacesAdded   = "org.freedesktop.DBus.ObjectManager.InterfacesAdded"
	DBusSignalInterfacesRemoved = "org.freedesktop.DBus.ObjectManager.InterfacesRemoved"
	DBusSignalPropertiesChanged = "org.freedesktop.DBus.Properties.PropertiesChanged"
	DBusMethodAddMatch          = "org.freedesktop.DBus.AddMatch"
)

// ModemManager D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/ref-dbus.html
const (
	MMInterface         = "org.freedesktop.ModemManager1"
	MMObjectPath        = "/org/freedesktop/ModemManager1"
	MMPropertyVersion   = MMInterface + ".Version"
	MMMethodSetLogging  = MMInterface + ".SetLogging"
	MMMethodScanDevices = MMInterface + ".ScanDevices"
)

// ModemManager/Modem D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/ref-dbus-object-modem.html
const (
	ModemPathPrefix                = MMObjectPath + "/Modem/"
	ModemInterface                 = MMInterface + ".Modem"
	ModemMethodEnable              = ModemInterface + ".Enable"
	ModemMethodSetPowerState       = ModemInterface + ".SetPowerState"
	ModemMethodSetPrimarySimSlot   = ModemInterface + ".SetPrimarySimSlot"
	ModemMethodSetCurrentModes     = ModemInterface + ".SetCurrentModes"
	ModemPropertyModel             = ModemInterface + ".Model"
	ModemPropertyRevision          = ModemInterface + ".Revision"
	ModemPropertyManufacturer      = ModemInterface + ".Manufacturer"
	ModemPropertyPorts             = ModemInterface + ".Ports"
	ModemPropertyPrimaryPort       = ModemInterface + ".PrimaryPort"
	ModemPropertyIMEI              = ModemInterface + ".EquipmentIdentifier"
	ModemPropertyState             = ModemInterface + ".State"
	ModemPropertyStateFailReason   = ModemInterface + ".StateFailedReason"
	ModemPropertyPowerState        = ModemInterface + ".PowerState"
	ModemPropertySIM               = ModemInterface + ".Sim"
	ModemPropertySIMSlots          = ModemInterface + ".SimSlots"
	ModemPropertyPrimarySIMSlot    = ModemInterface + ".PrimarySimSlot"
	ModemPropertyRATsName          = "AccessTechnologies"
	ModemPropertyRATs              = ModemInterface + "." + ModemPropertyRATsName
	ModemPropertyBearers           = ModemInterface + ".Bearers"
	ModemPropertySignalQualityName = "SignalQuality"
	ModemPropertySignalQuality     = ModemInterface + "." + ModemPropertySignalQualityName
	ModemPropertySupportedModes    = ModemInterface + ".SupportedModes"
)

// ModemManager/SIM D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/ref-dbus-object-sim.html
const (
	SIMInterface          = MMInterface + ".Sim"
	SIMPropertyActive     = SIMInterface + ".Active"
	SIMPropertyICCID      = SIMInterface + ".SimIdentifier"
	SIMPropertyIMSI       = SIMInterface + ".Imsi"
	SIMPropertyType       = SIMInterface + ".SimType"
	SIMPropertyESIMStatus = SIMInterface + ".EsimStatus"
)

// SIM type
// https://www.freedesktop.org/software/ModemManager/doc/latest/ModemManager/ModemManager-Flags-and-Enumerations.html#MMSimType
const (
	SIMTypeUnknown  = 0
	SIMTypePhysical = 1
	SIMTypeESIM     = 2
)

// ESIM status
// https://www.freedesktop.org/software/ModemManager/doc/latest/ModemManager/ModemManager-Flags-and-Enumerations.html#MMSimEsimStatus
const (
	ESIMWithoutProfiles = 1
	ESIMWithProfiles    = 2
)

// Modem control protocol
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModemPortType
const (
	ModemPortTypeQMI  = 6
	ModemPortTypeMBIM = 7
)

// Modem state
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModemState
const (
	// ModemStateFailed : the modem is unusable.
	ModemStateFailed = -1
	// ModemStateUnknown : state unknown or not reportable.
	ModemStateUnknown = 0
	// ModemStateDisabled : modem is not enabled.
	ModemStateDisabled = 3
	// ModemStateRegistered = the modem is registered with a network provider
	// and data connections and messaging may be available for use.
	ModemStateRegistered = 8
	// ModemStateConnecting : the modem is activating and connecting the first packet
	// data bearer. Subsequent bearer activations when another bearer is already active
	// do not cause this state to be entered.
	ModemStateConnecting = 10
	// ModemStateConnected : one or more packet data bearers is active and connected.
	ModemStateConnected = 11
)

// Modem power state
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModemPowerState
const (
	ModemPowerStateOff = 1
	ModemPowerStateLow = 2
	ModemPowerStateOn  = 3
)

// Reason for modem failure
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModemStateFailedReason
const (
	// ModemStateFailedReasonSimMissing : SIM is required but missing.
	ModemStateFailedReasonSimMissing = 2
	// ModemStateFailedReasonSimError : SIM is available, but unusable.
	// (e.g. permanently locked)
	ModemStateFailedReasonSimError = 3
)

// Mode in which modem operates (2G/3G/...)
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModemMode
const (
	ModemMode2G = 1 << 1 // GPRS, EDGE.
	ModemMode3G = 1 << 2 // UMTS, HSxPA.
	ModemMode4G = 1 << 3 // LTE.
	ModemMode5G = 1 << 4 // 5GNR.
)

var allModemModes = []uint32{ModemMode2G, ModemMode3G, ModemMode4G, ModemMode5G}

// ModemManager/Modem/Signal D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Modem.Signal.html
const (
	SignalInterface    = ModemInterface + ".Signal"
	SignalMethodSetup  = SignalInterface + ".Setup"
	SignalPropertyGSM  = SignalInterface + ".Gsm"
	SignalPropertyUMTS = SignalInterface + ".Umts"
	SignalPropertyLTE  = SignalInterface + ".Lte"
	SignalProperty5G   = SignalInterface + ".Nr5g"
)

// Radio access technologies (RATs)
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModemAccessTechnology
const (
	AccessTechnologyGSM        = 1 << 1  // GSM.
	AccessTechnologyGSMCompact = 1 << 2  // Compact GSM.
	AccessTechnologyGPRS       = 1 << 3  // GPRS.
	AccessTechnologyEDGE       = 1 << 4  // EDGE (ETSI 27.007: "GSM w/EGPRS").
	AccessTechnologyUMTS       = 1 << 5  // UMTS (ETSI 27.007: "UTRAN").
	AccessTechnologyHSDPA      = 1 << 6  // HSDPA (ETSI 27.007: "UTRAN w/HSDPA").
	AccessTechnologyHSUPA      = 1 << 7  // HSUPA (ETSI 27.007: "UTRAN w/HSUPA").
	AccessTechnologyHSPA       = 1 << 8  // HSPA (ETSI 27.007: "UTRAN w/HSDPA and HSUPA").
	AccessTechnologyHSPAPlus   = 1 << 9  // HSPA+ (ETSI 27.007: "UTRAN w/HSPA+").
	AccessTechnologyLTE        = 1 << 14 // LTE (ETSI 27.007: "E-UTRAN")
	AccessTechnology5GNR       = 1 << 15 // 5GNR (ETSI 27.007: "NG-RAN")
	AccessTechnologyLTECatM    = 1 << 16 // Cat-M (ETSI 23.401: LTE Category M1/M2)
	AccessTechnologyLTENbIOT   = 1 << 17 // NB IoT (ETSI 23.401: LTE Category NB1/NB2)

	AccessTechnologies2G = AccessTechnologyGSM | AccessTechnologyGSMCompact |
		AccessTechnologyGPRS | AccessTechnologyEDGE
	AccessTechnologies3G = AccessTechnologyUMTS | AccessTechnologyHSDPA |
		AccessTechnologyHSUPA | AccessTechnologyHSPA | AccessTechnologyHSPAPlus
	AccessTechnologies4G = AccessTechnologyLTE | AccessTechnologyLTECatM |
		AccessTechnologyLTENbIOT
	AccessTechnologies5G        = AccessTechnology5GNR
	AccessTechnologiesSupported = AccessTechnologies2G | AccessTechnologies3G |
		AccessTechnologies4G | AccessTechnologies5G
)

// ModemManager/Modem/3GPP D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Modem.Modem3gpp.html
const (
	Modem3GPPInterface                 = ModemInterface + ".Modem3gpp"
	Modem3GPPMethodSetInitialEpsBearer = Modem3GPPInterface + ".SetInitialEpsBearerSettings"
	Modem3GPPMethodScan                = Modem3GPPInterface + ".Scan"
	Modem3GPPPropertyRegistrationState = Modem3GPPInterface + ".RegistrationState"
	Modem3GPPPropertyPLMN              = Modem3GPPInterface + ".OperatorCode"
	Modem3GPPPropertyProviderName      = Modem3GPPInterface + ".OperatorName"
	Modem3GPPPropertyInitialEpsBearer  = Modem3GPPInterface + ".InitialEpsBearerSettings"
)

// Modem registration state
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModem3gppRegistrationState
const (
	RegistrationStateDenied                  = 3
	RegistrationStateRoaming                 = 5
	RegistrationStateRoamingSmsOnly          = 7
	RegistrationStateRoamingCsfbNotPreferred = 10
)

// Network availability
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModem3gppNetworkAvailability
const (
	NetworkAvailabilityAvailable = 1
	NetworkAvailabilityCurrent   = 2
	NetworkAvailabilityForbidden = 3
)

// ModemManager/Bearer D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Bearer.html#
const (
	BearerInterface             = MMInterface + ".Bearer"
	BearerPropertyConnectedName = "Connected"
	BearerPropertyConnected     = BearerInterface + "." + BearerPropertyConnectedName
	BearerPropertyStatsName     = "Stats"
	BearerPropertyStats         = BearerInterface + "." + BearerPropertyStatsName
	BearerPropertyIPv4Config    = BearerInterface + ".Ip4Config"
	BearerPropertyIPv6Config    = BearerInterface + ".Ip6Config"
)

// Bearer IP method
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMBearerIpMethod
const (
	BearerIPMethodPPP    = 1
	BearerIPMethodStatic = 2
	BearerIPMethodDHCP   = 3
)

// Bearer IP family
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMBearerIpFamily
const (
	BearerIPFamilyIPv4   = 1 << 0 // IPv4.
	BearerIPFamilyIPv6   = 1 << 1 // IPv6.
	BearerIPFamilyIPv4v6 = 1 << 2 // IPv4 and IPv6.
)

// Bearer allowed user-authentication method
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMBearerAllowedAuth
const (
	BearerAllowedAuthUnknown = 0
	BearerAllowedAuthNone    = 1 << 0 // None.
	BearerAllowedAuthPap     = 1 << 1 // PAP.
	BearerAllowedAuthChap    = 1 << 2 // CHAP.
)

// ModemManager/Modem/Location D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Modem.Location.html
const (
	LocationInterface               = ModemInterface + ".Location"
	LocationMethodSetup             = LocationInterface + ".Setup"
	LocationMethodSetGpsRefreshRate = LocationInterface + ".SetGpsRefreshRate"
	LocationPropertyName            = "Location"
	LocationProperty                = LocationInterface + "." + LocationPropertyName
	LocationPropertyEnabledName     = "Enabled"
	LocationPropertyEnabled         = LocationInterface + "." + LocationPropertyEnabledName
	LocationPropertySignalsName     = "SignalsLocation"
	LocationPropertySignals         = LocationInterface + "." + LocationPropertySignalsName
	// LocationTimestampLayout : used for UTC timestamp in LocationProperty
	// for LocationSourceGpsRaw
	LocationTimestampLayout = "150405.00"
)

// Location source
// https://www.freedesktop.org/software/ModemManager/api/latest/ModemManager-Flags-and-Enumerations.html#MMModemLocationSource
const (
	LocationSourceNone   = 0
	LocationSourceGpsRaw = 1 << 1
)

// ModemManager/Modem/Simple D-Bus interface
// https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Modem.Simple.html
const (
	SimpleInterface        = ModemInterface + ".Simple"
	SimpleMethodConnect    = SimpleInterface + ".Connect"
	SimpleMethodDisconnect = SimpleInterface + ".Disconnect"
)
