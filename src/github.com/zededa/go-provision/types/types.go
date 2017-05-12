package types

import (
	"net"
	"time"
)

// Database entry for onboarding certificate.
// Provides a secure binding to the username under which it is registered.
// Can be used to register RemainingUse different devices
type OnboardingCert struct {
	Cert         []byte
	UserName     string
	RegTime      time.Time
	RemainingUse int
	LastUsedTime time.Time
}

// Message payload for json to POST to /rest/self-register
// Certificate is the PEM encoded device certificate.
// The TLS exchange needs to be done using a registered Onboarding Certificate
type RegisterCreate struct {
	PemCert []byte
}

// Device database record. Also used for the json GET response for /rest/device
// TBD separate DeviceConfig i.e. Redirect and below from earlier fields?
type DeviceDb struct {
	DeviceCert        []byte
	DevicePublicKey   []byte
	UserName          string
	RegTime           time.Time
	ReRegisteredCount int
	ReadTime          time.Time
	// Redirect parameters; XXX should we send redirect response code?
	Redirect         bool
	RedirectToServer string
	RedirectRootCert []byte
	// LISP parameters; safe to have DNSname? Or list of IPs and credential
	// strings.
	LispMapServers []LispServerInfo
	LispInstance   uint32
	EID            net.IP
	EIDHashLen     uint8
	ZedServers     ZedServerConfig
}

type LispServerInfo struct {
	NameOrIp   string
	Credential string
}

type DeviceHwStatus struct {
	// XXX add timestamp? which type?
	Manufacturer string
	Model        string
	Serial       string
	Machine      string
	Processor    string
	Platform     string
	Compatible   string
	Memory       uint // Kbyte
	Storage      uint // Kbyte
}

type DeviceSwStatus struct {
	// XXX add timestamp?
	ApplicationStatus []SwStatus
}

// Note that SwConfig might make private+cert, plus EID, or allow EID generation
// Does that mean we need a cert in SwStatus?
// SwConfig would have an 'Activate bool' instead of Activated
// SwConfig would have a Url, DigestAlg, and Digest as well.
// Need to restucture, since a given EID/Name can have multiple versions.
// Ditto for SwConfig.
type SwStatus struct {
	EID         net.IP // If one assigned. UUID alternative?
	Name        string
	Version     string
	Description string // optional
	State       SwState
	Activated   bool
}

// Type names from OMA-TS-LWM2M_SwMgmt-V1_0-20151201-C
type SwState uint8

const (
	INITIAL          SwState = iota + 1
	DOWNLOAD_STARTED         // Really download in progress
	DOWNLOADED
	DELIVERED // Package integrity verified
	INSTALLED // Available to be activated
)

// Part of config handed to the device.
// The EIDs in the overlay to which it should connect.
// XXX change to name, IP; "zedcontrol" would be a name
type ZedServerConfig struct {
	NamesToEids	[]NameToEid
}

type NameToEid struct {
	HostName        string
	EIDs		[]net.IP
}