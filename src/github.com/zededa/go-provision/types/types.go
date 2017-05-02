package types

import (
	"net"
	"time"
)

// Database entry for provisioning certificate.
// Provides a secure binding to the username under which it is registered.
// Can be used to register RemainingUse different devices
type ProvisioningCert struct {
	Cert         []byte
	UserName     string
	RegTime      time.Time
	RemainingUse int
	LastUsedTime time.Time
}

// Message payload for json to POST to /rest/self-register
// Certificate is the PEM encoded device certificate.
// The TLS exchange needs to be done using a registered Provisioning Certificate
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
}

type LispServerInfo struct {
	NameOrIp   string
	Credential string
}
