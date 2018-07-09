// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

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
	LispMapServers         []LispServerInfo
	LispInstance           uint32
	EID                    net.IP
	EIDHashLen             uint8
	ZedServers             ZedServerConfig
	EidAllocationPrefix    []byte
	EidAllocationPrefixLen int
	ClientAddr             string // To detect NATs
}

type LispServerInfo struct {
	NameOrIp   string
	Credential string
}

// Part of config handed to the device.
// The EIDs in the overlay to which it should connect.
// Think of this as /etc/hosts for the ZedManager - maps from names such as
// "zedcontrol" amd "zedlake0" to EIDs in the management overlay.
type ZedServerConfig struct {
	NameToEidList []NameToEid
}

type NameToEid struct {
	HostName string
	EIDs     []net.IP
}
