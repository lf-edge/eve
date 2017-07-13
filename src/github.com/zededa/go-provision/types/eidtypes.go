// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Type defintions for interface from Zedmanager to IdentityMgr for EID
// allocation and status

package types

import (
	"net"
)

// XXX fill in

// Indexed by UUID plus IID; version not included in index
// A given App Instance can not have multiple interfaces to the same IID.
type EIDConfig struct {
	UUIDandVersion	UUIDandVersion
	IID		uint32
	DisplayName	string
	IsZedmanager	bool	// XXX useful?
	Allocate	bool
	ExportPrivate	bool	// Provide private key to ZedManager for mobility
	EIDAllocationPrefix []byte	// XXX normally 0xfd
	// When Allocate is false the ZedCloud provides these parameters.
	// No work for IdentityMgr in that case.
	// When Allocate is true these fields are not filled in the config
	EID		net.IP
	PemCert		[]byte
	LispSignature	string
	PemPrivateKey	[]byte	// If ExportPrivate. XXX or in separate type?
}

// Indexed by UUID plus IID
type EIDStatus struct {
	UUIDandVersion	UUIDandVersion
	IID		uint32
	DisplayName	string
	ExportPrivate	bool
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	EID		net.IP
	PemCert		[]byte
	PemPublicKey	[]byte	// XXX for debugging
	LispSignature	string
	PemPrivateKey	[]byte	// If ExportPrivate. XXX or in separate type?
}
