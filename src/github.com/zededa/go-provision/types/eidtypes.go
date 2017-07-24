// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Type defintions for interface from Zedmanager to IdentityMgr for EID
// allocation and status

package types

import (
	"net"
)

type EIDAllocation struct {
	Allocate	bool
	ExportPrivate	bool	// Provide private key to ZedManager for mobility
	AllocationPrefix []byte	// XXX normally 0xfd
	AllocationPrefixLen int // XXX normally 8
}

// Indexed by UUID plus IID; version not included in index
// Implies a given App Instance can not have multiple interfaces to the same IID.
type EIDConfig struct {
	UUIDandVersion	UUIDandVersion
	IID		uint32
	DisplayName	string
	EIDAllocation
	// When Allocate is false the ZedCloud provides these parameters.
	// No work for IdentityMgr in that case.
	// When Allocate is true these fields are not set in the config
	EID		net.IP
	LispSignature	string
	PemCert		[]byte
	PemPrivateKey	[]byte	// If ExportPrivate. XXX or in separate type?
}

// Indexed by UUID plus IID. Version is not part of the index.
type EIDStatus struct {
	UUIDandVersion	UUIDandVersion
	IID		uint32
	DisplayName	string
	EIDAllocation
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	EID		net.IP
	LispSignature	string
	PemCert		[]byte
	PemPublicKey	[]byte
	PemPrivateKey	[]byte	// If ExportPrivate. XXX or in separate type?
}
