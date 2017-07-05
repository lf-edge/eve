// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Type defintions for interface from Zedmanager to IdentityMgr for EID
// allocation and status

package types

import (
	"net"
)

// XXX fill in

// Indexed by UUID plus OlNum; version not included in index
type EIDConfig struct {
	UUIDandVersion	UUIDandVersion
	DisplayName	string
	OlNum		int	// Each overlay has separate EID
	IsZedmanager	bool	// XXX useful?
	IID		uint32
	Allocate	bool	
	ExportPrivate	bool	// Provide private key to ZedManager for mobilirt
	EIDAllocationPrefix []byte	// XXX normally 0xfd
	// When the EID is moved the ZedCloud provides these parameters.
	// No work for IdentityMgr in that case.
	EID		net.IP
	PemCert		[]byte
	LispSignature	string
	PemPrivateKey	[]byte	// If ExportPrivate. XXX or in separate type?
}

// Indexed by UUID plus olNum
type EIDStatus struct {
	UUIDandVersion	UUIDandVersion
	DisplayName	string
	OlNum		int	// Each overlay has separate EID
	IID		uint32
	ExportPrivate	bool	// Private key below is set. XXX vs. "" string?
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	EID		net.IP
	PemCert		[]byte
	PemPublicKey	[]byte	// XXX for debugging
	LispSignature	string
	PemPrivateKey	[]byte	// If ExportPrivate. XXX or in separate type?
}
