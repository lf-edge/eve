// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Type definitions for interface from Zedmanager to IdentityMgr for EID
// allocation and status

package types

import (
	"fmt"
	"net"
	"time"
)

// Parameters which determine whether and how the EID is allocated
type EIDAllocation struct {
	Allocate            bool
	ExportPrivate       bool   // Provide private key to ZedManager
	AllocationPrefix    []byte // Normally and default 0xfd
	AllocationPrefixLen int    // Normally and default 8
}

// Indexed by UUID plus IID; version not included in index
// Implies a given App Instance can not have multiple interfaces to the same IID.
type EIDConfig struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string
	EIDConfigDetails
}

type EIDConfigDetails struct {
	IID uint32
	EIDAllocation
	// When Allocate is false the ZedCloud provides these parameters.
	// No work for IdentityMgr in that case.
	// When Allocate is true these fields are not set in the config
	EID           net.IP
	LispSignature string
	PemCert       []byte
	PemPrivateKey []byte
}

func (config EIDConfig) Key() string {
	return fmt.Sprintf("%s:%d",
		config.UUIDandVersion.UUID.String(), config.IID)
}

// Indexed by UUID plus IID. Version is not part of the index.
type EIDStatus struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string
	EIDStatusDetails
}

type EIDStatusDetails struct {
	IID uint32
	EIDAllocation
	PendingAdd    bool
	PendingModify bool
	PendingDelete bool
	EID           net.IP
	LispSignature string
	PemCert       []byte
	PemPublicKey  []byte
	PemPrivateKey []byte    // If ExportPrivate. XXX or in separate type?
	CreateTime    time.Time // When EID was created
}

func EidKey(uuidAndVers UUIDandVersion, iid uint32) string {
	return fmt.Sprintf("%s:%d", uuidAndVers.UUID.String(), iid)
}

func (status EIDStatus) Key() string {
	return fmt.Sprintf("%s:%d",
		status.UUIDandVersion.UUID.String(), status.IID)
}

func (status EIDStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}
