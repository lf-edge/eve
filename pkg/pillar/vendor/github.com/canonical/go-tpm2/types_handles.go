// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// This file contains types defined in section 7 (Handles) in
// part 2 of the library spec.

// Handle corresponds to the TPM_HANDLE type, and is a numeric
// identifier that references a resource on the TPM.
type Handle uint32

// Type returns the type of the handle.
func (h Handle) Type() HandleType {
	return HandleType(h >> 24)
}

const (
	HandleOwner       Handle = 0x40000001 // TPM_RH_OWNER
	HandleNull        Handle = 0x40000007 // TPM_RH_NULL
	HandleUnassigned  Handle = 0x40000008 // TPM_RH_UNASSIGNED
	HandlePW          Handle = 0x40000009 // TPM_RS_PW
	HandleLockout     Handle = 0x4000000a // TPM_RH_LOCKOUT
	HandleEndorsement Handle = 0x4000000b // TPM_RH_ENDORSEMENT
	HandlePlatform    Handle = 0x4000000c // TPM_RH_PLATFORM
	HandlePlatformNV  Handle = 0x4000000d // TPM_RH_PLATFORM_NV
)

// HandleType corresponds to the TPM_HT type, and is used to
// identify the type of a Handle.
type HandleType uint8

// BaseHandle returns the first handle for the handle type.
func (h HandleType) BaseHandle() Handle {
	return Handle(h) << 24
}

const (
	HandleTypePCR           HandleType = 0x00 // TPM_HT_PCR
	HandleTypeNVIndex       HandleType = 0x01 // TPM_HT_NV_INDEX
	HandleTypeHMACSession   HandleType = 0x02 // TPM_HT_HMAC_SESSION
	HandleTypeLoadedSession HandleType = 0x02 // TPM_HT_LOADED_SESSION
	HandleTypePolicySession HandleType = 0x03 // TPM_HT_POLICY_SESSION
	HandleTypeSavedSession  HandleType = 0x03 // TPM_HT_SAVED_SESSION
	HandleTypePermanent     HandleType = 0x40 // TPM_HT_PERMANENT
	HandleTypeTransient     HandleType = 0x80 // TPM_HT_TRANSIENT
	HandleTypePersistent    HandleType = 0x81 // TPM_HT_PERSISTENT
)
