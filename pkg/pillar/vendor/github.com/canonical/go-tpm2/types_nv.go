// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"fmt"

	"github.com/canonical/go-tpm2/mu"
)

// This file contains types defined in section 13 (NV Storage Structures)
// in part 2 of the library spec.

// NVType corresponds to the TPM_NT type.
type NVType uint32

// WithAttrs returns NVAttributes for this type with the specified attributes set.
func (t NVType) WithAttrs(attrs NVAttributes) NVAttributes {
	return NVAttributes(t<<4) | attrs
}

const (
	NVTypeOrdinary NVType = 0 // TPM_NT_ORDINARY
	NVTypeCounter  NVType = 1 // TPM_NT_COUNTER
	NVTypeBits     NVType = 2 // TPM_NT_BITS
	NVTypeExtend   NVType = 4 // TPM_NT_EXTEND
	NVTypePinFail  NVType = 8 // TPM_NT_PIN_FAIL
	NVTypePinPass  NVType = 9 // TPM_NT_PIN_PASS
)

// NVPinCounterParams corresponds to the TPMS_NV_PIN_COUNTER_PARAMETERS type.
type NVPinCounterParams struct {
	Count uint32
	Limit uint32
}

// NVAttributes corresponds to the TPMA_NV type, and represents the
// attributes of a NV index. When exchanged with the TPM, some bits
// are reserved to encode the type of the NV index ([NVType]).
type NVAttributes uint32

// Type returns the NVType encoded in a NVAttributes value.
func (a NVAttributes) Type() NVType {
	return NVType((a & 0xf0) >> 4)
}

// AttrsOnly returns the NVAttributes without the encoded [NVType].
func (a NVAttributes) AttrsOnly() NVAttributes {
	return a & ^NVAttributes(0xf0)
}

const (
	AttrNVPPWrite        NVAttributes = 1 << 0  // TPMA_NV_PPWRITE
	AttrNVOwnerWrite     NVAttributes = 1 << 1  // TPMA_NV_OWNERWRITE
	AttrNVAuthWrite      NVAttributes = 1 << 2  // TPMA_NV_AUTHWRITE
	AttrNVPolicyWrite    NVAttributes = 1 << 3  // TPMA_NV_POLICY_WRITE
	AttrNVPolicyDelete   NVAttributes = 1 << 10 // TPMA_NV_POLICY_DELETE
	AttrNVWriteLocked    NVAttributes = 1 << 11 // TPMA_NV_WRITELOCKED
	AttrNVWriteAll       NVAttributes = 1 << 12 // TPMA_NV_WRITEALL
	AttrNVWriteDefine    NVAttributes = 1 << 13 // TPMA_NV_WRITEDEFINE
	AttrNVWriteStClear   NVAttributes = 1 << 14 // TPMA_NV_WRITE_STCLEAR
	AttrNVGlobalLock     NVAttributes = 1 << 15 // TPMA_NV_GLOBALLOCK
	AttrNVPPRead         NVAttributes = 1 << 16 // TPMA_NV_PPREAD
	AttrNVOwnerRead      NVAttributes = 1 << 17 // TPMA_NV_OWNERREAD
	AttrNVAuthRead       NVAttributes = 1 << 18 // TPMA_NV_AUTHREAD
	AttrNVPolicyRead     NVAttributes = 1 << 19 // TPMA_NV_POLICYREAD
	AttrNVNoDA           NVAttributes = 1 << 25 // TPMA_NV_NO_DA
	AttrNVOrderly        NVAttributes = 1 << 26 // TPMA_NV_ORDERLY
	AttrNVClearStClear   NVAttributes = 1 << 27 // TPMA_NV_CLEAR_STCLEAR
	AttrNVReadLocked     NVAttributes = 1 << 28 // TPMA_NV_READLOCKED
	AttrNVWritten        NVAttributes = 1 << 29 // TPMA_NV_WRITTEN
	AttrNVPlatformCreate NVAttributes = 1 << 30 // TPMA_NV_PLATFORMCREATE
	AttrNVReadStClear    NVAttributes = 1 << 31 // TPMA_NV_READ_STCLEAR
)

// NVPublic corresponds to the TPMS_NV_PUBLIC type, which describes a NV index.
type NVPublic struct {
	Index      Handle          // Handle of the NV index
	NameAlg    HashAlgorithmId // NameAlg is the digest algorithm used to compute the name of the index
	Attrs      NVAttributes    // Attributes of this index
	AuthPolicy Digest          // Authorization policy for this index
	Size       uint16          // Size of this index
}

// Name computes the name of this NV index
func (p *NVPublic) ComputeName() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	h := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(h, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	return mu.MustMarshalToBytes(p.NameAlg, mu.RawBytes(h.Sum(nil))), nil
}

func (p *NVPublic) compareName(name Name) bool {
	n, err := p.ComputeName()
	if err != nil {
		return false
	}
	return bytes.Equal(n, name)
}

// Name implements [github.com/canonical/go-tpm2/objectutil.Named] and
// [github.com/canonical/go-tpm2/policyutil.Named].
//
// This computes the name from the public area. If the name cannot be computed
// then an invalid name is returned ([Name.Type] will return NameTypeInvalid).
func (p *NVPublic) Name() Name {
	name, err := p.ComputeName()
	if err != nil {
		return Name{0, 0}
	}
	return name
}

// Handle implements [github.com/canonical/go-tpm2/policyutil.NVIndex].
func (p *NVPublic) Handle() Handle {
	return p.Index
}
