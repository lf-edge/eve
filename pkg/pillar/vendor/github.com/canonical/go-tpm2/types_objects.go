// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"
	"reflect"

	"github.com/canonical/go-tpm2/mu"
)

// This file contains types defined in section 12 (Key/Object Complex)
// in part 2 of the library spec.

// ObjectTypeId corresponds to the TPMI_ALG_PUBLIC type.
type ObjectTypeId AlgorithmId

// IsAsymmetric determines if the type corresponds to an asymmetric
// object.
func (t ObjectTypeId) IsAsymmetric() bool {
	return t == ObjectTypeRSA || t == ObjectTypeECC
}

const (
	ObjectTypeRSA       ObjectTypeId = ObjectTypeId(AlgorithmRSA)       // TPM_ALG_RSA
	ObjectTypeKeyedHash ObjectTypeId = ObjectTypeId(AlgorithmKeyedHash) // TPM_ALG_KEYEDHASH
	ObjectTypeECC       ObjectTypeId = ObjectTypeId(AlgorithmECC)       // TPM_ALG_ECC
	ObjectTypeSymCipher ObjectTypeId = ObjectTypeId(AlgorithmSymCipher) // TPM_ALG_SYMCIPHER
)

// PublicIDU is a union type that corresponds to the TPMU_PUBLIC_ID type. The selector type
// is [ObjectTypeId]. The mapping of selector values to fields is as follows:
//   - ObjectTypeRSA: RSA
//   - ObjectTypeKeyedHash: KeyedHash
//   - ObjectTypeECC: ECC
//   - ObjectTypeSymCipher: Sym
type PublicIDU struct {
	KeyedHash Digest
	Sym       Digest
	RSA       PublicKeyRSA
	ECC       *ECCPoint
}

// Select implements [mu.Union].
func (p *PublicIDU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return &p.RSA
	case ObjectTypeKeyedHash:
		return &p.KeyedHash
	case ObjectTypeECC:
		return &p.ECC
	case ObjectTypeSymCipher:
		return &p.Sym
	default:
		return nil
	}
}

// KeyedHashParams corresponds to the TPMS_KEYEDHASH_PARMS type, and defines the public
// parameters for a keyedhash object.
type KeyedHashParams struct {
	Scheme KeyedHashScheme // Signing method for a keyed hash signing object
}

// AsymParams corresponds to the TPMS_ASYM_PARMS type, and defines the common public
// parameters for an asymmetric key.
type AsymParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For a key with the AttrSign attribute: a signing scheme.
	// For a key with the AttrDecrypt attribute: a key exchange protocol.
	// For a key with both AttrSign and AttrDecrypt attributes: AlgorithmNull.
	Scheme AsymScheme
}

// RSAParams corresponds to the TPMS_RSA_PARMS type, and defines the public parameters
// for an RSA key.
type RSAParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For an unrestricted signing key: AlgorithmRSAPSS, AlgorithmRSASSA or AlgorithmNull.
	// For a restricted signing key: AlgorithmRSAPSS or AlgorithmRSASSA.
	// For an unrestricted decrypt key: AlgorithmRSAES, AlgorithmOAEP or AlgorithmNull.
	// For a restricted decrypt key: AlgorithmNull.
	Scheme   RSAScheme
	KeyBits  uint16 // Number of bits in the public modulus
	Exponent uint32 // Public exponent. When the value is zero, the exponent is 65537
}

// ECCParams corresponds to the TPMS_ECC_PARMS type, and defines the public parameters for an
// ECC key.
type ECCParams struct {
	Symmetric SymDefObject // Symmetric algorithm for a restricted decrypt key.
	// For a key with the AttrSign attribute: a signing scheme.
	// For a key with the AttrDecrypt attribute: a key exchange protocol or AlgorithmNull.
	// For a storage key: AlgorithmNull.
	Scheme  ECCScheme
	CurveID ECCCurve  // ECC curve ID
	KDF     KDFScheme // Unused - always KDFAlgorithmNull
}

// PublicParamsU is a union type that corresponds to the TPMU_PUBLIC_PARMS type. The selector
// type is ]ObjectTypeId].
// The mapping of selector values to fields is as follows:
//   - ObjectTypeRSA: RSADetail
//   - ObjectTypeKeyedHash: KeyedHashDetail
//   - ObjectTypeECC: ECCDetail
//   - ObjectTypeSymCipher: SymDetail
type PublicParamsU struct {
	KeyedHashDetail *KeyedHashParams
	SymDetail       *SymCipherParams
	RSADetail       *RSAParams
	ECCDetail       *ECCParams
}

// Select implements [mu.Union].
func (p *PublicParamsU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return &p.RSADetail
	case ObjectTypeKeyedHash:
		return &p.KeyedHashDetail
	case ObjectTypeECC:
		return &p.ECCDetail
	case ObjectTypeSymCipher:
		return &p.SymDetail
	default:
		return nil
	}
}

// AsymDetail returns the parameters associated with the specified object type
// as *AsymParams. It panics if the type is not [ObjectTypeRSA] or [ObjectTypeECC],
// or the appropriate field isn't set.
//
// Deprecated: Use [Public.AsymDetail] instead.
func (p PublicParamsU) AsymDetail(t ObjectTypeId) *AsymParams {
	switch t {
	case ObjectTypeRSA:
		return &AsymParams{
			Symmetric: p.RSADetail.Symmetric,
			Scheme: AsymScheme{
				Scheme:  AsymSchemeId(p.RSADetail.Scheme.Scheme),
				Details: p.RSADetail.Scheme.Details}}
	case ObjectTypeECC:
		return &AsymParams{
			Symmetric: p.ECCDetail.Symmetric,
			Scheme: AsymScheme{
				Scheme:  AsymSchemeId(p.ECCDetail.Scheme.Scheme),
				Details: p.ECCDetail.Scheme.Details}}
	default:
		panic("invalid type")
	}
}

// PublicParams corresponds to the TPMT_PUBLIC_PARMS type.
type PublicParams struct {
	Type       ObjectTypeId   // Type specifier
	Parameters *PublicParamsU // Algorithm details
}

// Public corresponds to the TPMT_PUBLIC type, and defines the public area for an object.
type Public struct {
	Type       ObjectTypeId     // Type of this object
	NameAlg    HashAlgorithmId  // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes // Object attributes
	AuthPolicy Digest           // Authorization policy for this object
	Params     *PublicParamsU   // Type specific parameters
	Unique     *PublicIDU       // Type specific unique identifier
}

// ComputeName computes the name of this object
func (p *Public) ComputeName() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	h := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(h, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	return mu.MustMarshalToBytes(p.NameAlg, mu.RawBytes(h.Sum(nil))), nil
}

func (p *Public) compareName(name Name) bool {
	n, err := p.ComputeName()
	if err != nil {
		return false
	}
	return bytes.Equal(n, name)
}

// AsymDetail returns the asymmetric parameters associated with the object. It panics if it is
// not an asymmetric key ([Public.IsAsymmetric] returns false) or if the public area is invalid
// ([mu.IsValid] returns false). The public area will be valid if it was constructed by the
// [github.com/canonical/go-tpm2/mu] package.
func (p *Public) AsymDetail() *AsymParams {
	switch p.Type {
	case ObjectTypeRSA, ObjectTypeECC:
		data := mu.MustMarshalToBytes(p)

		var t ObjectTypeId
		var nameAlg HashAlgorithmId
		var attrs ObjectAttributes
		var policy Digest
		var params *AsymParams
		if _, err := mu.UnmarshalFromBytes(data, &t, &nameAlg, &attrs, &policy, &params); err != nil {
			panic(err)
		}

		return params
	default:
		panic("invalid type")
	}
}

// Name implements [github.com/canonical/go-tpm2/objectutil.Named] and
// [github.com/canonical/go-tpm2/policyutil.Named].
//
// This computes the name from the public area. If the name cannot be computed
// then an invalid name is returned ([Name.Type] will return NameTypeInvalid).
func (p *Public) Name() Name {
	name, err := p.ComputeName()
	if err != nil {
		return Name{0, 0}
	}
	return name
}

func (p *Public) ToTemplate() (Template, error) {
	b, err := mu.MarshalToBytes(p)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal object: %v", err)
	}
	return b, nil
}

func (p *Public) isParent() bool {
	if !p.NameAlg.IsValid() {
		return false
	}
	return p.Attrs&(AttrRestricted|AttrDecrypt) == AttrRestricted|AttrDecrypt
}

// IsAsymmetric indicates that this public area is associated with an asymmetric
// key.
func (p *Public) IsAsymmetric() bool {
	return p.Type.IsAsymmetric()
}

// IsStorageParent indicates that this public area is associated with an object that can be
// a storage parent.
func (p *Public) IsStorageParent() bool {
	if !p.isParent() {
		return false
	}
	switch p.Type {
	case ObjectTypeRSA, ObjectTypeECC, ObjectTypeSymCipher:
		return true
	default:
		return false
	}
}

// IsDerivationParent indicates that this public area is associated with an object that can be
// a derivation parent.
func (p *Public) IsDerivationParent() bool {
	if !p.isParent() {
		return false
	}
	if p.Type != ObjectTypeKeyedHash {
		return false
	}
	return true
}

// Public returns a corresponding public key for the TPM public area.
// This will panic if the public area does not correspond to an asymmetric
// key.
func (p *Public) Public() crypto.PublicKey {
	switch p.Type {
	case ObjectTypeRSA:
		exp := int(p.Params.RSADetail.Exponent)
		if exp == 0 {
			exp = DefaultRSAExponent
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(p.Unique.RSA),
			E: exp}
	case ObjectTypeECC:
		return &ecdsa.PublicKey{
			Curve: p.Params.ECCDetail.CurveID.GoCurve(),
			X:     new(big.Int).SetBytes(p.Unique.ECC.X),
			Y:     new(big.Int).SetBytes(p.Unique.ECC.Y)}
	default:
		panic("object is not a public key")
	}
}

// PublicDerived is similar to Public but can be used as a template to create a derived object
// with [TPMContext.CreateLoaded].
type PublicDerived struct {
	Type       ObjectTypeId     // Type of this object
	NameAlg    HashAlgorithmId  // NameAlg is the algorithm used to compute the name of this object
	Attrs      ObjectAttributes // Object attributes
	AuthPolicy Digest           // Authorization policy for this object
	Params     *PublicParamsU   // Type specific parameters

	// Unique contains the derivation values. These take precedence over any values specified
	// in SensitiveCreate.Data when creating a derived object,
	Unique *Derive
}

// ComputeName computes the name of this object
func (p *PublicDerived) ComputeName() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	h := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(h, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	return mu.MustMarshalToBytes(p.NameAlg, mu.RawBytes(h.Sum(nil))), nil
}

// Name implements [github.com/canonical/go-tpm2/objectutil.Named] and
// [github.com/canonical/go-tpm2/policyutil.Named].
//
// This computes the name from the public area. If the name cannot be computed
// then an invalid name is returned ([Name.Type] will return NameTypeInvalid).
func (p *PublicDerived) Name() Name {
	name, err := p.ComputeName()
	if err != nil {
		return Name{0, 0}
	}
	return name
}

func (p *PublicDerived) ToTemplate() (Template, error) {
	b, err := mu.MarshalToBytes(p)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal object: %v", err)
	}
	return b, nil
}

// Template corresponds to the TPM2B_TEMPLATE type
type Template []byte

// 12.3) Private Area Structures

// PrivateVendorSpecific corresponds to the TPM2B_PRIVATE_VENDOR_SPECIFIC type.
type PrivateVendorSpecific []byte

// SensitiveCompositeU is a union type that corresponds to the TPMU_SENSITIVE_COMPOSITE
// type. The selector type is [ObjectTypeId]. The mapping of selector values to fields is
// as follows:
//   - ObjectTypeRSA: RSA
//   - ObjectTypeECC: ECC
//   - ObjectTypeKeyedHash: Bits
//   - ObjectTypeSymCipher: Sym
type SensitiveCompositeU struct {
	RSA  PrivateKeyRSA
	ECC  ECCParameter
	Bits SensitiveData
	Sym  SymKey
}

// Select implements [mu.Union].
func (s *SensitiveCompositeU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(ObjectTypeId) {
	case ObjectTypeRSA:
		return &s.RSA
	case ObjectTypeECC:
		return &s.ECC
	case ObjectTypeKeyedHash:
		return &s.Bits
	case ObjectTypeSymCipher:
		return &s.Sym
	default:
		return nil
	}
}

// Any returns the value associated with the specified object type as
// PrivateVendorSpecific.
//
// Deprecated: Use [Sensitive.AnySensitive] instead.
func (s SensitiveCompositeU) Any(t ObjectTypeId) PrivateVendorSpecific {
	switch t {
	case ObjectTypeRSA:
		return PrivateVendorSpecific(s.RSA)
	case ObjectTypeECC:
		return PrivateVendorSpecific(s.ECC)
	case ObjectTypeKeyedHash:
		return PrivateVendorSpecific(s.Bits)
	case ObjectTypeSymCipher:
		return PrivateVendorSpecific(s.Sym)
	default:
		return nil
	}
}

// Sensitive corresponds to the TPMT_SENSITIVE type.
type Sensitive struct {
	Type      ObjectTypeId         // Same as the corresponding Type in the Public object
	AuthValue Auth                 // Authorization value
	SeedValue Digest               // For a parent object, the seed value for protecting descendant objects
	Sensitive *SensitiveCompositeU // Type specific private data
}

func (s *Sensitive) AnySensitive() PrivateVendorSpecific {
	sensitive := s.Sensitive
	if sensitive == nil {
		sensitive = new(SensitiveCompositeU)
	}

	switch s.Type {
	case ObjectTypeRSA:
		return PrivateVendorSpecific(sensitive.RSA)
	case ObjectTypeECC:
		return PrivateVendorSpecific(sensitive.ECC)
	case ObjectTypeKeyedHash:
		return PrivateVendorSpecific(sensitive.Bits)
	case ObjectTypeSymCipher:
		return PrivateVendorSpecific(sensitive.Sym)
	default:
		panic("invalid object type")
	}
}

// Private corresponds to the TPM2B_PRIVATE type.
type Private []byte

// 12.4) Identity Object

// IDObject corresponds to the TPM2B_ID_OBJECT type.
type IDObject []byte

// IDObjectRaw corresponds to the TPM2B_ID_OBJECT type.
//
// Deprecated: use IDObject
type IDObjectRaw = IDObject
