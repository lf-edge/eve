// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"reflect"

	"github.com/canonical/go-tpm2/mu"
)

// This file contains types defined in section 11 (Algorithm Parameters
// and Structures) in part 2 of the library spec.

// 11.1) Symmetric

// SymKeyBitsU is a union type that corresponds to the TPMU_SYM_KEY_BITS type and is used to
// specify symmetric encryption key sizes. The selector type is [AlgorithmId]. Mapping of
// selector values to fields is as follows:
//   - AlgorithmAES: Sym
//   - AlgorithmSM4: Sym
//   - AlgorithmCamellia: Sym
//   - AlgorithmXOR: XOR
//   - AlgorithmNull: none
type SymKeyBitsU struct {
	Sym uint16
	XOR HashAlgorithmId
}

// Select implements [mu.Union].
func (b *SymKeyBitsU) Select(selector reflect.Value) interface{} {
	switch selector.Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return &b.Sym
	case AlgorithmXOR:
		return &b.XOR
	case AlgorithmNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// SymModeU is a union type that corresponds to the TPMU_SYM_MODE type. The selector
// type is [AlgorithmId]. The mapping of selector values to fields is as follows:
//   - AlgorithmAES: Sym
//   - AlgorithmSM4: Sym
//   - AlgorithmCamellia: Sym
//   - AlgorithmXOR: none
//   - AlgorithmNull: none
type SymModeU struct {
	Sym SymModeId
}

// Select implements [mu.Union].
func (m *SymModeU) Select(selector reflect.Value) interface{} {
	switch selector.Convert(reflect.TypeOf(AlgorithmId(0))).Interface().(AlgorithmId) {
	case AlgorithmAES:
		fallthrough
	case AlgorithmSM4:
		fallthrough
	case AlgorithmCamellia:
		return &m.Sym
	case AlgorithmXOR:
		fallthrough
	case AlgorithmNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// SymDef corresponds to the TPMT_SYM_DEF type, and is used to select the algorithm
// used for parameter encryption.
type SymDef struct {
	Algorithm SymAlgorithmId // Symmetric algorithm
	KeyBits   *SymKeyBitsU   // Symmetric key size
	Mode      *SymModeU      // Symmetric mode
}

// SymDefObject corresponds to the TPMT_SYM_DEF_OBJECT type, and is used to define an
// object's symmetric algorithm.
type SymDefObject struct {
	Algorithm SymObjectAlgorithmId // Symmetric algorithm
	KeyBits   *SymKeyBitsU         // Symmetric key size
	Mode      *SymModeU            // Symmetric mode
}

// SymKey corresponds to the TPM2B_SYM_KEY type.
type SymKey []byte

// SymCipherParams corresponds to the TPMS_SYMCIPHER_PARMS type, and contains the
// parameters for a symmetric object.
type SymCipherParams struct {
	Sym SymDefObject
}

// Label corresponds to the TPM2B_LABEL type.
type Label []byte

// Derive corresponds to the TPMS_DERIVE type.
type Derive struct {
	Label   Label
	Context Label
}

// SensitiveCreate corresponds to the TPMS_SENSITIVE_CREATE type and is used to define
// the values to be placed in the sensitive area of a created object.
type SensitiveCreate struct {
	UserAuth Auth          // Authorization value
	Data     SensitiveData // Secret data
}

// SensitiveData corresponds to the TPM2B_SENSITIVE_DATA type.
type SensitiveData []byte

// SchemeHash corresponds to the TPMS_SCHEME_HASH type, and is used for schemes that only
// require a hash algorithm to complete their definition.
type SchemeHash struct {
	HashAlg HashAlgorithmId // Hash algorithm used to digest the message
}

// SchemeECDAA corresponds to the TPMS_SCHEME_ECDAA type.
type SchemeECDAA struct {
	HashAlg HashAlgorithmId // Hash algorithm used to digest the message
	Count   uint16
}

// KeyedHashSchemeId corresponds to the TPMI_ALG_KEYEDHASH_SCHEME type
type KeyedHashSchemeId AlgorithmId

const (
	KeyedHashSchemeHMAC KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmHMAC) // TPM_ALG_HMAC
	KeyedHashSchemeXOR  KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmXOR)  // TPM_ALG_XOR
	KeyedHashSchemeNull KeyedHashSchemeId = KeyedHashSchemeId(AlgorithmNull) // TPM_ALG_NULL
)

// SchemeHMAC corresponds to the TPMS_SCHEME_HMAC type.
type SchemeHMAC = SchemeHash

// SchemeXOR corresponds to the TPMS_SCHEME_XOR type, and is used to define the XOR encryption
// scheme.
type SchemeXOR struct {
	HashAlg HashAlgorithmId // Hash algorithm used to digest the message
	KDF     KDFAlgorithmId  // Hash algorithm used for the KDF
}

// SchemeKeyedHashU is a union type that corresponds to the TPMU_SCHEME_KEYED_HASH type.
// The selector type is [KeyedHashSchemeId]. The mapping of selector values to fields is
// as follows:
//   - KeyedHashSchemeHMAC: HMAC
//   - KeyedHashSchemeXOR: XOR
//   - KeyedHashSchemeNull: none
type SchemeKeyedHashU struct {
	HMAC *SchemeHMAC
	XOR  *SchemeXOR
}

// Select implements [mu.Union].
func (d *SchemeKeyedHashU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(KeyedHashSchemeId) {
	case KeyedHashSchemeHMAC:
		return &d.HMAC
	case KeyedHashSchemeXOR:
		return &d.XOR
	case KeyedHashSchemeNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// KeyedHashScheme corresponds to the TPMT_KEYEDHASH_SCHEME type.
type KeyedHashScheme struct {
	Scheme  KeyedHashSchemeId // Scheme selector
	Details *SchemeKeyedHashU // Scheme specific parameters
}

// 11.2 Assymetric

// 11.2.1 Signing Schemes

type SigSchemeRSASSA = SchemeHash
type SigSchemeRSAPSS = SchemeHash
type SigSchemeECDSA = SchemeHash
type SigSchemeECDAA = SchemeECDAA
type SigSchemeSM2 = SchemeHash
type SigSchemeECSchnorr = SchemeHash

// SigSchemeU is a union type that corresponds to the TPMU_SIG_SCHEME type. The
// selector type is [SigSchemeId]. The mapping of selector value to fields is as follows:
//   - SigSchemeAlgRSASSA: RSASSA
//   - SigSchemeAlgRSAPSS: RSAPSS
//   - SigSchemeAlgECDSA: ECDSA
//   - SigSchemeAlgECDAA: ECDAA
//   - SigSchemeAlgSM2: SM2
//   - SigSchemeAlgECSchnorr: ECSchnorr
//   - SigSchemeAlgHMAC: HMAC
//   - SigSchemeAlgNull: none
type SigSchemeU struct {
	RSASSA    *SigSchemeRSASSA
	RSAPSS    *SigSchemeRSAPSS
	ECDSA     *SigSchemeECDSA
	ECDAA     *SigSchemeECDAA
	SM2       *SigSchemeSM2
	ECSchnorr *SigSchemeECSchnorr
	HMAC      *SchemeHMAC
}

// Select implements [mu.Union].
func (s *SigSchemeU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return &s.RSASSA
	case SigSchemeAlgRSAPSS:
		return &s.RSAPSS
	case SigSchemeAlgECDSA:
		return &s.ECDSA
	case SigSchemeAlgECDAA:
		return &s.ECDAA
	case SigSchemeAlgSM2:
		return &s.SM2
	case SigSchemeAlgECSchnorr:
		return &s.ECSchnorr
	case SigSchemeAlgHMAC:
		return &s.HMAC
	case SigSchemeAlgNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// Any returns the signature scheme associated with scheme as a *SchemeHash.
// It panics if the specified scheme is invalid ([SigSchemeId.IsValid] returns
// false), or the appropriate field isn't set.
//
// Deprecated: Use [SigScheme.AnyDetails] instead.
func (s SigSchemeU) Any(scheme SigSchemeId) *SchemeHash {
	switch scheme {
	case SigSchemeAlgRSASSA:
		return (*SchemeHash)(&(*s.RSASSA))
	case SigSchemeAlgRSAPSS:
		return (*SchemeHash)(&(*s.RSAPSS))
	case SigSchemeAlgECDSA:
		return (*SchemeHash)(&(*s.ECDSA))
	case SigSchemeAlgECDAA:
		return &SchemeHash{HashAlg: s.ECDAA.HashAlg}
	case SigSchemeAlgSM2:
		return (*SchemeHash)(&(*s.SM2))
	case SigSchemeAlgECSchnorr:
		return (*SchemeHash)(&(*s.ECSchnorr))
	case SigSchemeAlgHMAC:
		return (*SchemeHash)(&(*s.HMAC))
	default:
		panic("invalid scheme")
	}
}

// SigScheme corresponds to the TPMT_SIG_SCHEME type.
type SigScheme struct {
	Scheme  SigSchemeId // Scheme selector
	Details *SigSchemeU // Scheme specific parameters
}

// AnyDetails returns the details of the signature scheme. If the scheme is [SigSchemeAlgNull],
// then nil is returned. If the scheme is not otherwise valid, it will panic.
func (s *SigScheme) AnyDetails() *SchemeHash {
	switch {
	case s.Scheme == SigSchemeAlgNull:
		return nil
	case !s.Scheme.IsValid():
		panic("invalid scheme")
	}

	data := mu.MustMarshalToBytes(s)

	var scheme SigSchemeId
	var details *SchemeHash
	if _, err := mu.UnmarshalFromBytes(data, &scheme, &details); err != nil {
		panic(err)
	}

	return details
}

// 11.2.2 Encryption Schemes

type EncSchemeRSAES = Empty
type EncSchemeOAEP = SchemeHash

type KeySchemeECDH = SchemeHash
type KeySchemeECMQV = SchemeHash

// 11.2.3 Key Derivation Schemes

type SchemeMGF1 = SchemeHash
type SchemeKDF1_SP800_56A = SchemeHash
type SchemeKDF2 = SchemeHash
type SchemeKDF1_SP800_108 = SchemeHash

// KDFSchemeU is a union type that corresponds to the TPMU_KDF_SCHEME
// type. The selector type is [KDFAlgorithmId]. The mapping of selector
// value to field is as follows:
//   - KDFAlgorithmMGF1: MGF1
//   - KDFAlgorithmKDF1_SP800_56A: KDF1_SP800_56A
//   - KDFAlgorithmKDF2: KDF2
//   - KDFAlgorithmKDF1_SP800_108: KDF1_SP800_108
//   - KDFAlgorithmNull: none
type KDFSchemeU struct {
	MGF1           *SchemeMGF1
	KDF1_SP800_56A *SchemeKDF1_SP800_56A
	KDF2           *SchemeKDF2
	KDF1_SP800_108 *SchemeKDF1_SP800_108
}

// Select implements [mu.Union].
func (s *KDFSchemeU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(KDFAlgorithmId) {
	case KDFAlgorithmMGF1:
		return &s.MGF1
	case KDFAlgorithmKDF1_SP800_56A:
		return &s.KDF1_SP800_56A
	case KDFAlgorithmKDF2:
		return &s.KDF2
	case KDFAlgorithmKDF1_SP800_108:
		return &s.KDF1_SP800_108
	case KDFAlgorithmNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// KDFScheme corresponds to the TPMT_KDF_SCHEME type.
type KDFScheme struct {
	Scheme  KDFAlgorithmId // Scheme selector
	Details *KDFSchemeU    // Scheme specific parameters.
}

// AsymSchemeId corresponds to the TPMI_ALG_ASYM_SCHEME type
type AsymSchemeId AlgorithmId

// IsValid determines if the scheme is a valid asymmetric scheme.
func (s AsymSchemeId) IsValid() bool {
	switch s {
	case AsymSchemeRSASSA:
	case AsymSchemeRSAES:
	case AsymSchemeRSAPSS:
	case AsymSchemeOAEP:
	case AsymSchemeECDSA:
	case AsymSchemeECDH:
	case AsymSchemeECDAA:
	case AsymSchemeSM2:
	case AsymSchemeECSchnorr:
	case AsymSchemeECMQV:
	default:
		return false
	}
	return true
}

// HasDigest determines if the asymmetric scheme is associated with
// a digest algorithm.
func (s AsymSchemeId) HasDigest() bool {
	switch s {
	case AsymSchemeRSASSA:
	case AsymSchemeRSAPSS:
	case AsymSchemeOAEP:
	case AsymSchemeECDSA:
	case AsymSchemeECDH:
	case AsymSchemeECDAA:
	case AsymSchemeSM2:
	case AsymSchemeECSchnorr:
	case AsymSchemeECMQV:
	default:
		return false
	}
	return true
}

const (
	AsymSchemeNull      AsymSchemeId = AsymSchemeId(AlgorithmNull)      // TPM_ALG_NULL
	AsymSchemeRSASSA    AsymSchemeId = AsymSchemeId(AlgorithmRSASSA)    // TPM_ALG_RSASSA
	AsymSchemeRSAES     AsymSchemeId = AsymSchemeId(AlgorithmRSAES)     // TPM_ALG_RSAES
	AsymSchemeRSAPSS    AsymSchemeId = AsymSchemeId(AlgorithmRSAPSS)    // TPM_ALG_RSAPSS
	AsymSchemeOAEP      AsymSchemeId = AsymSchemeId(AlgorithmOAEP)      // TPM_ALG_OAEP
	AsymSchemeECDSA     AsymSchemeId = AsymSchemeId(AlgorithmECDSA)     // TPM_ALG_ECDSA
	AsymSchemeECDH      AsymSchemeId = AsymSchemeId(AlgorithmECDH)      // TPM_ALG_ECDH
	AsymSchemeECDAA     AsymSchemeId = AsymSchemeId(AlgorithmECDAA)     // TPM_ALG_ECDAA
	AsymSchemeSM2       AsymSchemeId = AsymSchemeId(AlgorithmSM2)       // TPM_ALG_SM2
	AsymSchemeECSchnorr AsymSchemeId = AsymSchemeId(AlgorithmECSchnorr) // TPM_ALG_ECSCHNORR
	AsymSchemeECMQV     AsymSchemeId = AsymSchemeId(AlgorithmECMQV)     // TPM_ALG_ECMQV
)

// AsymSchemeU is a union type that corresponds to the TPMU_ASYM_SCHEME type. The
// selector type is [AsymSchemeId]. The mapping of selector values to fields is as follows:
//   - AsymSchemeRSASSA: RSASSA
//   - AsymSchemeRSAES: RSAES
//   - AsymSchemeRSAPSS: RSAPSS
//   - AsymSchemeOAEP: OAEP
//   - AsymSchemeECDSA: ECDSA
//   - AsymSchemeECDH: ECDH
//   - AsymSchemeECDAA: ECDAA
//   - AsymSchemeSM2: SM2
//   - AsymSchemeECSchnorr: ECSchnorr
//   - AsymSchemeECMQV: ECMQV
//   - AsymSchemeNull: none
type AsymSchemeU struct {
	RSASSA    *SigSchemeRSASSA
	RSAES     *EncSchemeRSAES
	RSAPSS    *SigSchemeRSAPSS
	OAEP      *EncSchemeOAEP
	ECDSA     *SigSchemeECDSA
	ECDH      *KeySchemeECDH
	ECDAA     *SigSchemeECDAA
	SM2       *SigSchemeSM2
	ECSchnorr *SigSchemeECSchnorr
	ECMQV     *KeySchemeECMQV
}

// Select implements [mu.Union].
func (s *AsymSchemeU) Select(selector reflect.Value) interface{} {
	switch selector.Convert(reflect.TypeOf(AsymSchemeId(0))).Interface().(AsymSchemeId) {
	case AsymSchemeRSASSA:
		return &s.RSASSA
	case AsymSchemeRSAES:
		return &s.RSAES
	case AsymSchemeRSAPSS:
		return &s.RSAPSS
	case AsymSchemeOAEP:
		return &s.OAEP
	case AsymSchemeECDSA:
		return &s.ECDSA
	case AsymSchemeECDH:
		return &s.ECDH
	case AsymSchemeECDAA:
		return &s.ECDAA
	case AsymSchemeSM2:
		return &s.SM2
	case AsymSchemeECSchnorr:
		return &s.ECSchnorr
	case AsymSchemeECMQV:
		return &s.ECMQV
	case AsymSchemeNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// Any returns the asymmetric scheme associated with scheme as a *SchemeHash.
// It panics if the specified scheme does not have an associated digest algorithm
// ([AsymSchemeId.HasDigest] returns false), or if the appropriate field isn't set.
//
// Deprecated: Use [AsymScheme.AnyDetails], [RSAScheme.AnyDetails] or
// [ECCScheme.AnyDetails] instead.
func (s AsymSchemeU) Any(scheme AsymSchemeId) *SchemeHash {
	if !scheme.HasDigest() {
		panic("invalid asymmetric scheme")
	}

	switch scheme {
	case AsymSchemeRSASSA:
		return (*SchemeHash)(&(*s.RSASSA))
	case AsymSchemeRSAPSS:
		return (*SchemeHash)(&(*s.RSAPSS))
	case AsymSchemeOAEP:
		return (*SchemeHash)(&(*s.OAEP))
	case AsymSchemeECDSA:
		return (*SchemeHash)(&(*s.ECDSA))
	case AsymSchemeECDH:
		return (*SchemeHash)(&(*s.ECDH))
	case AsymSchemeECDAA:
		return &SchemeHash{HashAlg: s.ECDAA.HashAlg}
	case AsymSchemeSM2:
		return (*SchemeHash)(&(*s.SM2))
	case AsymSchemeECSchnorr:
		return (*SchemeHash)(&(*s.ECSchnorr))
	case AsymSchemeECMQV:
		return (*SchemeHash)(&(*s.ECMQV))
	default:
		panic("not reached")
	}
}

// AsymScheme corresponds to the TPMT_ASYM_SCHEME type.
type AsymScheme struct {
	Scheme  AsymSchemeId // Scheme selector
	Details *AsymSchemeU // Scheme specific parameters
}

// AnyDetails returns the details of the asymmetric scheme. If the scheme is [AsymSchemeNull],
// or doesn't have a digest, then nil is returned. If the scheme is not otherwise valid, it
// will panic.
func (s *AsymScheme) AnyDetails() *SchemeHash {
	switch {
	case s.Scheme == AsymSchemeNull:
		return nil
	case !s.Scheme.HasDigest():
		return nil
	case !s.Scheme.IsValid():
		panic("invalid scheme")
	}

	data := mu.MustMarshalToBytes(s)

	var scheme AsymSchemeId
	var details *SchemeHash
	if _, err := mu.UnmarshalFromBytes(data, &scheme, &details); err != nil {
		panic(err)
	}

	return details
}

// 11.2.4 RSA

// RSASchemeId corresponds to the TPMI_ALG_RSA_SCHEME type.
type RSASchemeId AsymSchemeId

const (
	RSASchemeNull   RSASchemeId = RSASchemeId(AlgorithmNull)   // TPM_ALG_NULL
	RSASchemeRSASSA RSASchemeId = RSASchemeId(AlgorithmRSASSA) // TPM_ALG_RSASSA
	RSASchemeRSAES  RSASchemeId = RSASchemeId(AlgorithmRSAES)  // TPM_ALG_RSAES
	RSASchemeRSAPSS RSASchemeId = RSASchemeId(AlgorithmRSAPSS) // TPM_ALG_RSAPSS
	RSASchemeOAEP   RSASchemeId = RSASchemeId(AlgorithmOAEP)   // TPM_ALG_OAEP
)

// RSAScheme corresponds to the TPMT_RSA_SCHEME type.
type RSAScheme struct {
	Scheme  RSASchemeId  // Scheme selector
	Details *AsymSchemeU // Scheme specific parameters.
}

// AnyDetails returns the details of the RSA scheme. If the scheme is [RSASchemeNull],
// or doesn't have a digest, then nil is returned. If the scheme is not otherwise valid, it
// will panic.
func (s *RSAScheme) AnyDetails() *SchemeHash {
	scheme := AsymScheme{
		Scheme:  AsymSchemeId(s.Scheme),
		Details: s.Details}
	return scheme.AnyDetails()
}

// PublicKeyRSA corresponds to the TPM2B_PUBLIC_KEY_RSA type.
type PublicKeyRSA []byte

// PrivateKeyRSA corresponds to the TPM2B_PRIVATE_KEY_RSA type.
type PrivateKeyRSA []byte

// 11.2.5 ECC

// ECCParameter corresponds to the TPM2B_ECC_PARAMETER type.
type ECCParameter []byte

// ECCPoint corresponds to the TPMS_ECC_POINT type, and contains the coordinates
// that define an ECC point.
type ECCPoint struct {
	X ECCParameter // X coordinate
	Y ECCParameter // Y coordinate
}

// ECCSchemeId corresponds to the TPMI_ALG_ECC_SCHEME type.
type ECCSchemeId AsymSchemeId

const (
	ECCSchemeNull      ECCSchemeId = ECCSchemeId(AlgorithmNull)      // TPM_ALG_NULL
	ECCSchemeECDSA     ECCSchemeId = ECCSchemeId(AlgorithmECDSA)     // TPM_ALG_ECDSA
	ECCSchemeECDH      ECCSchemeId = ECCSchemeId(AlgorithmECDH)      // TPM_ALG_ECDH
	ECCSchemeECDAA     ECCSchemeId = ECCSchemeId(AlgorithmECDAA)     // TPM_ALG_ECDAA
	ECCSchemeSM2       ECCSchemeId = ECCSchemeId(AlgorithmSM2)       // TPM_ALG_SM2
	ECCSchemeECSchnorr ECCSchemeId = ECCSchemeId(AlgorithmECSchnorr) // TPM_ALG_ECSCHNORR
	ECCSchemeECMQV     ECCSchemeId = ECCSchemeId(AlgorithmECMQV)     // TPM_ALG_ECMQV
)

// ECCScheme corresponds to the TPMT_ECC_SCHEME type.
type ECCScheme struct {
	Scheme  ECCSchemeId  // Scheme selector
	Details *AsymSchemeU // Scheme specific parameters.
}

// AnyDetails returns the details of the ECC scheme. If the scheme is [ECCSchemeNull]
// then nil is returned. If the scheme is not otherwise valid, it will panic.
func (s *ECCScheme) AnyDetails() *SchemeHash {
	scheme := AsymScheme{
		Scheme:  AsymSchemeId(s.Scheme),
		Details: s.Details}
	return scheme.AnyDetails()
}

// 11.3 Signatures

// SignatureRSA corresponds to the TPMS_SIGNATURE_RSA type.
type SignatureRSA struct {
	Hash HashAlgorithmId // Hash algorithm used to digest the message
	Sig  PublicKeyRSA    // Signature, which is the same size as the public key
}

// SignatureECC corresponds to the TPMS_SIGNATURE_ECC type.
type SignatureECC struct {
	Hash       HashAlgorithmId // Hash is the digest algorithm used in the signature process
	SignatureR ECCParameter
	SignatureS ECCParameter
}

type SignatureRSASSA = SignatureRSA
type SignatureRSAPSS = SignatureRSA
type SignatureECDSA = SignatureECC
type SignatureECDAA = SignatureECC
type SignatureSM2 = SignatureECC
type SignatureECSchnorr = SignatureECC

// SignatureU is a union type that corresponds to TPMU_SIGNATURE. The selector
// type is [SigSchemeId]. The mapping of selector values to fields is as follows:
//   - SigSchemeAlgRSASSA: RSASSA
//   - SigSchemeAlgRSAPSS: RSAPSS
//   - SigSchemeAlgECDSA: ECDSA
//   - SigSchemeAlgECDAA: ECDAA
//   - SigSchemeAlgSM2: SM2
//   - SigSchemeAlgECSchnorr: ECSchnorr
//   - SigSchemeAlgHMAC: HMAC
//   - SigSchemeAlgNull: none
type SignatureU struct {
	RSASSA    *SignatureRSASSA
	RSAPSS    *SignatureRSAPSS
	ECDSA     *SignatureECDSA
	ECDAA     *SignatureECDAA
	SM2       *SignatureSM2
	ECSchnorr *SignatureECSchnorr
	HMAC      *TaggedHash
}

// Select implements [mu.Union].
func (s *SignatureU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(SigSchemeId) {
	case SigSchemeAlgRSASSA:
		return &s.RSASSA
	case SigSchemeAlgRSAPSS:
		return &s.RSAPSS
	case SigSchemeAlgECDSA:
		return &s.ECDSA
	case SigSchemeAlgECDAA:
		return &s.ECDAA
	case SigSchemeAlgSM2:
		return &s.SM2
	case SigSchemeAlgECSchnorr:
		return &s.ECSchnorr
	case SigSchemeAlgHMAC:
		return &s.HMAC
	case SigSchemeAlgNull:
		return mu.NilUnionValue
	default:
		return nil
	}
}

// Any returns the signature associated with scheme as a *SchemeHash. It
// panics if scheme is [SigSchemeAlgNull] or the appropriate field isn't
// set.
//
// Deprecated: Use [Signature.Digest] instead.
func (s SignatureU) Any(scheme SigSchemeId) *SchemeHash {
	if !scheme.IsValid() {
		panic("invalid signature scheme")
	}

	switch scheme {
	case SigSchemeAlgRSASSA:
		return &SchemeHash{HashAlg: s.RSASSA.Hash}
	case SigSchemeAlgRSAPSS:
		return &SchemeHash{HashAlg: s.RSAPSS.Hash}
	case SigSchemeAlgECDSA:
		return &SchemeHash{HashAlg: s.ECDSA.Hash}
	case SigSchemeAlgECDAA:
		return &SchemeHash{HashAlg: s.ECDAA.Hash}
	case SigSchemeAlgSM2:
		return &SchemeHash{HashAlg: s.SM2.Hash}
	case SigSchemeAlgECSchnorr:
		return &SchemeHash{HashAlg: s.ECSchnorr.Hash}
	case SigSchemeAlgHMAC:
		return &SchemeHash{HashAlg: s.HMAC.HashAlg}
	default:
		panic("not reached")
	}
}

// Signature corresponds to the TPMT_SIGNATURE type which represents a
// signature.
type Signature struct {
	SigAlg    SigSchemeId // Signature algorithm
	Signature *SignatureU // Actual signature
}

// HashAlg returns the digest algorithm used to create the signature. This will panic if
// the signature algorithm is not valid ([SigSchemeId.IsValid] returns false) or if the signature
// structure is otherwise invalid ([mu.IsValid] returns false). The signature structure will be
// valid if it was constructed by the [github.com/canonical/go-tpm2/mu] package.
func (s *Signature) HashAlg() HashAlgorithmId {
	if !s.SigAlg.IsValid() {
		panic("invalid scheme")
	}

	data := mu.MustMarshalToBytes(s)

	var alg SigSchemeId
	var hashAlg HashAlgorithmId
	if _, err := mu.UnmarshalFromBytes(data, &alg, &hashAlg); err != nil {
		panic(err)
	}

	return hashAlg
}

// 11.4) Key/Secret Exchange

// EncryptedSecret corresponds to the TPM2B_ENCRYPTED_SECRET type.
type EncryptedSecret []byte
