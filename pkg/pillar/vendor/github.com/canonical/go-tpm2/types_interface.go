// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto"
	"crypto/cipher"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"hash"
)

// This file contains types defined in section 9 (Interface Types) in
// part 2 of the library spec. Interface types are used by the TPM
// implementation to check that a value is appropriate for the context
// during unmarshalling. This package has limited support for some
// algorithm interfaces by defining context specific algorithm types
// based on the AlgorithmId type. Note that no interface types with
// TPM_HANDLE as the underlying type are supported, as this package
// doesn't use handles in most APIs.

var _ crypto.SignerOpts = HashAlgorithmId(0)

// HashAlgorithmId corresponds to the TPMI_ALG_HASH type
type HashAlgorithmId AlgorithmId

// GetHash returns the equivalent crypto.Hash value for this algorithm if one
// exists, and 0 if one does not exist.
func (a HashAlgorithmId) GetHash() crypto.Hash {
	switch a {
	case HashAlgorithmSHA1:
		return crypto.SHA1
	case HashAlgorithmSHA256:
		return crypto.SHA256
	case HashAlgorithmSHA384:
		return crypto.SHA384
	case HashAlgorithmSHA512:
		return crypto.SHA512
	case HashAlgorithmSHA3_256:
		return crypto.SHA3_256
	case HashAlgorithmSHA3_384:
		return crypto.SHA3_384
	case HashAlgorithmSHA3_512:
		return crypto.SHA3_512
	default:
		return 0
	}
}

// HashFunc implements [crypto.SignerOpts.HashFunc].
//
// This will return 0 if the algorithm does not have a corresponding
// crypto.Hash.
func (a HashAlgorithmId) HashFunc() crypto.Hash {
	return a.GetHash()
}

// IsValid determines if the digest algorithm is valid. This
// should be checked by code that deserializes an algorithm before
// calling Size if it does not want to panic.
//
// Note that this does not guarantee that the [HashAlgorithmId.GetHash]
// will return a valid corresponding [crypto.Hash].
func (a HashAlgorithmId) IsValid() bool {
	switch a {
	case HashAlgorithmSHA1:
	case HashAlgorithmSHA256:
	case HashAlgorithmSHA384:
	case HashAlgorithmSHA512:
	case HashAlgorithmSM3_256:
	case HashAlgorithmSHA3_256:
	case HashAlgorithmSHA3_384:
	case HashAlgorithmSHA3_512:
	default:
		return false
	}

	return true
}

// Available determines if the TPM digest algorithm has an equivalent go
// [crypto.Hash] that is linked into the current binary.
func (a HashAlgorithmId) Available() bool {
	return a.GetHash().Available()
}

// NewHash constructs a new hash.Hash implementation for this algorithm.
// It will panic if [HashAlgorithmId.Available] returns false.
func (a HashAlgorithmId) NewHash() hash.Hash {
	return a.GetHash().New()
}

// Size returns the size of the algorithm. It will panic if
// [HashAlgorithmId.IsValid] returns false.
func (a HashAlgorithmId) Size() int {
	switch a {
	case HashAlgorithmSHA1:
		return 20
	case HashAlgorithmSHA256:
		return 32
	case HashAlgorithmSHA384:
		return 48
	case HashAlgorithmSHA512:
		return 64
	case HashAlgorithmSM3_256:
		return 32
	case HashAlgorithmSHA3_256:
		return 32
	case HashAlgorithmSHA3_384:
		return 48
	case HashAlgorithmSHA3_512:
		return 64
	default:
		panic("unknown hash algorithm")
	}
}

const (
	HashAlgorithmNull     HashAlgorithmId = HashAlgorithmId(AlgorithmNull)     // TPM_ALG_NULL
	HashAlgorithmSHA1     HashAlgorithmId = HashAlgorithmId(AlgorithmSHA1)     // TPM_ALG_SHA1
	HashAlgorithmSHA256   HashAlgorithmId = HashAlgorithmId(AlgorithmSHA256)   // TPM_ALG_SHA256
	HashAlgorithmSHA384   HashAlgorithmId = HashAlgorithmId(AlgorithmSHA384)   // TPM_ALG_SHA384
	HashAlgorithmSHA512   HashAlgorithmId = HashAlgorithmId(AlgorithmSHA512)   // TPM_ALG_SHA512
	HashAlgorithmSM3_256  HashAlgorithmId = HashAlgorithmId(AlgorithmSM3_256)  // TPM_ALG_SM3_256
	HashAlgorithmSHA3_256 HashAlgorithmId = HashAlgorithmId(AlgorithmSHA3_256) // TPM_ALG_SHA3_256
	HashAlgorithmSHA3_384 HashAlgorithmId = HashAlgorithmId(AlgorithmSHA3_384) // TPM_ALG_SHA3_384
	HashAlgorithmSHA3_512 HashAlgorithmId = HashAlgorithmId(AlgorithmSHA3_512) // TPM_ALG_SHA3_512
)

// SymAlgorithmId corresponds to the TPMI_ALG_SYM type
type SymAlgorithmId AlgorithmId

// IsValidBlockCipher determines if this algorithm is a valid block cipher.
// This should be checked by code that deserializes an algorithm before
// calling [SymAlgorithmId.BlockSize] if it does not want to panic.
func (a SymAlgorithmId) IsValidBlockCipher() bool {
	switch a {
	case SymAlgorithmTDES:
	case SymAlgorithmAES:
	case SymAlgorithmSM4:
	case SymAlgorithmCamellia:
	default:
		return false
	}
	return true
}

// Available indicates whether the TPM symmetric cipher has a registered
// go implementation.
func (a SymAlgorithmId) Available() bool {
	_, ok := symmetricAlgs[a]
	return ok
}

// BlockSize indicates the block size of the symmetric cipher. This will
// panic if [SymAlgorithmId.IsValidBlockCipher] returns false.
func (a SymAlgorithmId) BlockSize() int {
	switch a {
	case SymAlgorithmTDES:
		return 8
	case SymAlgorithmAES:
		return 16
	case SymAlgorithmSM4:
		return 16
	case SymAlgorithmCamellia:
		return 16
	default:
		panic("invalid symmetric algorithm")
	}
}

// NewCipher constructs a new symmetric cipher with the supplied key, if
// there is a go implementation registered.
func (a SymAlgorithmId) NewCipher(key []byte) (cipher.Block, error) {
	if !a.IsValidBlockCipher() {
		return nil, fmt.Errorf("%v is not a valid block cipher", a)
	}
	fn, ok := symmetricAlgs[a]
	if !ok {
		return nil, fmt.Errorf("unavailable cipher %v", a)
	}
	return fn(key)
}

const (
	SymAlgorithmTDES     SymAlgorithmId = SymAlgorithmId(AlgorithmTDES)     // TPM_ALG_TDES
	SymAlgorithmAES      SymAlgorithmId = SymAlgorithmId(AlgorithmAES)      // TPM_ALG_AES
	SymAlgorithmXOR      SymAlgorithmId = SymAlgorithmId(AlgorithmXOR)      // TPM_ALG_XOR
	SymAlgorithmNull     SymAlgorithmId = SymAlgorithmId(AlgorithmNull)     // TPM_ALG_NULL
	SymAlgorithmSM4      SymAlgorithmId = SymAlgorithmId(AlgorithmSM4)      // TPM_ALG_SM4
	SymAlgorithmCamellia SymAlgorithmId = SymAlgorithmId(AlgorithmCamellia) // TPM_ALG_CAMELLIA
)

// SymObjectAlgorithmId corresponds to the TPMI_ALG_SYM_OBJECT type
type SymObjectAlgorithmId AlgorithmId

// IsValidBlockCipher determines if this algorithm is a valid block cipher.
// This should be checked by code that deserializes an algorithm before
// calling [SymObjectAlgorithmId.BlockSize] if it does not want to panic.
func (a SymObjectAlgorithmId) IsValidBlockCipher() bool {
	return SymAlgorithmId(a).IsValidBlockCipher()
}

// Available indicates whether the TPM symmetric cipher has a registered
// go implementation.
func (a SymObjectAlgorithmId) Available() bool {
	return SymAlgorithmId(a).Available()
}

// BlockSize indicates the block size of the symmetric cipher. This will
// panic if [SymObjectAlgorithmId.IsValidBlockCipher] returns false.
func (a SymObjectAlgorithmId) BlockSize() int {
	return SymAlgorithmId(a).BlockSize()
}

// NewCipher constructs a new symmetric cipher with the supplied key, if
// there is a go implementation registered.
func (a SymObjectAlgorithmId) NewCipher(key []byte) (cipher.Block, error) {
	return SymAlgorithmId(a).NewCipher(key)
}

const (
	SymObjectAlgorithmAES      SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmAES)      // TPM_ALG_AES
	SymObjectAlgorithmNull     SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmNull)     // TPM_ALG_NULL
	SymObjectAlgorithmSM4      SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmSM4)      // TPM_ALG_SM4
	SymObjectAlgorithmCamellia SymObjectAlgorithmId = SymObjectAlgorithmId(AlgorithmCamellia) // TPM_ALG_CAMELLIA
)

// SymModeId corresponds to the TPMI_ALG_SYM_MODE type
type SymModeId AlgorithmId

const (
	SymModeNull SymModeId = SymModeId(AlgorithmNull) // TPM_ALG_NULL
	SymModeCTR  SymModeId = SymModeId(AlgorithmCTR)  // TPM_ALG_CTR
	SymModeOFB  SymModeId = SymModeId(AlgorithmOFB)  // TPM_ALG_OFB
	SymModeCBC  SymModeId = SymModeId(AlgorithmCBC)  // TPM_ALG_CBC
	SymModeCFB  SymModeId = SymModeId(AlgorithmCFB)  // TPM_ALG_CFB
	SymModeECB  SymModeId = SymModeId(AlgorithmECB)  // TPM_ALG_ECB
)

// KDFAlgorithmId corresppnds to the TPMI_ALG_KDF type
type KDFAlgorithmId AlgorithmId

const (
	KDFAlgorithmMGF1           KDFAlgorithmId = KDFAlgorithmId(AlgorithmMGF1)           // TPM_ALG_MGF1
	KDFAlgorithmNull           KDFAlgorithmId = KDFAlgorithmId(AlgorithmNull)           // TPM_ALG_NULL
	KDFAlgorithmKDF1_SP800_56A KDFAlgorithmId = KDFAlgorithmId(AlgorithmKDF1_SP800_56A) // TPM_ALG_KDF1_SP800_56A
	KDFAlgorithmKDF2           KDFAlgorithmId = KDFAlgorithmId(AlgorithmKDF2)           // TPM_ALG_KDF2
	KDFAlgorithmKDF1_SP800_108 KDFAlgorithmId = KDFAlgorithmId(AlgorithmKDF1_SP800_108) // TPM_ALG_KDF1_SP800_108
)

// SigSchemeId corresponds to the TPMI_ALG_SIG_SCHEME type
type SigSchemeId AlgorithmId

// IsValid determines if the scheme is a valid signature scheme.
func (s SigSchemeId) IsValid() bool {
	switch s {
	case SigSchemeAlgHMAC:
	case SigSchemeAlgRSASSA:
	case SigSchemeAlgRSAPSS:
	case SigSchemeAlgECDSA:
	case SigSchemeAlgECDAA:
	case SigSchemeAlgSM2:
	case SigSchemeAlgECSchnorr:
	default:
		return false
	}
	return true
}

const (
	SigSchemeAlgHMAC      SigSchemeId = SigSchemeId(AlgorithmHMAC)      // TPM_ALG_HMAC
	SigSchemeAlgNull      SigSchemeId = SigSchemeId(AlgorithmNull)      // TPM_ALG_NULL
	SigSchemeAlgRSASSA    SigSchemeId = SigSchemeId(AlgorithmRSASSA)    // TPM_ALG_RSASSA
	SigSchemeAlgRSAPSS    SigSchemeId = SigSchemeId(AlgorithmRSAPSS)    // TPM_ALG_RSAPSS
	SigSchemeAlgECDSA     SigSchemeId = SigSchemeId(AlgorithmECDSA)     // TPM_ALG_ECDSA
	SigSchemeAlgECDAA     SigSchemeId = SigSchemeId(AlgorithmECDAA)     // TPM_ALG_ECDAA
	SigSchemeAlgSM2       SigSchemeId = SigSchemeId(AlgorithmSM2)       // TPM_ALG_SM2
	SigSchemeAlgECSchnorr SigSchemeId = SigSchemeId(AlgorithmECSchnorr) // TPM_ALG_ECSCHNORR
)
