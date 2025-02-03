// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package cryptutil

import (
	"github.com/canonical/go-tpm2"
	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
)

// KDFa performs key derivation using the counter mode described in SP800-108
// and HMAC as the PRF.
//
// This will panic if hashAlg is not available.
func KDFa(hashAlg tpm2.HashAlgorithmId, key, label, contextU, contextV []byte, sizeInBits int) []byte {
	return internal_crypt.KDFa(hashAlg.GetHash(), key, label, contextU, contextV, sizeInBits)
}

// KDFe performs key derivation using the "Concatenation Key Derivation Function
// (Approved Alternative 1) in the original version of SP800-56A.
//
// This will panic if hashAlg is not available.
func KDFe(hashAlg tpm2.HashAlgorithmId, z, label, partyUInfo, partyVInfo []byte, sizeInBits int) []byte {
	return internal_crypt.KDFe(hashAlg.GetHash(), z, label, partyUInfo, partyVInfo, sizeInBits)
}
