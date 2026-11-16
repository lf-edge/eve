// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypto

import (
	"crypto"

	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
)

// KDFa performs key derivation using the counter mode described in SP800-108
// and HMAC as the PRF.
//
// This will panic if hashAlg is not available.
//
// Deprecated: Use [github.com/canonical/go-tpm2/cryptutil.KDFa].
func KDFa(hashAlg crypto.Hash, key, label, contextU, contextV []byte, sizeInBits int) []byte {
	return internal_crypt.KDFa(hashAlg, key, label, contextU, contextV, sizeInBits)
}

// KDFe performs key derivation using the "Concatenation Key Derivation Function
// (Approved Alternative 1) in the original version of SP800-56A.
//
// This will panic if hashAlg is not available.
//
// Deprecated: Use [github.com/canonical/go-tpm2/cryptutil.KDFe].
func KDFe(hashAlg crypto.Hash, z, label, partyUInfo, partyVInfo []byte, sizeInBits int) []byte {
	return internal_crypt.KDFe(hashAlg, z, label, partyUInfo, partyVInfo, sizeInBits)
}
