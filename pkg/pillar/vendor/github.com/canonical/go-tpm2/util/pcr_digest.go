// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/policyutil"
)

// ComputePCRDigest computes a digest using the specified algorithm from the provided set of PCR
// values and the provided PCR selections. The digest is computed the same way as PCRComputeCurrentDigest
// as defined in the TPM reference implementation. It is most useful for computing an input to
// [tpm2.TPMContext.PolicyPCR] or [TrialAuthPolicy.PolicyPCR], and for validating quotes and creation data.
//
// Deprecated: use [policyutil.ComputePCRDigest].
func ComputePCRDigest(alg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList, values tpm2.PCRValues) (tpm2.Digest, error) {
	return policyutil.ComputePCRDigest(alg, pcrs, values)
}

// ComputePCRDigestFromAllValues computes a digest using the specified algorithm from all of the
// provided set of PCR values. The digest is computed the same way as PCRComputeCurrentDigest as
// defined in the TPM reference implementation. It returns the PCR selection associated with the
// computed digest.
//
// Deprecated: use [policyutil.ComputePCRDigestFromAllValues].
func ComputePCRDigestFromAllValues(alg tpm2.HashAlgorithmId, values tpm2.PCRValues) (tpm2.PCRSelectionList, tpm2.Digest, error) {
	return policyutil.ComputePCRDigestFromAllValues(alg, values)
}
