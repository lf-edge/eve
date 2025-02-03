// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"
	"fmt"
	"math"

	"github.com/canonical/go-tpm2"
)

// ComputePCRDigest computes a digest using the specified algorithm from the provided set of PCR
// values and the provided PCR selections. The digest is computed the same way as PCRComputeCurrentDigest
// as defined in the TPM reference implementation. It is most useful for computing an input to
// [tpm2.TPMContext.PolicyPCR] or [TrialAuthPolicy.PolicyPCR], and for validating quotes and creation data.
func ComputePCRDigest(alg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList, values tpm2.PCRValues) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("algorithm is not available")
	}
	h := alg.NewHash()

	for _, s := range pcrs {
		if _, ok := values[s.Hash]; !ok {
			return nil, fmt.Errorf("the provided values don't contain digests for the selected PCR bank %v", s.Hash)
		}

		bmp, err := s.Select.ToBitmap(math.MaxUint8)
		if err != nil {
			return nil, fmt.Errorf("invalid selection: %w", err)
		}
		sel := bmp.ToPCRs()

		for _, i := range sel {
			d, ok := values[s.Hash][i]
			if !ok {
				return nil, fmt.Errorf("the provided values don't contain a digest for PCR%d in bank %v", i, s.Hash)
			}
			h.Write(d)
		}
	}

	return h.Sum(nil), nil
}

// ComputePCRDigestFromAllValues computes a digest using the specified algorithm from all of the
// provided set of PCR values. The digest is computed the same way as PCRComputeCurrentDigest as
// defined in the TPM reference implementation. It returns the PCR selection associated with the
// computed digest.
func ComputePCRDigestFromAllValues(alg tpm2.HashAlgorithmId, values tpm2.PCRValues) (tpm2.PCRSelectionList, tpm2.Digest, error) {
	if !alg.Available() {
		return nil, nil, errors.New("algorithm is not available")
	}
	pcrs, err := values.SelectionList()
	if err != nil {
		return nil, nil, err
	}
	digest, err := ComputePCRDigest(alg, pcrs, values)
	if err != nil {
		return nil, nil, err
	}

	return pcrs, digest, nil
}
