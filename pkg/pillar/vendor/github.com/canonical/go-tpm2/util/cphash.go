// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"encoding/binary"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// ComputeCpHash computes a command parameter digest from the specified command code, the supplied
// handles, and parameters using the specified digest algorithm.
//
// The required parameters is defined in part 3 of the TPM 2.0 Library Specification for the
// specific command.
//
// The result of this is useful for extended authorization commands that bind an authorization to
// a command and set of command parameters, such as [tpm2.TPMContext.PolicySigned],
// [tpm2.TPMContext.PolicySecret], [tpm2.TPMContext.PolicyTicket] and
// [tpm2.TPMContext.PolicyCpHash].
//
// Deprecated: Use [policyutil.ComputeCpHash].
func ComputeCpHash(alg tpm2.HashAlgorithmId, command tpm2.CommandCode, handles []Entity, params ...interface{}) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("algorithm is not available")
	}

	cpBytes, err := mu.MarshalToBytes(params...)
	if err != nil {
		return nil, err
	}

	h := alg.NewHash()

	binary.Write(h, binary.BigEndian, command)
	for _, handle := range handles {
		h.Write(handle.Name())
	}
	h.Write(cpBytes)

	return h.Sum(nil), nil
}
