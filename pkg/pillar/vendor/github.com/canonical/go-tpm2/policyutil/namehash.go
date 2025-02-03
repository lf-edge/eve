// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
)

// NameHash provides a way to obtain a name digest.
type NameHash interface {
	// Digest returns the name digest for the specified algorithm.
	Digest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error)
}

type commandHandles []Named

func (handles commandHandles) Digest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("algorithm is not available")
	}

	h := alg.NewHash()

	for i, handle := range handles {
		if !handle.Name().IsValid() {
			return nil, fmt.Errorf("invalid name for handle %d", i)
		}
		h.Write(handle.Name())
	}

	return h.Sum(nil), nil
}

// CommandHandles returns a NameHash implementation for the supplied command handles.
func CommandHandles(handles ...Named) NameHash {
	return commandHandles(handles)
}

type nameDigest tpm2.TaggedHash

func (d *nameDigest) Digest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	if alg != d.HashAlg {
		return nil, errors.New("no digest for algorithm")
	}
	return tpm2.Digest((*tpm2.TaggedHash)(d).Digest()), nil
}

// CommandHandleDigest returns a NameHash implementation for the specified algorithm and digest.
func CommandHandleDigest(alg tpm2.HashAlgorithmId, digest tpm2.Digest) NameHash {
	d := tpm2.MakeTaggedHash(alg, digest)
	return (*nameDigest)(&d)
}

type nameDigests tpm2.TaggedHashList

func (d nameDigests) Digest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	for _, digest := range tpm2.TaggedHashList(d) {
		if digest.HashAlg != alg {
			continue
		}
		return digest.Digest(), nil
	}
	return nil, errors.New("no digest for algorithm")
}

func CommandHandleDigests(digests ...tpm2.TaggedHash) NameHash {
	return nameDigests(digests)
}

// ComputeNameHash computes a digest from the supplied handles using the specified digest
// algorithm.
//
// The result of this is useful with [tpm2.TPMContext.PolicyNameHash].
func ComputeNameHash(alg tpm2.HashAlgorithmId, handles ...Named) (tpm2.Digest, error) {
	d := CommandHandles(handles...)
	return d.Digest(alg)
}
