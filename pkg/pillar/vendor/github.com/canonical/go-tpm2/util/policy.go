// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"encoding/binary"
	"hash"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// TrialAuthPolicy provides a mechanism for computing authorization policy digests without
// having to execute a trial authorization policy session on the TPM. An advantage of this
// is that it is possible to compute digests for PolicySecret and PolicyNV assertions
// without knowledge of the authorization value of the authorizing entities used for those
// commands.
type TrialAuthPolicy struct {
	alg    tpm2.HashAlgorithmId
	digest tpm2.Digest

	// A policy can only contain one of TPM2_PolicyCpHash, TPM2_PolicyNameHash or
	// TPM2_PolicyTemplate
	hashOccupied bool
}

// ComputeAuthPolicy creates a new context for computing an authorization policy digest.
// It will panic if the specified algorithm is not available. The caller should check
// this beforehand.
func ComputeAuthPolicy(alg tpm2.HashAlgorithmId) *TrialAuthPolicy {
	if !alg.Available() {
		panic("unsupported digest algorithm or algorithm not linked in to binary")
	}
	return &TrialAuthPolicy{alg: alg, digest: make(tpm2.Digest, alg.Size())}
}

func (p *TrialAuthPolicy) beginUpdate() (hash.Hash, func()) {
	h := p.alg.NewHash()
	h.Write(p.digest)

	return h, func() {
		p.digest = h.Sum(nil)
	}
}

func (p *TrialAuthPolicy) beginUpdateForCommand(commandCode tpm2.CommandCode) (hash.Hash, func()) {
	h, end := p.beginUpdate()
	binary.Write(h, binary.BigEndian, commandCode)
	return h, end
}

func (p *TrialAuthPolicy) update(commandCode tpm2.CommandCode, entity Entity, ref tpm2.Nonce) {
	name := entity.Name()
	if !name.IsValid() {
		panic("invalid name")
	}

	h, end := p.beginUpdateForCommand(commandCode)
	h.Write(name)
	end()

	h, end = p.beginUpdate()
	h.Write(ref)
	end()
}

func (p *TrialAuthPolicy) reset() {
	p.digest = make(tpm2.Digest, len(p.digest))
}

// GetDigest returns the current digest computed for the policy assertions executed so far.
func (p *TrialAuthPolicy) GetDigest() tpm2.Digest {
	return p.digest
}

// SetDigests overwrites the current digest. It will panic if the supplied digest is
// not the correct size.
func (p *TrialAuthPolicy) SetDigest(d tpm2.Digest) {
	if len(d) != p.alg.Size() {
		panic("invalid digest length")
	}
	p.digest = d
}

// Reset clears the current digest.
func (p *TrialAuthPolicy) Reset() {
	p.reset()
}

// PolicySigned computes a TPM2_PolicySigned assertion executed for a key with
// the specified name and the specified policyRef.
func (p *TrialAuthPolicy) PolicySigned(auth Entity, policyRef tpm2.Nonce) {
	p.update(tpm2.CommandPolicySigned, auth, policyRef)
}

// PolicySecret computes a TPM2_PolicySecret assertion executed for an object
// with the specified name and the specified policyRef.
func (p *TrialAuthPolicy) PolicySecret(auth Entity, policyRef tpm2.Nonce) {
	p.update(tpm2.CommandPolicySecret, auth, policyRef)
}

// PolicyOR computes a TPM2_PolicyOR assertion executed for the specified
// digests. It will panic if there are fewer than 2 or more than 8 digests,
// or if any digest has the wrong size.
func (p *TrialAuthPolicy) PolicyOR(pHashList tpm2.DigestList) {
	if len(pHashList) < 2 || len(pHashList) > 8 {
		panic("invalid number of digests")
	}

	p.reset()

	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyOR)
	for _, digest := range pHashList {
		if len(digest) != p.alg.Size() {
			panic("invalid digest length")
		}
		h.Write(digest)
	}
	end()
}

// PolicyPCR computes a TPM2_PolicyPCR assertion executed for the specified
// PCR selection and with PCR values associated with the specified PCR digest.
//
// If generating policy for non PC client TPM devices, make sure to call
// tpm2.PCRSelectionList.WithMinSelectSize with an appropriate value defined
// in the TPM's platform profile specification.
func (p *TrialAuthPolicy) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) {
	if len(pcrDigest) != p.alg.Size() {
		panic("invalid PCR digest length")
	}
	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyPCR)
	mu.MustMarshalToWriter(h, pcrs)
	h.Write(pcrDigest)
	end()
}

// PolicyNV computes a TPM2_PolicyNV assertion executed for an index for the
// specified name, with the specified comparison operation.
func (p *TrialAuthPolicy) PolicyNV(nvIndex Entity, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) {
	name := nvIndex.Name()
	if !name.IsValid() {
		panic("invalid index name")
	}

	h := p.alg.NewHash()
	h.Write(operandB)
	binary.Write(h, binary.BigEndian, offset)
	binary.Write(h, binary.BigEndian, operation)

	args := h.Sum(nil)

	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyNV)
	h.Write(args)
	h.Write(name)
	end()
}

// PolicyCounterTimer computes a TPM2_PolicyCounterTimer assertion for the
// specified comparison operation.
func (p *TrialAuthPolicy) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) {
	h := p.alg.NewHash()
	h.Write(operandB)
	binary.Write(h, binary.BigEndian, offset)
	binary.Write(h, binary.BigEndian, operation)

	args := h.Sum(nil)

	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyCounterTimer)
	h.Write(args)
	end()
}

// PolicyCommandCode computes a TPM2_PolicyCommandCode assertion for the
// specified command code.
func (p *TrialAuthPolicy) PolicyCommandCode(code tpm2.CommandCode) {
	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyCommandCode)
	binary.Write(h, binary.BigEndian, code)
	end()
}

// PolicyCpHash computes a TPM2_PolicyCpHash assertion for the command parameters
// associated with the specified hash.
func (p *TrialAuthPolicy) PolicyCpHash(cpHashA tpm2.Digest) {
	if len(cpHashA) != p.alg.Size() {
		panic("invalid digest length")
	}
	if p.hashOccupied {
		panic("policy already has a hash")
	}
	p.hashOccupied = true
	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyCpHash)
	h.Write(cpHashA)
	end()
}

// PolicyNameHash computes a TPM2_PolicyNameHash assertion with for the entities
// associated with the specified name digest.
func (p *TrialAuthPolicy) PolicyNameHash(nameHash tpm2.Digest) {
	if len(nameHash) != p.alg.Size() {
		panic("invalid digest length")
	}
	if p.hashOccupied {
		panic("policy already has a hash")
	}
	p.hashOccupied = true
	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyNameHash)
	h.Write(nameHash)
	end()
}

// PolicyDuplicationSelect computes a TPM2_PolicyDuplicationSelect assertion for
// the object and parent object with the specified names.
func (p *TrialAuthPolicy) PolicyDuplicationSelect(object, newParent Entity, includeObject bool) {
	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyDuplicationSelect)

	if includeObject {
		objectName := object.Name()
		if !objectName.IsValid() {
			panic("invalid object name")
		}
		h.Write(objectName)
	}

	newParentName := newParent.Name()
	if !newParentName.IsValid() {
		panic("invalid new parent name")
	}

	h.Write(newParentName)
	binary.Write(h, binary.BigEndian, includeObject)
	end()
}

// PolicyAuthorize computes a TPM2_PolicyAuthorize assertion for the key with the
// specified name and the specified policyRef.
func (p *TrialAuthPolicy) PolicyAuthorize(policyRef tpm2.Nonce, key Entity) {
	p.update(tpm2.CommandPolicyAuthorize, key, policyRef)
}

// PolicyAuthValue computes a TPM2_PolicyAuthValue assertion.
func (p *TrialAuthPolicy) PolicyAuthValue() {
	_, end := p.beginUpdateForCommand(tpm2.CommandPolicyAuthValue)
	end()
}

// PolicyPassword computes a TPM2_PolicyPassword assertion.
func (p *TrialAuthPolicy) PolicyPassword() {
	// This extends the same value as PolicyAuthValue - see section 23.18 of part 3 of the "TPM 2.0 Library
	// Specification"
	_, end := p.beginUpdateForCommand(tpm2.CommandPolicyAuthValue)
	end()
}

// PolicyNvWritten computes a TPM2_PolicyNvWritten assertion
func (p *TrialAuthPolicy) PolicyNvWritten(writtenSet bool) {
	h, end := p.beginUpdateForCommand(tpm2.CommandPolicyNvWritten)
	binary.Write(h, binary.BigEndian, writtenSet)
	end()
}
