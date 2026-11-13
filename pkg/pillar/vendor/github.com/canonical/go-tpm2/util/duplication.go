// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"crypto"
	"crypto/rand"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
)

// UnwrapDuplicationObject unwraps the supplied duplication object and returns the corresponding
// sensitive area. The duplication object will normally be created by executing the
// [tpm2.TPMContext.Duplicate] command.
//
// If outerSecret is supplied then it is assumed that the object has an outer duplication wrapper.
// For an object duplicated with [tpm2.TPMContext.Duplicate], outerSecret is the secret structure
// returned by this command. In this case, privKey, outerHashAlg and outerSymmetricAlg must be
// supplied - privKey is the key that recovers the seed used to generate the outer wrapper (the new
// parent when using [tpm2.TPMContext.Duplicate]), outerHashAlg is the algorithm used for integrity
// checking and key derivation (the new parent's name algorithm when using
// [tpm2.TPMContext.Duplicate]) and must not be [tpm2.HashAlgorithmNull], and outerSymmetricAlg
// defines the symmetric algorithm for the outer wrapper (the new parent's symmetric algorithm when
// using [tpm2.TPMContext.Duplicate]) and must not be [tpm2.SymObjectAlgorithmNull]).
//
// If innerSymmetricAlg is supplied and the Algorithm field is not [tpm2.SymObjectAlgorithmNull],
// then it is assumed that the object has an inner duplication wrapper. In this case, the symmetric
// key for the inner wrapper must be supplied using the innerSymmetricKey argument.
//
// Deprecated: Use [objectutil.UnwrapDuplicated].
func UnwrapDuplicationObject(duplicate tpm2.Private, public *tpm2.Public, privKey crypto.PrivateKey, outerHashAlg tpm2.HashAlgorithmId, outerSymmetricAlg *tpm2.SymDefObject, outerSecret tpm2.EncryptedSecret, innerSymmetricKey tpm2.Data, innerSymmetricAlg *tpm2.SymDefObject) (*tpm2.Sensitive, error) {
	return objectutil.UnwrapDuplicated(duplicate, public, privKey, outerHashAlg, outerSymmetricAlg, outerSecret, innerSymmetricKey, innerSymmetricAlg)
}

// CreateDuplicationObject creates a duplication object that can be imported in to a TPM with the
// [tpm2.TPMContext.Import] command from the supplied sensitive area.
//
// If parentPublic is supplied, an outer duplication wrapper will be applied to the duplication
// object. The parentPublic argument should correspond to the public area of the storage key to
// which the duplication object will be imported. A secret structure will be returned as
// [tpm2.EncryptedSecret] which can be used by the private part of parentPublic in order to
// recover the seed used to generate the outer wrapper.
//
// If innerSymmetricAlg is supplied and the Algorithm field is not [tpm2.SymObjectAlgorithmNull],
// this function will apply an inner duplication wrapper to the duplication object. If
// innerSymmetricKey is supplied, it will be used as the symmetric key for the inner wrapper. It
// must have a size appropriate for the selected symmetric algorithm. If innerSymmetricKey is not
// supplied, a symmetric key will be created and returned as [tpm2.Data].
//
// Deprecated: Use [objectutil.CreateImportable].
func CreateDuplicationObject(sensitive *tpm2.Sensitive, public, parentPublic *tpm2.Public, innerSymmetricKey tpm2.Data, innerSymmetricAlg *tpm2.SymDefObject) (innerSymmetricKeyOut tpm2.Data, duplicate tpm2.Private, outerSecret tpm2.EncryptedSecret, err error) {
	return objectutil.CreateImportable(rand.Reader, sensitive, public, parentPublic, innerSymmetricKey, innerSymmetricAlg)
}
