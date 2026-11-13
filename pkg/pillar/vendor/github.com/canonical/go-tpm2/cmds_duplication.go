// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"github.com/canonical/go-tpm2/mu"
)

// Section 13 - Duplication Commands

// Duplicate executes the TPM2_Duplicate command in order to duplicate the object associated with
// objectContext so that it may be used in a different hierarchy. The new parent is specified by
// the newParentContext argument, which may correspond to an object on the same or a different TPM,
// or may be nil for no parent.
//
// This command requires authorization for objectContext with the duplication role, with the
// session provided via objectContextAuthSession.
//
// If symmetricAlg is provided, it defines the symmetric algorithm used for the inner duplication
// wrapper (see section 23.3 - "Protected Storage Hierarchy - Duplication" of Part 1 of the Trusted
// Platform Module Library specification). If symmetricAlg is provided and symmetricAlg.Algorithm
// is not [SymObjectAlgorithmNull], a symmetric key for the inner duplication wrapper may be
// provided via encryptionKeyIn.
//
// If newParentContext is supplied, an outer duplication wrapper is applied (see section 23.3 -
// "Protected Storage Hierarchy - Duplication" of Part 1 of the Trusted Platform Module Library
// specification)
//
// If the object associated with objectContext has the [AttrFixedParent] atttribute set, a
// *[TPMHandleError] error with an error code of [ErrorAttributes] will be returned for handle
// index 1.
//
// If the object associated with objectContext has a name algorithm of [HashAlgorithmNull], a
// *[TPMHandleError] error with an error code of [ErrorType] will be returned for handle index 1.
//
// If newParentContext is provided and it does not correspond to a storage parent, a
// *[TPMHandleError] error with an error code of [ErrorType] will be returned for handle index 2.
//
// If the object associated with objectContext has the [AttrEncryptedDuplication] attribute set and
// no symmetricAlg is provided or symmetricAlg.Algorithm is [SymObjectAlgorithmNull], a
// *[TPMParameterError] error with an error code of [ErrorSymmetric] will be returned for parameter
// index 2.
//
// If the object associated with objectContext has the [AttrEncryptedDuplication] attribute set and
// newParentContext is not provided, a *[TPMHandleError] error with an error code of
// [ErrorHierarchy] will be returned for handle index 2.
//
// If the length of encryptionKeyIn is not consistent with symmetricAlg, a *[TPMParameterError]
// error with an error code of [ErrorSize] will be returned for parameter index 1.
//
// If newParentContext corresponds to an ECC key and the public point of the key is not on the
// curve specified by the key, a *[TPMError] error with an error code of [ErrorKey] will be
// returned.
//
// On success, the function returns a randomly generated symmetric key as Data for the inner
// duplication wrapper if symmetricAlg was provided, symmetricAlg.Algorithm was not
// [SymObjectAlgorithmNull] and encryptionKeyIn was not provided. It also returns the sensitive
// area associated with objectContext protected with an inner duplication wrapper (if specified by
// symmetricAlg) and an outer duplication wrapper (if newParentContext was provided). If
// newParentContext was provided, a secret structure that can be used by the private part of the
// new parent to recover the seed used to generate the outer wrapper is returned as an
// EncryptedSecret.
func (t *TPMContext) Duplicate(objectContext, newParentContext ResourceContext, encryptionKeyIn Data, symmetricAlg *SymDefObject, objectContextAuthSession SessionContext, sessions ...SessionContext) (encryptionKeyOut Data, duplicate Private, outSymSeed EncryptedSecret, err error) {
	if symmetricAlg == nil {
		symmetricAlg = &SymDefObject{Algorithm: SymObjectAlgorithmNull}
	}

	if err := t.StartCommand(CommandDuplicate).
		AddHandles(UseResourceContextWithAuth(objectContext, objectContextAuthSession), UseHandleContext(newParentContext)).
		AddParams(encryptionKeyIn, symmetricAlg).
		AddExtraSessions(sessions...).
		Run(nil, &encryptionKeyOut, &duplicate, &outSymSeed); err != nil {
		return nil, nil, nil, err
	}

	return encryptionKeyOut, duplicate, outSymSeed, nil
}

// func (t *TPMContext) Rewrap(oldParent, newParent HandleContext, inDuplicate Private, name Name, inSymSeed EncryptedSecret, oldParentAuth interface{}, sessions ...SessionContext) (Private, EncryptedSecret, error) {
// }

// Import executes the TPM2_Import command in order to encrypt the sensitive area of the object
// associated with the objectPublic and duplicate arguments with the symmetric algorithm of the
// storage parent associated with parentContext, so that it can be loaded and used in the new
// hierarchy.
//
// If the object to be imported has an outer duplication wrapper (see section 23.3 -
// "Protected Storage Hierarchy - Duplication" of Part 1 of the Trusted Platform Module Library
// specification), then inSymSeed must be supplied which contains a secret structure that can be
// recovered by the private part of the key associated with parentContext in order to remove the
// outer wrapper.
//
// If the object to be imported has an inner duplication wrapper (see section 23.3 -
// "Protected Storage Hierarchy - Duplication" of Part 1 of the Trusted Platform Module Library
// specification), then symmetricAlg must be provided with the algorithm of the inner duplication
// wrapper, and encryptionKey must be provided with the symmetric key for the inner duplication
// wrapper.
//
// This command requires authorization with the user auth role for parentContext, with session
// based authorization provided via parentContextAuthSession.
//
// If objectPublic has the [AttrFixedTPM] or [AttrFixedParent] attributes set, a
// *[TPMParameterError] error with an error code of [ErrorAttributes] will be returned for
// parameter index 2.
//
// If parentContext is not associated with a storage parent, a *[TPMHandleError] error with an
// error code of [ErrorType] will be returned.
//
// If the length of encryptionKey is not consistent with symmetricAlg, a *[TPMParameterError] error
// with an error code of [ErrorSize] will be returned for parameter index 1.
//
// If symmetricAlg is not provided or symmetricAlg.Algorithm is [SymObjectAlgorithmNull] and
// objectPublic has the [AttrEncryptedDuplication] attribute set, a *[TPMParameterError] error with
// an error code of [ErrorAttributes] will be returned for parameter index 1.
//
// If the length of inSymSeed is not zero and the object associated with parentContext is not an
// asymmetric key, a *[TPMHandleError] error with an error code of [ErrorType] will be returned.
//
// If parentContext is associated with a RSA key and the size of inSymSeed does not match the size
// of the key's public modulus, a *[TPMParameterError] error with an error code of [ErrorSize] will
// be returned for parameter index 4.
//
// If parentContext is associated with a RSA key and the plaintext size of inSymSeed is larger than
// the name algorithm, a *[TPMParameterError] error with an error code of [ErrorValue] will be
// returned for parameter index 4.
//
// If parentContext is associated with a ECC key and inSymSeed does not contain enough data to
// unmarshal a ECC point, a *[TPMParameterError] error with an error code of [ErrorInsufficient]
// will be returned for parameter index 4.
//
// If parentContext is associated with a ECC key and the ECC point in inSymSeed is not on the curve
// specified by the parent key, a *[TPMParameterError] error with an error code of [ErrorECCPoint]
// will be returned for parameter index 4.
//
// If parentContext is associated with a ECC key and multiplication of the ECC point in inSymSeed
// results in a point at infinity, a *[TPMParameterError] error with an error code of
// [ErrorNoResult] will be returned for parameter index 4.
//
// If the name of the object associated with objectPublic cannot be computed, a
// *[TPMParameterError] error with an error code of [ErrorHash] will be returned for parameter
// index 2.
//
// If the object has an outer duplication wrapper and the integrity value of duplicate cannot be
// unmarshalled correctly, a *[TPMParameterError] error with an error code of either [ErrorSize] or
// [ErrorInsufficient] will be returned for parameter index 3. If the integrity check fails, a
// *[TPMParameterError] error with an error code of [ErrorIntegrity] will be returned for parameter
// index 3.
//
// If the object has an inner duplication wrapper and the integrity value of duplicate cannot be
// unmarshalled correctly after decrypting the inner wrapper, a *[TPMParameterError] error with an
// error code of either [ErrorSize] or [ErrorInsufficient] will be returned for parameter index 3.
// If the integrity check fails, a *[TPMParameterError error with an error code of [ErrorIntegrity]
// will be returned for parameter index 3.
//
// If, after removing the duplication wrappers, the sensitive area does not unmarshal correctly, a
// *[TPMParameterError] error with an error code of either [ErrorSize] or [ErrorInsufficient] will
// be returned for parameter index 3.
//
// On success, a new private area encrypted with the symmetric algorithm defined by the object
// associated with parentContext is returned.
func (t *TPMContext) Import(parentContext ResourceContext, encryptionKey Data, objectPublic *Public, duplicate Private, inSymSeed EncryptedSecret, symmetricAlg *SymDefObject, parentContextAuthSession SessionContext, sessions ...SessionContext) (outPrivate Private, err error) {
	if symmetricAlg == nil {
		symmetricAlg = &SymDefObject{Algorithm: SymObjectAlgorithmNull}
	}

	if err := t.StartCommand(CommandImport).
		AddHandles(UseResourceContextWithAuth(parentContext, parentContextAuthSession)).
		AddParams(encryptionKey, mu.Sized(objectPublic), duplicate, inSymSeed, symmetricAlg).
		AddExtraSessions(sessions...).
		Run(nil, &outPrivate); err != nil {
		return nil, err
	}

	return outPrivate, nil
}
