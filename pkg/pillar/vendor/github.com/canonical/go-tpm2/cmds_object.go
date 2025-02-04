// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 12 - Object Commands

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2/mu"
)

// Create executes the TPM2_Create command to create a new ordinary object as a child of the
// storage parent associated with parentContext.
//
// The command requires authorization with the user auth role for parentContext, with session based
// authorization provided via parentContextAuthSession.
//
// A template for the object is provided via the inPublic parameter. The Type field of inPublic
// defines the algorithm for the object. The NameAlg field defines the digest algorithm for
// computing the name of the object. The Attrs field defines the attributes of the object. The
// AuthPolicy field allows an authorization policy to be defined for the new object.
//
// Data that will form part of the sensitive area of the object can be provided via inSensitive,
// which is optional.
//
// If the Attrs field of inPublic does not have the [AttrSensitiveDataOrigin] attribute set, then
// the sensitive data in the created object is initialized with the data provided via the Data
// field of inSensitive.
//
// If the Attrs field of inPublic has the [AttrSensitiveDataOrigin] attribute set and Type is
// [ObjectTypeSymCipher], then the sensitive data in the created object is initialized with a TPM
// generated key. The size of this key is determined by the symmetric algorithm defined in the
// Params field of inPublic. If Type is [ObjectTypeKeyedHash], then the sensitive data in the
// created object is initialized with a TPM generated value that is the same size as the name
// algorithm selected by the NameAlg field of inPublic.
//
// If the Type field of inPublic is [ObjectTypeRSA] or [ObjectTypeECC], then the sensitive data
// in the created object is initialized with a TPM generated private key. The size of this is
// determined by the asymmetric algorithm defined in the Params field of inPublic.
//
// If the Type field of inPublic is [ObjectTypeKeyedHash] and the Attrs field has
// [AttrSensitiveDataOrigin], [AttrSign] and [AttrDecrypt] all clear, then the created object is a
// sealed data object.
//
// If the Attrs field of inPublic has the [AttrRestricted] and [AttrDecrypt] attributes set, and
// the Type field is not [ObjectTypeKeyedHash], then the newly created object will be a storage
// parent.
//
// If the Attrs field of inPublic has the [AttrRestricted] and [AttrDecrypt] attributes set, and
// the Type field is [ObjectTypeKeyedHash], then the newly created object will be a derivation
// parent.
//
// The authorization value for the created object is initialized to the value of the UserAuth field
// of inSensitive.
//
// If the object associated with parentContext is not a valid storage parent object, a
// *[TPMHandleError] error with an error code of [ErrorType] will be returned for handle index 1.
//
// If there are no available slots for new objects on the TPM, a *[TPMWarning] error with a warning
// code of [WarningObjectMemory] will be returned.
//
// If the Attrs field of inPublic as the [AttrSensitiveDataOrigin] attribute set and the Data field
// of inSensitive has a non-zero size, or the [AttrSensitiveDataOrigin] attribute is clear and the
// Data field of inSensitive has a zero size, a *[TPMParameterError] error with an error code of
// [ErrorAttributes] will be returned for parameter index 1.
//
// If the attributes in the Attrs field of inPublic are inconsistent or inappropriate for the
// usage, a *[TPMParameterError] error with an error code of [ErrorAttributes] will be returned for
// parameter index 2.
//
// If the NameAlg field of inPublic is [HashAlgorithmNull], then a *[TPMParameterError] error with
// an error code of [ErrorHash] will be returned for parameter index 2.
//
// If an authorization policy is defined via the AuthPolicy field of inPublic then the length of
// the digest must match the name algorithm selected via the NameAlg field, else a
// *[TPMParameterError] error with an error code of [ErrorSize] is returned for parameter index 2.
//
// If the scheme in the Params field of inPublic is inappropriate for the usage, a
// *[TPMParameterError] error with an error code of [ErrorScheme] will be returned for parameter
// index 2.
//
// If the Type field of inPublic is [ObjectTypeRSA], [ObjectTypeECC] or [ObjectTypeKeyedHash] and
// the digest algorithm specified by the scheme in the Params field of inPublic is inappropriate
// for the usage, a *[TPMParameterError] error with an error code of [ErrorHash] will be returned
// for parameter index 2.
//
// If the Type field of inPublic is not [ObjectTypeKeyedHash], a *[TPMParameterError] error with an
// error code of [ErrorSymmetric] will be returned for parameter index 2 if the symmetric algorithm
// specified in the Params field of inPublic is inappropriate for the usage.
//
// If the Type field of inPublic is [ObjectTypeECC] and the KDF scheme specified in the Params
// field of inPublic is not [KDFAlgorithmNull], a *[TPMParameterError] error with an error code of
// [ErrorKDF] will be returned for parameter index 2.
//
// If the Type field of inPublic is not [ObjectTypeKeyedHash] and the [AttrRestricted],
// [AttrFixedParent] and [AttrDecrypt] attributes of Attrs are set, a *[TPMParameterError] error
// with an error code of [ErrorHash] will be returned for parameter index 2 if the NameAlg field of
// inPublic does not select the same name algorithm as the parent object. A *[TPMParameterError]
// error with an error code of [ErrorSymmetric] will be returned for parameter index 2 if the
// symmetric algorithm specified in the Params field of inPublic does not match the symmetric
// algorithm of the parent object.
//
// If the length of the UserAuth field of inSensitive is longer than the name algorithm selected by
// the NameAlg field of inPublic, a *[TPMParameterError] error with an error code of [ErrorSize]
// will be returned for parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeRSA] and the Params field specifies an unsupported
// exponent, a *[TPMError] with an error code of [ErrorRange] will be returned. If the specified
// key size is an unsupported value, a *[TPMError] with an error code of [ErrorValue] will be
// returned.
//
// If the Type field of inPublic is [ObjectTypeSymCipher] and the key size is an unsupported value,
// a *[TPMError] with an error code of [ErrorKeySize] will be returned. If the
// [AttrSensitiveDataOrigin] attribute is not set and the length of the Data field of inSensitive
// does not match the key size specified in the Params field of inPublic, a *[TPMError] with an
// error code of [ErrorKeySize] will be returned.
//
// If the Type field of inPublic is [ObjectTypeKeyedHash] and the [AttrSensitiveDataOrigin]
// attribute is not set, a *[TPMError] with an error code of [ErrorSize] will be returned if the
// length of the Data field of inSensitive is longer than permitted for the digest algorithm
// selected by the specified scheme.
//
// This function will call [TPMContext.InitProperties] if it hasn't already been called.
//
// On success, the private and public parts of the newly created object will be returned. The newly
// created object will not exist on the TPM. If the Type field of inPublic is [ObjectTypeKeyedHash]
// or [ObjectTypeSymCipher], then the returned *Public object will have a Unique field that is the
// digest of the sensitive data and the value of the object's seed in the sensitive area, computed
// using the object's name algorithm. If the Type field of inPublic is [ObjectTypeECC] or
// [ObjectTypeRSA], then the returned *Public object will have a Unique field containing details
// about the public part of the key, computed from the private part of the key.
//
// The returned *CreationData will contain a digest computed from the values of PCRs selected by
// the creationPCR parameter at creation time in the PCRDigest field. It will also contain the
// provided outsideInfo in the OutsideInfo field. The returned *TkCreation ticket can be used to
// prove the association between the created object and the returned *CreationData via the
// [TPMContext.CertifyCreation] method.
func (t *TPMContext) Create(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic *Public, outsideInfo Data, creationPCR PCRSelectionList, parentContextAuthSession SessionContext, sessions ...SessionContext) (outPrivate Private, outPublic *Public, creationData *CreationData, creationHash Digest, creationTicket *TkCreation, err error) {
	if err := t.initPropertiesIfNeeded(); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	if err := t.StartCommand(CommandCreate).
		AddHandles(UseResourceContextWithAuth(parentContext, parentContextAuthSession)).
		AddParams(mu.Sized(inSensitive), mu.Sized(inPublic), outsideInfo, creationPCR.WithMinSelectSize(t.minPcrSelectSize)).
		AddExtraSessions(sessions...).
		Run(nil, &outPrivate, mu.Sized(&outPublic), mu.Sized(&creationData), &creationHash, &creationTicket); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return outPrivate, outPublic, creationData, creationHash, creationTicket, nil
}

// Load executes the TPM2_Load command in order to load both the public and private parts of an
// object in to the TPM.
//
// The parentContext parameter corresponds to the parent key. The command requires authorization
// with the user auth role for parentContext, with session based authorization provided via
// parentContextAuthSession.
//
// The object to load is specified by providing the inPrivate and inPublic arguments.
//
// If there are no available slots for new objects on the TPM, a *[TPMWarning] error with a warning
// code of [WarningObjectMemory] will be returned.
//
// If inPrivate is empty, a *[TPMParameterError] error with an error code of [ErrorSize] will be
// returned for parameter index 1.
//
// If parentContext does not correspond to a storage parent, a *[TPMHandleError] error with an
// error code of [ErrorType] will be returned.
//
// If the name algorithm associated with inPublic is invalid, a *[TPMParameterError] error with an
// error code of [ErrorHash] will be returned for parameter index 2.
//
// If the integrity value or IV for inPrivate cannot be unmarshalled correctly, a
// *[TPMParameterError] error with an error code of either [ErrorSize] or [ErrorInsufficient] will
// be returned for parameter index 1. If the integrity check of inPrivate fails, a
// *[TPMParameterError] error with an error code of [ErrorIntegrity] will be returned for parameter
// index 1. If the size of the IV for inPrivate doesn't match the block size for the encryption
// algorithm, a *[TPMParameterError] error with an error code of [ErrorValue] will be returned for
// parameter index 1.
//
// TPM2_Load performs many of the same validations of the public attributes as TPM2_Create, and may
// return similar error codes as *[TPMParameterError] for parameter index 2.
//
// If the object associated with parentContext has the [AttrFixedTPM] attribute clear, some
// additional validation of the decrypted sensitive data is performed as detailed below.
//
// If the Type field of inPublic does not match the type specified in the sensitive data, a
// *[TPMParameterError] error with an error code of [ErrorType] is returned for parameter index 1.
// If the authorization value in the sensitive area is larger than the name algorithm, a
// *[TPMParameterError] error with an error code of [ErrorSize] is returned for parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeRSA] and the size of the modulus in the Unique field
// is inconsistent with the size specified in the Params field, a *[TPMParameterError] error with
// an error code of [ErrorKey] will be returned for parameter index 2. If the value of the exponent
// in the Params field is invalid, a *[TPMParameterError] error with an error code of [ErrorValue]
// will be returned for parameter index 2. If the size of private key in the sensitive area is not
// the correct size, a *[TPMParameterError] error with an error code of [ErrorKeySize] will be
// returned for parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeECC] and the private key in the sensitive area is
// invalid, a *[TPMParameterError] error with an error code of [ErrorKeySize] will be returned for
// parameter index 1. If the public point specified in the Unique field of inPublic does not belong
// to the private key, a *[TPMError] with an error code of [ErrorBinding] will be returned.
//
// If the Type field of inPublic is [ObjectTypeSymCipher] and the size of the symmetric key in the
// sensitive area is inconsistent with the symmetric algorithm specified in the Params field of
// inPublic, a *[TPMParameterError] error with an error code of [ErrorKeySize] will be returned for
// parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeKeyedHash] and the size of the sensitive data is
// larger than permitted for the digest algorithm selected by the scheme defined in the Params
// field of inPublic, a *[TPMParameterError] error with an error code of [ErrorKeySize] will be
// returned for parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeSymCipher] or [ObjectTypeKeyedHash] and the size of
// seed value in the sensitive area does not match the name algorithm, a *[TPMError] error with an
// error code of [ErrorKeySize] will be returned. If the digest in the Unique field of inPublic is
// inconsistent with the value of the sensitive data and the seed value, a *[TPMError] with an
// error code of [ErrorBinding] will be returned.
//
// If the loaded object is a storage parent and the size of the seed value in the sensitive area
// isn't sufficient for the selected name algorithm, a *[TPMParameterError] error with an error
// code of [ErrorSize] will be returned for parameter index 1.
//
// On success, a ResourceContext corresponding to the newly loaded transient object will be
// returned. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func (t *TPMContext) Load(parentContext ResourceContext, inPrivate Private, inPublic *Public, parentContextAuthSession SessionContext, sessions ...SessionContext) (objectContext ResourceContext, err error) {
	var objectHandle Handle
	var name Name

	if err := t.StartCommand(CommandLoad).
		AddHandles(UseResourceContextWithAuth(parentContext, parentContextAuthSession)).
		AddParams(inPrivate, mu.Sized(inPublic)).
		AddExtraSessions(sessions...).
		Run(&objectHandle, &name); err != nil {
		return nil, err
	}

	if objectHandle.Type() != HandleTypeTransient {
		return nil, &InvalidResponseError{CommandLoad, fmt.Errorf("handle 0x%08x returned from TPM is the wrong type", objectHandle)}
	}
	if inPublic == nil {
		return nil, &InvalidResponseError{CommandLoad, errors.New("expected an error because no public area was supplied")}
	}
	if inPublic.NameAlg.Available() && !inPublic.compareName(name) {
		return nil, &InvalidResponseError{CommandLoad, errors.New("name returned from TPM not consistent with supplied public area")}
	}

	var public *Public
	if err := mu.CopyValue(&public, inPublic); err != nil {
		// if this fails then the TPM should have returned an error.
		return nil, &InvalidResponseError{CommandLoad, fmt.Errorf("expected an error because the public area was invalid: %w", err)}
	}
	return newObjectContext(objectHandle, name, public), nil
}

// LoadExternal executes the TPM2_LoadExternal command in order to load an object that is not a
// protected object in to the TPM. The object is specified by providing the inPrivate and inPublic
// arguments, although inPrivate is optional. If only the public part is to be loaded, the
// hierarchy parameter must specify a hierarchy to associate the loaded object with so that
// tickets can be created properly. If both the public and private parts are to be loaded, then
// hierarchy should be [HandleNull].
//
// If there are no available slots for new objects on the TPM, a *[TPMWarning] error with a warning
// code of [WarningObjectMemory] will be returned.
//
// If the hierarchy specified by the hierarchy parameter is disabled, a *[TPMParameterError] error
// with an error code of [ErrorHierarchy] will be returned for parameter index 3.
//
// If inPrivate is provided and hierarchy is not [HandleNull], a *[TPMParameterError] error with an
// error code of [ErrorHierarchy] will be returned for parameter index 3.
//
// If inPrivate is provided and the Attrs field of inPublic has either [AttrFixedTPM],
// [AttrFixedParent] or [AttrRestricted] attribute set, a *[TPMParameterError] error with an error
// code of [ErrorAttributes] will be returned for parameter index 2.
//
// TPM2_LoadExternal performs many of the same validations of the public attributes as TPM2_Create,
// and may return similar error codes as *[TPMParameterError] for parameter index 2.
//
// If inPrivate is provided and the Type field of inPublic does not match the type specified in the
// sensitive data, a *[TPMParameterError] error with an error code of [ErrorType] is returned for
// parameter index 1. If the authorization value in the sensitive area is larger than the name
// algorithm, a *[TPMParameterError] error with an error code of [ErrorSize] is returned for
// parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeRSA] and the size of the modulus in the Unique field
// is inconsistent with the size specified in the Params field, a *[TPMParameterError] error with
// an error code of [ErrorKey] will be returned for parameter index 2. If the value of the exponent
// in the Params field is invalid, a *[TPMParameterError] error with an error code of [ErrorValue]
// will be returned for parameter index 2. If inPrivate is provided and the size of private key in
// the sensitive area is not the correct size, a *[TPMParameterError] error with an error code of
// [ErrorKeySize] will be returned for parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeECC], inPrivate is provided and the private key in
// the sensitive area is invalid, a *[TPMParameterError] error with an error code of [ErrorKeySize]
// will be returned for parameter index 1. If the public point specified in the Unique field of
// inPublic does not belong to the private key, a *[TPMError] with an error code of [ErrorBinding]
// will be returned.
//
// If the Type field of inPublic is [ObjectTypeECC], inPrivate is not provided and the size of the
// public key in the Unique field of inPublic is inconsistent with the value of the Params field of
// inPublic, a *[TPMParameterError] error with an error code of [ErrorKey] is returned for
// parameter index 2. If the public point is not on the curve specified in the Params field of
// inPublic, a *[TPMParameterError] error with an error code of [ErrorECCPoint] will be returned
// for parameter index 2.
//
// If the Type field of inPublic is [ObjectTypeSymCipher], inPrivate is provided and the size of
// the symmetric key in the sensitive area is inconsistent with the symmetric algorithm specified
// in the Params field of inPublic, a *[TPMParameterError] error with an error code of
// [ErrorKeySize] will be returned for parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeKeyedHash], inPrivate is provided and the size of
// the sensitive data is larger than permitted for the digest algorithm selected by the scheme
// defined in the Params field of inPublic, a *[TPMParameterError] error with an error code of
// [ErrorKeySize] will be returned for parameter index 1.
//
// If the Type field of inPublic is [ObjectTypeSymCipher] or [ObjectTypeKeyedHash] and inPrivate
// has not been provided, a *[TPMParameterError] error with an error code of [ErrorKey] will be
// returned for parameter index 2 if the size of the digest in the Unique field of inPublic does
// not match the selected name algorithm.
//
// If the Type field of inPublic is [ObjectTypeSymCipher] or [ObjectTypeKeyedHash], inPrivate has
// been provided and the size of seed value in the sensitive area does not match the name
// algorithm, a *[TPMError] error with an error code of [ErrorKeySize] will be returned. If the
// digest in the Unique field of inPublic is inconsistent with the value of the sensitive data and
// the seed value, a *[TPMError] with an error code of [ErrorBinding] will be returned.
//
// On success, a ResourceContext corresponding to the newly loaded transient object will be
// returned. If inPrivate has been provided, it will not be necessary to call
// [ResourceContext].SetAuthValue on it - this function sets the correct authorization value so
// that it can be used in subsequent commands that require knowledge of the authorization value.
func (t *TPMContext) LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle, sessions ...SessionContext) (objectContext ResourceContext, err error) {
	var objectHandle Handle
	var name Name

	if err := t.StartCommand(CommandLoadExternal).
		AddParams(mu.Sized(inPrivate), mu.Sized(inPublic), hierarchy).
		AddExtraSessions(sessions...).
		Run(&objectHandle, &name); err != nil {
		return nil, err
	}

	if objectHandle.Type() != HandleTypeTransient {
		return nil, &InvalidResponseError{CommandLoadExternal,
			fmt.Errorf("handle 0x%08x returned from TPM is the wrong type", objectHandle)}
	}
	if inPublic == nil {
		return nil, &InvalidResponseError{CommandLoadExternal, errors.New("expected an error because no public area was supplied")}
	}
	if inPublic.NameAlg.Available() && !inPublic.compareName(name) {
		return nil, &InvalidResponseError{CommandLoadExternal, errors.New("name returned from TPM not consistent with supplied public area")}
	}

	var public *Public
	if err := mu.CopyValue(&public, inPublic); err != nil {
		// if this fails then the TPM should have returned an error.
		return nil, &InvalidResponseError{CommandLoadExternal, fmt.Errorf("expected an error because the public area was invalid: %w", err)}
	}
	rc := newObjectContext(objectHandle, name, public)
	if inPrivate != nil {
		rc.authValue = make([]byte, len(inPrivate.AuthValue))
		copy(rc.authValue, inPrivate.AuthValue)
	}
	return rc, nil
}

// ReadPublic executes the TPM2_ReadPublic command to read the public area of the object associated
// with objectContext.
//
// If objectContext corresponds to a sequence object, a *[TPMError] with an error code of
// [ErrorSequence] will be returned.
//
// On success, the public part of the object is returned, along with the object's name and
// qualified name.
func (t *TPMContext) ReadPublic(objectContext HandleContext, sessions ...SessionContext) (outPublic *Public, name Name, qualifiedName Name, err error) {
	if err := t.StartCommand(CommandReadPublic).
		AddHandles(UseHandleContext(objectContext)).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&outPublic), &name, &qualifiedName); err != nil {
		return nil, nil, nil, err
	}
	return outPublic, name, qualifiedName, nil
}

// ActivateCredential executes the TPM2_ActivateCredential command to associate a credential with
// the object associated with activateContext.
//
// The activateContext parameter corresponds to an object to which credentialBlob is to be
// associated. It would typically be an attestation key, and the credential issuer would have
// validated that this object has the expected properties of an attestation key (it is a
// restricted, non-duplicable signing key) before issuing the credential. Authorization with the
// admin role is required for activateContext, with session based authorization provided via
// activateContextAuthSession.
//
// The credentialBlob is an encrypted and integrity protected credential (see section 24 -
// "Credential Protection" of Part 1 of the Trusted Platform Module Library specification). The
// secret parameter is used by the private part of the key associated with keyContext in order to
// recover the seed used to protect the credential.
//
// The keyContext parameter corresponds to an asymmetric restricted decrypt. It is typically an
// endorsement key, and the credential issuer would have verified that it is a valid endorsement
// key by verifying the associated endorsement certificate. Authorization with the user auth role
// is required for keyContext, with session based authorization provided via keyContextAuthSession.
//
// If keyContext does not correspond to an asymmetric restricted decrypt key, a *[TPMHandleError]
// error with an error code of [ErrorType] is returned for handle index 2.
//
// If recovering the seed from secret fails, a *[TPMParameterError] error with an error code of
// [ErrorScheme], [ErrorValue], [ErrorSize] or [ErrorECCPoint] may be returned for parameter index
// 2.
//
// If the integrity value or IV for credentialBlob cannot be unmarshalled correctly or any other
// errors occur during unmarshalling of credentialBlob, a *[TPMParameterError] error with an error
// code of either [ErrorSize] or [ErrorInsufficient] will be returned for parameter index 1. If
// the integrity check of credentialBlob fails, a *[TPMParameterError] error with an error code of
// [ErrorIntegrity] will be returned for parameter index 1. If the size of the IV for
// credentialBlob doesn't match the block size for the encryption algorithm, a *[TPMParameterError]
// error with an error code of [ErrorValue] will be returned for parameter index 1.
//
// On success, the decrypted credential is returned. This is typically used to decrypt a
// certificate associated with activateContext, or provide a response to a challenge provided by
// the credential issuer.
func (t *TPMContext) ActivateCredential(activateContext, keyContext ResourceContext, credentialBlob IDObject, secret EncryptedSecret, activateContextAuthSession, keyContextAuthSession SessionContext, sessions ...SessionContext) (certInfo Digest, err error) {
	if err := t.StartCommand(CommandActivateCredential).
		AddHandles(UseResourceContextWithAuth(activateContext, activateContextAuthSession), UseResourceContextWithAuth(keyContext, keyContextAuthSession)).
		AddParams(credentialBlob, secret).
		AddExtraSessions(sessions...).
		Run(nil, &certInfo); err != nil {
		return nil, err
	}
	return certInfo, nil
}

// MakeCredential executes the TPM2_MakeCredential command to allow the TPM to perform the actions
// of a certificate authority, in order to create an activation credential.
//
// The object associated with context must be the public part of a storage key, which would
// typically be the endorsement key of the TPM from which the request originates. The certificate
// authority would normally be in receipt of the TPM manufacturer issued endorsement certificate
// corresponding to this key and would have validated this. The certificate is an assertion from
// the manufacturer that the key is a valid endorsement key (a restricted, non-duplicable decrypt
// key) that is resident on a genuine TPM.
//
// The credential parameter is the activation credential, which would typically be used to protect
// the generated certificate or supply a challenge. The objectName parameter is the name of object
// for which a certificate is requested. The public part of this object would normally be validated
// by the certificate authority to ensure that it has the properties expected of an attestation key
// (it is a restricted, non-duplicable signing key).
//
// If context does not correspond to an asymmetric restricted decrypt key, a *[TPMHandleError]
// error with an error code of [ErrorType] is returned.
//
// If the size of credential is larger than the name algorithm associated with context, a
// *[TPMParameterError] error with an error code of [ErrorSize] will be returned for parameter
// index 1.
//
// If the algorithm of the object associated with context is [ObjectTypeECC], a *[TPMError] with an
// error code of [ErrorKey] will be returned if the ECC key is invalid. If the algorithm of the
// object associated with context is [ObjectTypeRSA], a *[TPMError] with an error code of
// [ErrorScheme] will be returned if the padding scheme is invalid or not supported.
//
// On success, the encrypted and integrity protected activation credential is returned as
// IDObject (see section 24 - "Credential Protection" of Part 1 of the Trusted Platform Module
// Library specification). A secret which can be used by the private part of the key associated
// with context to recover the seed used to protect the credential (using the
// TPM2_ActivateCredential command) is returned as EncryptedSecret.
func (t *TPMContext) MakeCredential(context ResourceContext, credential Digest, objectName Name, sessions ...SessionContext) (credentialBlob IDObject, secret EncryptedSecret, err error) {
	if err := t.StartCommand(CommandMakeCredential).
		AddHandles(UseHandleContext(context)).
		AddParams(credential, objectName).
		AddExtraSessions(sessions...).
		Run(nil, &credentialBlob, &secret); err != nil {
		return nil, nil, err
	}
	return credentialBlob, secret, nil
}

// Unseal executes the TPM2_Unseal command to decrypt the sealed data object associated with
// itemContext and retrieve its sensitive data. The command requires authorization with the user
// auth role for itemContext, with session based authorization provided via itemContextAuthSession.
//
// If the type of object associated with itemContext is not [ObjectTypeKeyedHash], a
// *[TPMHandleError] error with an error code of [ErrorType] will be returned. If the object
// associated with itemContext has either the [AttrDecrypt], [AttrSign] or [AttrRestricted]
// attributes set, a *[TPMHandleError] error with an error code of [ErrorAttributes] will be
// returned.
//
// On success, the object's sensitive data is returned in decrypted form.
func (t *TPMContext) Unseal(itemContext ResourceContext, itemContextAuthSession SessionContext, sessions ...SessionContext) (outData SensitiveData, err error) {
	if err := t.StartCommand(CommandUnseal).
		AddHandles(UseResourceContextWithAuth(itemContext, itemContextAuthSession)).
		AddExtraSessions(sessions...).
		Run(nil, &outData); err != nil {
		return nil, err
	}

	return outData, nil
}

// ObjectChangeAuth executes the TPM2_ObjectChangeAuth to change the authorization value of the
// object associated with objectContext. This command requires authorization with the admin role
// for objectContext, with sessio based authorization provided via objectContextAuthSession.
//
// The new authorization value is provided via newAuth. The parentContext parameter must
// correspond to the parent object for objectContext. No authorization is required for
// parentContext.
//
// If the object associated with objectContext is a sequence object, a *[TPMHandleError] error with
// an error code of ErrorType will be returned for handle index 1.
//
// If the length of newAuth is longer than the name algorithm for objectContext, a
// *[TPMParameterError] error with an error code of [ErrorSize] will be returned.
//
// If the object associated with parentContext is not the parent object of objectContext, a
// *[TPMHandleError] error with an error code of [ErrorType] will be returned for handle index 2.
//
// On success, this returns a new private area for the object associated with objectContext. This
// function does not make any changes to the version of the object that is currently loaded in to
// the TPM.
func (t *TPMContext) ObjectChangeAuth(objectContext, parentContext ResourceContext, newAuth Auth, objectContextAuthSession SessionContext, sessions ...SessionContext) (outPrivate Private, err error) {
	if err := t.StartCommand(CommandObjectChangeAuth).
		AddHandles(UseResourceContextWithAuth(objectContext, objectContextAuthSession), UseHandleContext(parentContext)).
		AddParams(newAuth).
		AddExtraSessions(sessions...).
		Run(nil, &outPrivate); err != nil {
		return nil, err
	}

	return outPrivate, nil
}

// CreateLoaded executes the TPM2_CreateLoaded command to create a new primary, ordinary or derived
// object. To create a new primary object, parentContext should correspond to a hierarchy. To
// create a new ordinary object, parentContext should correspond to a storage parent. To create a
// new derived object, parentContext should correspond to a derivation parent.
//
// The command requires authorization with the user auth role for parentContext, with session based
// authorization provided via parentContextAuthSession.
//
// A template for the object is provided via the inPublic parameter. Because of the way that this
// parameter is handled by the TPM spec, the parameter is an interface that serializes the actual
// template. The interface is implemented by both the [Public] and [PublicDerived] types.
//
// The Type field of the template defines the algorithm for the object. The NameAlg field defines
// the digest algorithm for computing the name of the object. The Attrs field defines the
// attributes of the object. The AuthPolicy field allows an authorization policy to be defined for
// the new object.
//
// Data that will form part of the sensitive area of the object can be provided via inSensitive,
// which is optional.
//
// If parentContext does not correspond to a derivation parent and the Attrs field of of the
// template does not have the [AttrSensitiveDataOrigin] attribute set, then the sensitive data in
// the created object is initialized with the data provided via the Data field of inSensitive.
//
// If the Attrs field of the template has the [AttrSensitiveDataOrigin] attribute set and Type is
// [ObjectTypeSymCipher], then the sensitive data in the created object is initialized with a TPM
// generated key. The size of this key is determined by the symmetric algorithm defined in the
// Params field of the template. If Type is [ObjectTypeKeyedHash], then the sensitive data in the
// created object is initialized with a TPM generated value that is the same size as the name
// algorithm selected by the NameAlg field of the template.
//
// If the Type field of the template is [ObjectTypeRSA] then the sensitive data in the created
// object is initialized with a TPM generated private key. The size of this is determined by the
// asymmetric algorithm defined in the Params field of the template.
//
// If the Type field of the template is [ObjectTypeECC] and parentContext does not correspond to a
// derivation parent, then the sensitive data in the created object is initialized with a TPM
// generated private key. The size of this is determined by the asymmetric algorithm defined in
// the Params field of the template.
//
// If parentContext corresponds to a derivation parent, the sensitive data in the created object is
// initialized with a value derived from the parent object's private seed, and the derivation
// values specified in either the Unique field of the template or the Data field of inSensitive.
//
// If the Type field of the template is [ObjectTypeKeyedHash], the Attrs field has
// [AttrSensitiveDataOrigin], [AttrSign] and [AttrDecrypt] all clear, then the created object is a
// sealed data object.
//
// If the Attrs field of the template has the [AttrRestricted] and [AttrDecrypt] attributes set,
// and the Type field is not [ObjectTypeKeyedHash], then the newly created object will be a storage
// parent.
//
// If the Attrs field of the template has the [AttrRestricted] and [AttrDecrypt] attributes set,
// and the Type field is [ObjectTypeKeyedHash], then the newly created object will be a derivation
// parent.
//
// The authorization value for the created object is initialized to the value of the UserAuth field
// of inSensitive.
//
// If parentContext corresponds to an object and it isn't a valid storage parent or derivation
// parent, *[TPMHandleError] error with an error code of [ErrorType] will be returned for handle
// index 1.
//
// If there are no available slots for new objects on the TPM, a *[TPMWarning] error with a warning
// code of [WarningObjectMemory] will be returned.
//
// If the attributes in the Attrs field of the template are inconsistent or inappropriate for the
// usage, a *[TPMParameterError] error with an error code of [ErrorAttributes] will be returned for
// parameter index 2.
//
// If the NameAlg field of the template is [HashAlgorithmNull], then a *[TPMParameterError] error
// with an error code of [ErrorHash] will be returned for parameter index 2.
//
// If an authorization policy is defined via the AuthPolicy field of the template then the length
// of the digest must match the name algorithm selected via the NameAlg field, else a
// *[TPMParameterError] error with an error code of [ErrorSize] is returned for parameter index 2.
//
// If the scheme in the Params field of the template is inappropriate for the usage, a
// *[TPMParameterError] errow with an error code of [ErrorScheme] will be returned for parameter
// index 2.
//
// If the Type field of the template is [ObjectTypeRSA], [ObjectTypeECC] or [ObjectTypeKeyedHash]
// and the digest algorithm specified by the scheme in the Params field of the template is
// inappropriate for the usage, a *[TPMParameterError] error with an error code of [ErrorHash] will
// be returned for parameter index 2.
//
// If the Type field of the template is not [ObjectTypeKeyedHash], a *[TPMParameterError] error
// with an error code of [ErrorSymmetric] will be returned for parameter index 2 if the symmetric
// algorithm specified in the Params field of the template is inappropriate for the usage.
//
// If the Type field of the template is [ObjectTypeECC] and the KDF scheme specified in the Params
// field is not [KDFAlgorithmNull], a *[TPMParameterError] error with an error code of [ErrorKDF]
// will be returned for parameter index 2.
//
// If the Type field of the template is not [ObjectTypeKeyedHash] and the [AttrRestricted],
// [AttrFixedParent] and [AttrDecrypt] attributes of Attrs are set, a *[TPMParameterError] error
// with an error code of [ErrorHash] will be returned for parameter index 2 if the NameAlg field of
// the template does not select the same name algorithm as the parent object. A
// *[TPMParameterError] error with an error code of [ErrorSymmetric] will be returned for parameter
// index 2 if the symmetric algorithm specified in the Params field of the template does not match
// the symmetric algorithm of the parent object.
//
// If the length of the UserAuth field of inSensitive is longer than the name algorithm selected by
// the NameAlg field of the template, a *[TPMParameterError] error with an error code of
// [ErrorSize] will be returned for parameter index 1.
//
// If the Type field of the template is [ObjectTypeRSA] and the Params field specifies an
// unsupported exponent, a *[TPMError] with an error code of [ErrorRange] will be returned. If the
// specified key size is an unsupported value, a *[TPMError] with an error code of [ErrorValue]
// will be returned.
//
// If the Type field of the template is [ObjectTypeSymCipher] and the key size is an unsupported
// value, a *[TPMError] with an error code of [ErrorKeySize] will be returned. If the
// [AttrSensitiveDataOrigin] attribute is not set and the length of the Data field of inSensitive
// does not match the key size specified in the Params field of the template, a *[TPMError] with an
// error code of [ErrorKeySize] will be returned.
//
// If the Type field of the template is [ObjectTypeKeyedHash] and the [AttrSensitiveDataOrigin]
// attribute is not set, a *[TPMError] with an error code of [ErrorSize] will be returned if the
// length of the Data field of inSensitive is longer than permitted for the digest algorithm
// selected by the specified scheme.
//
// On success, a ResourceContext instance will be returned that corresponds to the newly created
// object on the TPM, along with the private and public parts.  It will not be necessary to call
// [ResourceContext].SetAuthValue on the returned ResourceContext - this function sets the correct
// authorization value so that it can be used in subsequent commands that require knowledge of the
// authorization value. If the Type field of the template is [ObjectTypeKeyedHash] or
// [ObjectTypeSymCipher], then the returned *Public object will have a Unique field that is the
// digest of the sensitive data and the value of the object's seed in the sensitive area, computed
// using the object's name algorithm. If the Type field of the template is [ObjectTypeECC] or
// [ObjectTypeRSA], then the returned *Public object will have a Unique field containing details
// about the public part of the key, computed from the private part of the key.
func (t *TPMContext) CreateLoaded(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic PublicTemplate, parentContextAuthSession SessionContext, sessions ...SessionContext) (objectContext ResourceContext, outPrivate Private, outPublic *Public, err error) {
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	if inPublic == nil {
		return nil, nil, nil, makeInvalidArgError("inPublic", "nil value")
	}

	inTemplate, err := inPublic.ToTemplate()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot marshal public template: %v", err)
	}

	var objectHandle Handle
	var name Name

	if err := t.StartCommand(CommandCreateLoaded).
		AddHandles(UseResourceContextWithAuth(parentContext, parentContextAuthSession)).
		AddParams(mu.Sized(inSensitive), inTemplate).
		AddExtraSessions(sessions...).
		Run(&objectHandle, &outPrivate, mu.Sized(&outPublic), &name); err != nil {
		return nil, nil, nil, err
	}

	if objectHandle.Type() != HandleTypeTransient {
		return nil, nil, nil, &InvalidResponseError{CommandCreateLoaded,
			fmt.Errorf("handle 0x%08x returned from TPM is the wrong type", objectHandle)}
	}
	if outPublic == nil {
		return nil, nil, nil, &InvalidResponseError{CommandCreateLoaded, errors.New("no public area returned from TPM")}
	}
	if outPublic.NameAlg.Available() && !outPublic.compareName(name) {
		return nil, nil, nil, &InvalidResponseError{CommandCreateLoaded, errors.New("name and public area returned from TPM are not consistent")}
	}

	var public *Public
	if err := mu.CopyValue(&public, outPublic); err != nil {
		return nil, nil, nil, &InvalidResponseError{CommandCreateLoaded, fmt.Errorf("cannot copy returned public area from TPM: %w", err)}
	}
	rc := newObjectContext(objectHandle, name, public)
	rc.authValue = make([]byte, len(inSensitive.UserAuth))
	copy(rc.authValue, inSensitive.UserAuth)

	return rc, outPrivate, outPublic, nil
}
