// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Secion 20 - Signing and Signature Verification

// VerifySignature executes the TPM2_VerifySignature command to validate the provided signature
// against a message with the provided digest, using the key associated with keyContext. If
// keyContext corresponds to an object that isn't a signing key, a *[TPMHandleError] error with an
// error code of [ErrorAttributes] will be returned.
//
// If the signature is invalid, a *[TPMParameterError] error with an error code of [ErrorSignature]
// will be returned for parameter index 2. If the signature references an unsupported signature
// scheme, a *[TPMParameterError] error with an error code of [ErrorScheme] will be returned for
// parameter index 2.
//
// If keyContext corresponds to a HMAC key but only the public part is loaded, a
// *[TPMParameterError] error with an error code of [ErrorHandle] will be returned for parameter
// index 2.
//
// On success, a valid TkVerified structure will be returned.
func (t *TPMContext) VerifySignature(keyContext ResourceContext, digest Digest, signature *Signature, sessions ...SessionContext) (validation *TkVerified, err error) {
	if err := t.StartCommand(CommandVerifySignature).
		AddHandles(UseHandleContext(keyContext)).
		AddParams(digest, signature).
		AddExtraSessions(sessions...).
		Run(nil, &validation); err != nil {
		return nil, err
	}

	return validation, nil
}

// Sign executes the TPM2_Sign command to sign the provided digest with the key associated with
// keyContext. The function requires authorization with the user auth role for keyContext, with
// session based authorization provided via keyContextAuthSession.
//
// If the object associated with keyContext is not a signing key, a *[TPMHandleError] error with an
// error code of [ErrorKey] will be returned.
//
// If the scheme of the key associated with keyContext is [AsymSchemeNull], then inScheme must be
// provided to specify a valid signing scheme for the key. If it isn't, a *[TPMParameterError]
// error with an error code of [ErrorScheme] will be returned for parameter index 2.
//
// If the scheme of the key associated with keyContext is not [AsymSchemeNull], then inScheme may
// be nil. If it is provided, then the specified scheme must match that of the signing key, else a
// *[TPMParameterError] error with an error code of [ErrorScheme] will be returned for parameter
// index 2.
//
// If the chosen scheme is unsupported, a *[TPMError] error with an error code of [ErrorScheme]
// will be returned.
//
// If the length of digest does not match the size of the digest associated with the selected
// signing scheme, a *[TPMParameterError] error with an error code of [ErrorSize] will be returned
// for parameter index 1.
//
// If the key associated with keyContext has the [AttrRestricted] attribute, then the validation
// parameter must be provided as proof that the supplied digest was created by the TPM. If the key
// associated with keyContext does not have the [AttrRestricted] attribute, then validation may be
// nil. If validation is not nil and doesn't correspond to a valid ticket, or it is nil and the
// key associated with keyContext has the [AttrRestricted] attribute set, a *[TPMParameterError]
// error with an error code of [ErrorTicket] will be returned for parameter index 3.
func (t *TPMContext) Sign(keyContext ResourceContext, digest Digest, inScheme *SigScheme, validation *TkHashcheck, keyContextAuthSession SessionContext, sessions ...SessionContext) (signature *Signature, err error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}
	if validation == nil {
		validation = &TkHashcheck{Tag: TagHashcheck, Hierarchy: HandleNull}
	}

	if err := t.StartCommand(CommandSign).
		AddHandles(UseResourceContextWithAuth(keyContext, keyContextAuthSession)).
		AddParams(digest, inScheme, validation).
		AddExtraSessions(sessions...).
		Run(nil, &signature); err != nil {
		return nil, err
	}

	return signature, nil
}
