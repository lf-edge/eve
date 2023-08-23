// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"github.com/canonical/go-tpm2/mu"
)

// Section 18 - Attestation Commands

// Certify executes the TPM2_Certify command, which is used to prove that an object with a specific
// name is loaded in to the TPM. By producing an attestation, the TPM certifies that the object
// with a given name is loaded in to the TPM and consistent with a valid sensitive area.
//
// The objectContext parameter corresponds to the object for which to produce an attestation. The
// command requires authorization with the admin role for objectContext, with session based
// authorization provided via objectContextAuthSession.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with
// it. This command requires authorization with the user auth role for signContext, with session
// based authorization provided via signContextAuthSession.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a
// *[TPMHandleError] error with an error code of [ErrorKey] will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is
// [AsymSchemeNull], then inScheme must be provided to specify a valid signing scheme for the key.
// If it isn't, a *[TPMParameterError] error with an error code of [ErrorScheme] will be returned
// for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not
// [AsymSchemeNull], then inScheme may be nil. If it is provided, then the specified scheme must
// match that of the signing key, else a *[TPMParameterError] error with an error code of
// [ErrorScheme] will be returned for parameter index 2.
//
// If successful, it returns an attestation structure detailing the name of the object associated
// with objectContext. If signContext is not nil, the attestation structure will be signed by the
// associated key and returned too.
func (t *TPMContext) Certify(objectContext, signContext ResourceContext, qualifyingData Data, inScheme *SigScheme, objectContextAuthSession, signContextAuthSession SessionContext, sessions ...SessionContext) (certifyInfo *Attest, signature *Signature, err error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	if err := t.StartCommand(CommandCertify).
		AddHandles(UseResourceContextWithAuth(objectContext, objectContextAuthSession), UseResourceContextWithAuth(signContext, signContextAuthSession)).
		AddParams(qualifyingData, inScheme).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&certifyInfo), &signature); err != nil {
		return nil, nil, err
	}

	return certifyInfo, signature, nil
}

// CertifyCreation executes the TPM2_CertifyCreation command, which is used to prove the
// association between the object represented by objectContext and its creation data represented by
// creationHash. It does this by computing a ticket from creationHash and the name of the object
// represented by objectContext and then verifying that it matches the provided creationTicket,
// which was provided by the TPM at object creation time.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with
// it. This command requires authorization with the user auth role for signContext, with session
// based authorization provided via signContextAuthSession.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a
// *[TPMHandleError] error with an error code of [ErrorKey] will be returned for handle index 1.
//
// If signContext is not nil and if the scheme of the key associated with signContext is
// [AsymSchemeNull], then inScheme must be provided to specify a valid signing scheme for the key.
// If it isn't, a *[TPMParameterError] error with an error code of [ErrorScheme] will be returned
// for parameter index 3.
//
// If signContext is not nil and the scheme of the key associated with signContext is not
// [AsymSchemeNull], then inScheme may be nil. If it is provided, then the specified scheme must
// match that of the signing key, else a *[TPMParameterError] error with an error code of
// [ErrorScheme] will be returned for parameter index 3.
//
// If creationTicket corresponds to an invalid ticket, a *[TPMParameterError] error with an error
// code of [ErrorTicket] will be returned for parameter index 4.
//
// If the digest generated for signing is greater than or has a larger size than the modulus of
// the key associated with signContext, a *[TPMError] with an error code of [ErrorValue] will be
// returned.
//
// If successful, it returns an attestation structure. If signContext is not nil, the attestation
// structure will be signed by the associated key and returned too.
func (t *TPMContext) CertifyCreation(signContext, objectContext ResourceContext, qualifyingData Data, creationHash Digest, inScheme *SigScheme, creationTicket *TkCreation, signContextAuthSession SessionContext, sessions ...SessionContext) (certifyInfo *Attest, signature *Signature, err error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	if err := t.StartCommand(CommandCertifyCreation).
		AddHandles(UseResourceContextWithAuth(signContext, signContextAuthSession), UseHandleContext(objectContext)).
		AddParams(qualifyingData, creationHash, inScheme, creationTicket).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&certifyInfo), &signature); err != nil {
		return nil, nil, err
	}

	return certifyInfo, signature, nil
}

// Quote executes the TPM2_Quote command in order to quote a set of PCR values. The TPM will hash
// the set of PCRs specified by the pcrs parameter.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with
// it. This command requires authorization with the user auth role for signContext, with session
// based authorization provided via signContextAuthSession.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a
// *[TPMHandleError] error with an error code of [ErrorKey] will be returned for handle index 1.
//
// If signContext is not nil and if the scheme of the key associated with signContext is
// [AsymSchemeNull], then inScheme must be provided to specify a valid signing scheme for the key.
// If it isn't, a *[TPMParameterError] error with an error code of [ErrorScheme] will be returned
// for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not
// [AsymSchemeNull], then inScheme may be nil. If it is provided, then the specified scheme must
// match that of the signing key, else a *[TPMParameterError] error with an error code of
// [ErrorScheme] will be returned for parameter index 2.
//
// This function will call [TPMContext.InitProperties] if it hasn't already been called.
//
// On success, it returns an attestation structure containing the hash of the PCRs selected by the
// pcrs parameter. If signContext is not nil, the attestation structure will be signed by the
// associated key and returned too.
func (t *TPMContext) Quote(signContext ResourceContext, qualifyingData Data, inScheme *SigScheme, pcrs PCRSelectionList, signContextAuthSession SessionContext, sessions ...SessionContext) (quoted *Attest, signature *Signature, err error) {
	if err := t.initPropertiesIfNeeded(); err != nil {
		return nil, nil, err
	}

	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	if err := t.StartCommand(CommandQuote).
		AddHandles(UseResourceContextWithAuth(signContext, signContextAuthSession)).
		AddParams(qualifyingData, inScheme, pcrs.WithMinSelectSize(t.minPcrSelectSize)).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&quoted), &signature); err != nil {
		return nil, nil, err
	}

	return quoted, signature, nil
}

// GetSessionAuditDigest executes the TPM2_GetSessionAuditDigest to obtain the current digest of
// the audit session corresponding to sessionContext.
//
// The privacyAdminContext argument must be a ResourceContext that corresponds to
// [HandleEndorsement]. This command requires authorization with the user auth role for
// privacyAdminContext, with session based authorization provided via
// privacyAdminContextAuthSession.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with
// it. This command requires authorization with the user auth role for signContext, with
// session based authorization provided via signContextAuthSession.
//
// If signContext is not nil and the object associated with signContext is not a signing key,
// a *[TPMHandleError] error with an error code of [ErrorKey] will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is
// [AsymSchemeNull], then inScheme must be provided to specify a valid signing scheme for the key.
// If it isn't, a *[TPMParameterError] error with an error code of [ErrorScheme] will be returned
// for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not
// [AsymSchemeNull], then inScheme may be nil. If it is provided, then the specified scheme must
// match that of the signing key, else a *[TPMParameterError] error with an error code of
// [ErrorScheme] will be returned for parameter index 2.
//
// On success, it returns an attestation structure detailing the current audit digest for
// sessionContext. If signContext is not nil, the attestation structure will be signed by the
// associated key and returned too.
func (t *TPMContext) GetSessionAuditDigest(privacyAdminContext, signContext ResourceContext, sessionContext SessionContext, qualifyingData Data, inScheme *SigScheme, privacyAdminContextAuthSession, signContextAuthSession SessionContext, sessions ...SessionContext) (auditInfo *Attest, signature *Signature, err error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	if err := t.StartCommand(CommandGetSessionAuditDigest).
		AddHandles(UseResourceContextWithAuth(privacyAdminContext, privacyAdminContextAuthSession), UseResourceContextWithAuth(signContext, signContextAuthSession), UseHandleContext(sessionContext)).
		AddParams(qualifyingData, inScheme).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&auditInfo), &signature); err != nil {
		return nil, nil, err
	}

	return auditInfo, signature, nil
}

// GetCommandAuditDigest executes the TPM2_GetCommandAuditDigest command to obtain the current
// command audit digest, the current audit digest algorithm and a digest of the list of commands
// being audited.
//
// The privacyContext argument must be a ResourceContext corresponding to [HandleEndorsement].
// This command requires authorization with the user auth role for privacyContext, with session
// based authorization provided via privacyContextAuthSession.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with
// it. This command requires authorization with the user auth role for signContext, with session
// based authorization provided via provided via signContextAuthSession.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a
// *[TPMHandleError] error with an error code of [ErrorKey] will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is
// [AsymSchemeNull], then inScheme must be provided to specify a valid signing scheme for the key.
// If it isn't, a *[TPMParameterError] error with an error code of [ErrorScheme] will be returned
// for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not
// [AsymSchemeNull], then inScheme may be nil. If it is provided, then the specified scheme must
// match that of the signing key, else a *[TPMParameterError] error with an error code of
// [ErrorScheme] will be returned for parameter index 2.
//
// On success, it returns an attestation structure detailing the current command audit digest,
// digest algorithm and a digest of the list of commands being audited. If signContext is not
// nil, the attestation structure will be signed by the associated key and returned too.
func (t *TPMContext) GetCommandAuditDigest(privacyContext, signContext ResourceContext, qualifyingData Data, inScheme *SigScheme, privacyContextAuthSession, signContextAuthSession SessionContext, sessions ...SessionContext) (auditInfo *Attest, signature *Signature, err error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	if err := t.StartCommand(CommandGetCommandAuditDigest).
		AddHandles(UseResourceContextWithAuth(privacyContext, privacyContextAuthSession), UseResourceContextWithAuth(signContext, signContextAuthSession)).
		AddParams(qualifyingData, inScheme).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&auditInfo), &signature); err != nil {
		return nil, nil, err
	}

	return auditInfo, signature, nil
}

// GetTime executes the TPM2_GetTime command in order to obtain the current values of time and
// clock.
//
// The privacyAdminContext argument must be a ResourceContext that corresponds to
// [HandleEndorsement]. The command requires authorization with the user auth role for
// privacyAdminContext, with session based authorization provided via
// privacyAdminContextAuthSession.
//
// If signContext is not nil, the returned attestation will be signed by the key associated with
// it. This command requires authorization with the user auth role for signContext, with session
// based authorization provided via signContextAuthSession.
//
// If signContext is not nil and the object associated with signContext is not a signing key, a
// *[TPMHandleError] error with an error code of [ErrorKey] will be returned for handle index 2.
//
// If signContext is not nil and if the scheme of the key associated with signContext is
// [AsymSchemeNull], then inScheme must be provided to specify a valid signing scheme for the key.
// If it isn't, a *[TPMParameterError] error with an error code of [ErrorScheme] will be returned
// for parameter index 2.
//
// If signContext is not nil and the scheme of the key associated with signContext is not
// [AsymSchemeNull], then inScheme may be nil. If it is provided, then the specified scheme must
// match that of the signing key, else a *[TPMParameterError] error with an error code of
// [ErrorScheme] will be returned for parameter index 2.
//
// On success, it returns an attestation structure detailing the current values of time and clock.
// If signContext is not nil, the attestation structure will be signed by the associated key and
// returned too.
func (t *TPMContext) GetTime(privacyAdminContext, signContext ResourceContext, qualifyingData Data, inScheme *SigScheme, privacyAdminContextAuthSession, signContextAuthSession SessionContext, sessions ...SessionContext) (timeInfo *Attest, signature *Signature, err error) {
	if inScheme == nil {
		inScheme = &SigScheme{Scheme: SigSchemeAlgNull}
	}

	if err := t.StartCommand(CommandGetTime).
		AddHandles(UseResourceContextWithAuth(privacyAdminContext, privacyAdminContextAuthSession), UseResourceContextWithAuth(signContext, signContextAuthSession)).
		AddParams(qualifyingData, inScheme).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&timeInfo), &signature); err != nil {
		return nil, nil, err
	}

	return timeInfo, signature, nil
}
