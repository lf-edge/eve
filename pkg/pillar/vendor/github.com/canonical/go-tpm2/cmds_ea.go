// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 23 - Enhanced Authorization (EA) Commands

// PolicySigned executes the TPM2_PolicySigned command to include a signed authorization in a
// policy. This is a combined assertion that binds a policy to the signing key associated with
// authContext.
//
// An authorizing entity signs a digest of authorization qualifiers with the key associated with
// authContext. The digest is computed as:
//
//	digest := H(nonceTPM||expiration||cpHashA||policyRef)
//
// ... where H is the digest algorithm associated with the auth parameter.
//
// Where there are no restrictions, the digest is computed from 4 zero bytes, which corresponds to
// an expiration time of zero. The authorization qualifiers must match the arguments passed to this
// command. The signature is provided via the auth parameter.
//
// The signature can be created using [github.com/canonical/go-tpm2/util.SignPolicyAuthorization].
//
// If includeNonceTPM is set to true, this function includes the most recently received TPM nonce
// value for the session associated with policySession as the first command parameter. In this
// case, the nonce value must be included in the digest that is signed by the authorizing entity.
// The current nonce value can be obtained and sent to the signer by calling
// [SessionContext].NonceTPM
//
// The cpHashA parameter allows the session to be bound to a specific command and set of command
// parameters by providing a command parameter digest. Command parameter digests can be computed
// using [github.com/canonical/go-tpm2/util.ComputeCpHash], using the digest algorithm for the
// session. If provided, the cpHashA value must be included in the digest that is signed by the
// authorizing entity. Note that this only binds the use of the session to a specific set of command
// parameters - this assertion cannot be used to bind a policy to a specific set of command
// parameters. For that, use [TPMContext.PolicyCpHash]. If the cpHashA parameter is not provided,
// the session is not bound to a specific command and set of command parameters.
//
// If policySession does not correspond to a trial session and cpHashA is supplied, a *[TPMError]
// error with an error code of [ErrorCpHash] will be returned if the session context already has a
// command parameter digest, name digest or template digest recorded on it and cpHashA does not
// match it.
//
// If policySession does not correspond to a trial session, cpHashA is supplied and its length does
// not match the digest algorithm for the session, a *[TPMParameterError] error with an error code
// of [ErrorSize] will be returned for parameter index 2.
//
// If the expiration parameter is not 0, it sets a timeout based on the absolute value of
// expiration in seconds, by which time the authorization will expire. If includeNonceTPM is true
// then the timeout is measured from the time that the current TPM nonce was generated for the
// session, else it is measured from the time that this command is executed. If the session
// associated with policySession is not a trial session and expiration corresponds to a time in the
// past, or the TPM's time epoch has changed since the session was started, a *[TPMParameterError]
// error with an error code of [ErrorExpired] will be returned for parameter index 4.
//
// If the session associated with policySession is not a trial session and the signing scheme or
// digest algorithm associated with the auth parameter is not supported by the TPM, a
// *[TPMParameterError] error with an error code of ErrorScheme will be returned for parameter
// index 5.
//
// If the session associated with policySession is not a trial session, the signature will be
// validated against a digest computed from the provided arguments, using the key associated with
// authContext. If the signature is invalid, a *[TPMParameterError] error with an error code of
// [ErrorSignature] will be returned for parameter index 5.
//
// On successful completion, the policy digest of the session associated with policySession will be
// extended to include the name of authContext and the value of policyRef. If provided, the value
// of cpHashA will be recorded on the session context to restrict the session's usage. If
// expiration is non-zero, the expiration time of the session context will be updated unless it
// already has an expiration time that is earlier. If expiration is less than zero, a timeout value
// and corresponding *TkAuth ticket will be returned if policySession does not correspond to a
// trial session. If includeNonceTPM is false, the returned ticket will expire on the next TPM
// reset if that occurs before the timeout.
func (t *TPMContext) PolicySigned(authContext ResourceContext, policySession SessionContext, includeNonceTPM bool, cpHashA Digest, policyRef Nonce, expiration int32, auth *Signature, sessions ...SessionContext) (timeout Timeout, policyTicket *TkAuth, err error) {
	var nonceTPM Nonce
	if includeNonceTPM {
		nonceTPM = policySession.NonceTPM()
	}

	if err := t.StartCommand(CommandPolicySigned).
		AddHandles(UseHandleContext(authContext), UseHandleContext(policySession)).
		AddParams(nonceTPM, cpHashA, policyRef, expiration, auth).
		AddExtraSessions(sessions...).
		Run(nil, &timeout, &policyTicket); err != nil {
		return nil, nil, err
	}

	return timeout, policyTicket, nil
}

// PolicySecret executes the TPM2_PolicySecret command to include a secret-based authorization to
// the policy session associated with policySession, and is a combined assertion. The command
// requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If authContextAuthSession corresponds a
// policy session, and that session does not include a TPM2_PolicyPassword or TPM2_PolicyAuthValue
// assertion, a *[TPMSessionError] error with an error code of [ErrorMode] will be returned for
// session index 1.
//
// This function includes the most recently received TPM nonce value for the session associated
// with policySession as the first command parameter.
//
// The cpHashA parameter allows the session to be bound to a specific command and set of command
// parameters by providing a command parameter digest. Command parameter digests can be computed
// using [github.com/canonical/go-tpm2/util.ComputeCpHash], using the digest algorithm for the
// session. Note that this only binds the use of the session to a specific set of command
// parameters - this assertion cannot be used to bind a policy to a specific set of command
// parameters. For that, use [TPMContext.PolicyCpHash].  If the cpHashA parameter is not provided,
// the session is not bound to a specific command and set of command parameters.
//
// If policySession does not correspond to a trial session and cpHashA is supplied, a *[TPMError]
// error with an error code of [ErrorCpHash] will be returned if the session context already has a
// command parameter digest, name digest or template digest recorded on it and cpHashA does not
// match it.
//
// If policySession does not correspond to a trial session, cpHashA is supplied and its length does
// not match the digest algorithm for the session, a *[TPMParameterError] error with an error code
// of [ErrorSize] will be returned for parameter index 2.
//
// If the expiration parameter is not 0, it sets a timeout based on the absolute value of
// expiration in seconds, by which time the authorization will expire. The timeout is measured from
// the time that the current TPM nonce was generated for the session. If the session associated
// with policySession is not a trial session and expiration corresponds to a time in the past, or
// the TPM's time epoch has changed since the session was started, a *[TPMParameterError] error
// with an error code of [ErrorExpired] will be returned for parameter index 4.
//
// On successful completion, knowledge of the authorization value associated with authContext is
// proven. The policy digest of the session associated with policySession will be extended to
// include the name of authContext and the value of policyRef. If provided, the value of cpHashA
// will be recorded on the session context to restrict the session's usage. If expiration is
// non-zero, the expiration time of the session context will be updated unless it already has an
// expiration time that is earlier. If expiration is less than zero, a timeout value and
// corresponding *TkAuth ticket will be returned if policySession does not correspond to a trial
// session.
func (t *TPMContext) PolicySecret(authContext ResourceContext, policySession SessionContext, cpHashA Digest, policyRef Nonce, expiration int32, authContextAuthSession SessionContext, sessions ...SessionContext) (timeout Timeout, policyTicket *TkAuth, err error) {
	if err := t.StartCommand(CommandPolicySecret).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(policySession)).
		AddParams(policySession.NonceTPM(), cpHashA, policyRef, expiration).
		AddExtraSessions(sessions...).
		Run(nil, &timeout, &policyTicket); err != nil {
		return nil, nil, err
	}

	return timeout, policyTicket, nil
}

// PolicyTicket executes the TPM2_PolicyTicket command, and behaves similarly to
// [TPMContext.PolicySigned] with the exception that it takes an authorization ticket rather than a
// signed authorization. The ticket parameter represents a valid authorization with an expiration
// time, and will have been returned from a previous call to [TPMContext.PolicySigned] or
// [TPMContext.PolicySecret] when called with an expiration time of less than zero.
//
// If policySession corresponds to a trial session, a *[TPMHandleError] error with an error code of
// [ErrorAttributes] will be returned.
//
// If the size of timeout is not the expected size, a *[TPMParameterError] with an error code of
// [ErrorSize] will be returned for parameter index 1.
//
// A *[TPMError] error with an error code of [ErrorCpHash] will be returned if cpHashA is supplied
// and the session context already has a command parameter digest, name digest or template digest
// recorded on it and cpHashA does not match it.
//
// The cpHashA and policyRef arguments must match the values passed to the command that originally
// produced the ticket. If the command that produced the ticket was [TPMContext.PolicySecret],
// authName must correspond to the name of the entity of which knowledge of the authorization value
// was proven. If the command that produced the ticket was [TPMContext.PolicySigned], authName must
// correspond to the name of the key that produced the signed authorization.
//
// If the ticket is invalid, a *[TPMParameterError] error with an error code of [ErrorTicket] will
// be returned for parameter index 5. If the ticket corresponds to an authorization that has
// expired, a *[TPMParameterError] error with an error code of [ErrorExpired] will be returned for
// parameter index 1.
//
// On successful verification of the ticket, the policy digest of the session context associated
// with policySession will be extended with the same values that the command that produced the
// ticket would extend it with. If provided, the value of cpHashA will be recorded on the session
// context to restrict the session's usage. The expiration time of the session context will be
// updated with the value of timeout, unless it already has an expiration time that is earlier.
func (t *TPMContext) PolicyTicket(policySession SessionContext, timeout Timeout, cpHashA Digest, policyRef Nonce, authName Name, ticket *TkAuth, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyTicket).
		AddHandles(UseHandleContext(policySession)).
		AddParams(timeout, cpHashA, policyRef, authName, ticket).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyOR executes the TPM2_PolicyOR command to allow a policy to be satisfied by different sets
// of conditions, and is an immediate assertion. If policySession does not correspond to a trial
// session, it determines if the current policy digest of the session context associated with
// policySession is contained in the list of digests specified via pHashList. If it is not, then a
// *[TPMParameterError] error with an error code of [ErrorValue] is returned without making any
// changes to the session context.
//
// On successful completion, the policy digest of the session context associated with policySession
// is cleared, and then extended to include a digest of the concatenation of all of the digests
// contained in pHashList.
func (t *TPMContext) PolicyOR(policySession SessionContext, pHashList DigestList, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyOR).
		AddHandles(UseHandleContext(policySession)).
		AddParams(pHashList).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyPCR executes the TPM2_PolicyPCR command to gate a policy based on the values of the PCRs
// selected via the pcrs parameter. If no digest has been specified via the pcrDigest parameter,
// then it is a deferred assertion and the policy digest of the session context associated with
// policySession will be extended to include the value of the PCR selection and a digest computed
// from the selected PCR contents.
//
// If pcrDigest is provided, then it is a combined assertion. If policySession does not correspond
// to a trial session, the digest computed from the selected PCRs will be compared to the value of
// pcrDigest and a *[TPMParameterError] error with an error code of [ErrorValue] will be returned
// for parameter index 1 if they don't match, without making any changes to the session context. If
// policySession corresponds to a trial session, the digest computed from the selected PCRs is not
// compared to the value of pcrDigest; instead, the policy digest of the session is extended to
// include the value of the PCR selection and the value of pcrDigest.
//
// If the PCR contents have changed since the last time this command was executed for this session,
// a *[TPMError] error will be returned with an error code of [ErrorPCRChanged].
//
// This function will call [TPMContext.InitProperties] if it hasn't already been called.
func (t *TPMContext) PolicyPCR(policySession SessionContext, pcrDigest Digest, pcrs PCRSelectionList, sessions ...SessionContext) error {
	if err := t.initPropertiesIfNeeded(); err != nil {
		return err
	}

	return t.StartCommand(CommandPolicyPCR).
		AddHandles(UseHandleContext(policySession)).
		AddParams(pcrDigest, pcrs.WithMinSelectSize(t.minPcrSelectSize)).
		AddExtraSessions(sessions...).
		Run(nil)
}

// func (t *TPMContext) PolicyLocality(policySession HandleContext, locality Locality, sessions ...SessionContext) error {
// }

// PolicyNV executes the TPM2_PolicyNV command to gate a policy based on the contents of the NV
// index associated with nvIndex, and is an immediate assertion. The caller specifies a value to be
// used for the comparison via the operandB argument, an offset from the start of the NV index data
// from which to start the comparison via the offset argument, and a comparison operator via the
// operation argument.
//
// The command requires authorization to read the NV index, defined by the state of the
// [AttrNVPPRead], [AttrNVOwnerRead], [AttrNVAuthRead] and [AttrNVPolicyRead] attributes. The
// handle used for authorization is specified via authContext. If the NV index has the
// [AttrNVPPRead] attribute, authorization can be satisfied with [HandlePlatform]. If the NV index
// has the [AttrNVOwnerRead] attribute, authorization can be satisfied with [HandleOwner]. If the
// NV index has the [AttrNVAuthRead] or [AttrNVPolicyRead] attribute, authorization can be
// satisfied with nvIndex. The command requires authorization with the user auth role for
// authContext, with session based authorization provided via authContextAuthSession. If the
// resource associated with authContext is not permitted to authorize this access and policySession
// does not correspond to a trial session, a *[TPMError] error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthRead] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyRead] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index associated with nvIndex has the [AttrNVReadLocked] attribute set and policySession
// does not correspond to a trial session, a *[TPMError] error with an error code of
// [ErrorNVLocked] will be returned.
//
// If the index associated with nvIndex has not been initialized (ie, the [AttrNVWritten] attribute
// is not set) and policySession does not correspond to a trial session, a *[TPMError] with an
// error code of [ErrorNVUninitialized] will be returned.
//
// If the session associated with policySession is not a trial session and offset is outside of the
// bounds of the NV index, a *[TPMParameterError] error with an error code of [ErrorValue] is
// returned for paramter index 2.
//
// If the session associated with policySession is not a trial session and the size of operandB in
// combination with the value of offset would result in a read outside of the bounds of the NV
// index, a *[TPMParameterError] error with an error code of [ErrorSize] is returned for paramter
// index 1.
//
// If the comparison fails and policySession does not correspond to a trial session, a *[TPMError]
// error will be returned with an error code of [ErrorPolicy].
//
// On successful completion, the policy digest of the session context associated with policySession
// is extended to include the values of operandB, offset, operation and the name of nvIndex.
func (t *TPMContext) PolicyNV(authContext, nvIndex ResourceContext, policySession SessionContext, operandB Operand, offset uint16, operation ArithmeticOp, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyNV).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex), UseHandleContext(policySession)).
		AddParams(operandB, offset, operation).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyCounterTimer executes the TPM2_PolicyCounterTimer command to gate a policy based on the
// contents of the [TimeInfo] structure, and is an immediate assertion. The caller specifies a
// value to be used for the comparison via the operandB argument, an offset from the start of the
// [TimeInfo] structure from which to start the comparison via the offset argument, and a
// comparison operator via the operation argument.
//
// If the comparison fails and policySession does not correspond to a trial session, a *[TPMError]
// error will be returned with an error code of [ErrorPolicy].
//
// On successful completion, the policy digest of the session context associated with policySession
// is extended to include the values of operandB, offset and operation.
func (t *TPMContext) PolicyCounterTimer(policySession SessionContext, operandB Operand, offset uint16, operation ArithmeticOp, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyCounterTimer).
		AddHandles(UseHandleContext(policySession)).
		AddParams(operandB, offset, operation).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyCommandCode executes the TPM2_PolicyCommandCode command to indicate that an authorization
// policy should be limited to a specific command. Ths is a deferred assertion.
//
// If the command code is not implemented, a *[TPMParameterError] error with an error code of
// [ErrorPolicyCC] will be returned. If the session associated with policySession has already been
// limited to a different command code, a *[TPMParameterError] error with an error code of
// [ErrorValue] will be returned.
//
// On successful completion, the policy digest of the session context associated with policySession
// will be extended to include the value of the specified command code, and the command code will
// be recorded on the session context to limit usage of the session.
func (t *TPMContext) PolicyCommandCode(policySession SessionContext, code CommandCode, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyCommandCode).
		AddHandles(UseHandleContext(policySession)).
		AddParams(code).
		AddExtraSessions(sessions...).
		Run(nil)
}

// func (t *TPMContext) PolicyPhysicalPresence(policySession HandleContext, sessions ...SessionContext) error {
// }

// PolicyCpHash executes the TPM2_PolicyCpHash command to bind a policy to a specific command and
// set of command parameters. This is a deferred assertion.
//
// [TPMContext.PolicySigned], [TPMContext.PolicySecret] and [TPMContext.PolicyTicket] allow an
// authorizing entity to execute an arbitrary command as the cpHashA parameter is not included in
// the session's policy digest. [TPMContext.PolicyCommandCode] allows the policy to be limited to
// a specific command. This command allows the policy to be limited further to a specific command
// and set of command parameters.
//
// Command parameter digests can be computed using [github.com/canonical/go-tpm2/util.ComputeCpHash],
// using the digest algorithm for the session.
//
// If the size of cpHashA is inconsistent with the digest algorithm for the session, a
// *[TPMParameterError] error with an error code of [ErrorSize] will be returned.
//
// If the session associated with policySession already has a command parameter digest, name digest
// or template digest defined, a *[TPMError] error with an error code of [ErrorCpHash] will be
// returned if cpHashA does not match the digest already recorded on the session context.
//
// On successful completion, the policy digest of the session context associated with policySession
// will be extended to include the value of cpHashA, and the value of cpHashA will be recorded on
// the session context to limit usage of the session to the specific command and set of command
// parameters.
func (t *TPMContext) PolicyCpHash(policySession SessionContext, cpHashA Digest, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyCpHash).
		AddHandles(UseHandleContext(policySession)).
		AddParams(cpHashA).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyNameHash executes the TPM2_PolicyNameHash command to bind a policy to a specific set of
// TPM entities, without being bound to the parameters of the command. This is a deferred
// assertion.
//
// If the size of nameHash is inconsistent with the digest algorithm for the session, a
// *[TPMParameterError] error with an error code of [ErrorSize] will be returned.
//
// If the session associated with policySession already has a name digest, command parameter
// digest or template digest defined, a *[TPMError] error with an error code of [ErrorCpHash] will
// be returned.
//
// On successful completion, the policy digest of the session context associated with policySession
// will be extended to include the value of nameHash, and the value of nameHash will be recorded on
// the session context to limit usage of the session to the specific set of TPM entities.
func (t *TPMContext) PolicyNameHash(policySession SessionContext, nameHash Digest, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyNameHash).
		AddHandles(UseHandleContext(policySession)).
		AddParams(nameHash).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyDuplicationSelect executes the TPM2_PolicyDuplicationSelect command to allow the policy to
// be restricted to duplication and to allow duplication to a specific new parent. The objectName
// argument corresponds to the name of the object to be duplicated. The newParentName argument
// corresponds to the name of the new parent object. This is a deferred assertion.
//
// If the session associated with policySession already has a command parameter digest, name digest
// or template digest defined, a *[TPMError] error with an error code of [ErrorCpHash] will be
// returned.
//
// If the session associated with policySession has already been limited to a specific command
// code, a *[TPMError] error with an error code of [ErrorCommandCode] will be returned.
//
// On successful completion, the policy digest of the session context associated with policySession
// will be extended to include the value of newParentName and includeObject. If includeObject is
// true, the policy digest of the session will be extended to also include the value of objectName.
// A digest of objectName and newParentName will be recorded as the name hash on the session
// context to limit usage of the session to those entities, and the [CommandDuplicate] command code
// will be recorded to limit usage of the session to [TPMContext.Duplicate].
func (t *TPMContext) PolicyDuplicationSelect(policySession SessionContext, objectName, newParentName Name, includeObject bool, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyDuplicationSelect).
		AddHandles(UseHandleContext(policySession)).
		AddParams(objectName, newParentName, includeObject).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyAuthorize executes the TPM2_PolicyAuthorize command, which allows policies to change. This
// is an immediate assertion. The command allows an authorizing entity to sign a new policy that
// can be used in an existing policy. The authorizing party signs a digest that is computed as
// follows:
//
//	digest := H(approvedPolicy||policyRef)
//
// ... where H is the name algorithm of the key used to sign the digest.
//
// The signature can be created by [github.com/canonical/go-tpm2/util.PolicyAuthorize].
// The unsigned digest can be created by [github.com/canonical/go-tpm2/util.ComputePolicyAuthorizeDigest].
//
// The signature is then verified by [TPMContext.VerifySignature], which provides a ticket that is
// used by this function.
//
// If the name algorithm of the signing key is not supported, a *[TPMParameterError] error with an
// error code of [ErrorHash] will be returned for parameter index 3.
//
// If the length of keySign does not match the length of the name algorithm, a *[TPMParameterError]
// error with an error code of [ErrorSize] will be returned for parameter index 3.
//
// If policySession is not associated with a trial session, the current digest of the session
// associated with policySession will be compared with approvedPolicy. If they don't match, then a
// *[TPMParameterError] error with an error code of [ErrorValue] will be returned for parameter
// index 1.
//
// If policySession is not associated with a trial session and checkTicket is invalid, a
// *[TPMParameterError] error with an error code of [ErrorValue] will be returned for parameter
// index 4.
//
// On successful completion, the policy digest of the session context associated with policySession
// is cleared, and then extended to include the value of keySign and policyRef.
func (t *TPMContext) PolicyAuthorize(policySession SessionContext, approvedPolicy Digest, policyRef Nonce, keySign Name, checkTicket *TkVerified, sessions ...SessionContext) error {
	if checkTicket == nil {
		checkTicket = &TkVerified{Tag: TagVerified, Hierarchy: HandleNull}
	}

	return t.StartCommand(CommandPolicyAuthorize).
		AddHandles(UseHandleContext(policySession)).
		AddParams(approvedPolicy, policyRef, keySign, checkTicket).
		AddExtraSessions(sessions...).
		Run(nil)
}

// PolicyAuthValue executes the TPM2_PolicyAuthValue command to bind the policy to the
// authorization value of the entity on which the authorization is used. This is a deferred
// assertion. On successful completion, the policy digest of the session context associated with
// policySession will be extended to record that this assertion has been executed, and a flag will
// be set on the session context to indicate that the authorization value of the entity on which
// the authorization is used must be included in the key for computing the command HMAC when the
// session is used.
//
// When using policySession in a subsequent authorization, the authorization value of the entity
// being authorized must be provided by calling [ResourceContext].SetAuthValue.
func (t *TPMContext) PolicyAuthValue(policySession SessionContext, sessions ...SessionContext) error {
	sessionData := policySession.(sessionContextInternal).Data()
	if sessionData == nil {
		return makeInvalidArgError("policySession", "incomplete session can only be used in TPMContext.FlushContext")
	}

	if err := t.StartCommand(CommandPolicyAuthValue).
		AddHandles(UseHandleContext(policySession)).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	sessionData.PolicyHMACType = policyHMACTypeAuth
	return nil
}

// PolicyPassword executes the TPM2_PolicyPassword command to bind the policy to the authorization
// value of the entity on which the authorization is used. This is a deferred assertion. On
// successful completion, the policy digest of the session context associated with policySession
// will be extended to record that this assertion has been executed, and a flag will be set on the
// session context to indicate that the authorization value of the entity on which the
// authorization is used must be included in cleartext in the command authorization when the
// session is used.
//
// When using policySession in a subsequent authorization, the authorization value of the entity
// being authorized must be provided by calling [ResourceContext].SetAuthValue.
func (t *TPMContext) PolicyPassword(policySession SessionContext, sessions ...SessionContext) error {
	sessionData := policySession.(sessionContextInternal).Data()
	if sessionData == nil {
		return makeInvalidArgError("policySession", "incomplete session can only be used in TPMContext.FlushContext")
	}

	if err := t.StartCommand(CommandPolicyPassword).
		AddHandles(UseHandleContext(policySession)).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	sessionData.PolicyHMACType = policyHMACTypePassword
	return nil
}

// PolicyGetDigest executes the TPM2_PolicyGetDigest command to return the current policy digest of
// the session context associated with policySession.
func (t *TPMContext) PolicyGetDigest(policySession SessionContext, sessions ...SessionContext) (policyDigest Digest, err error) {
	if err := t.StartCommand(CommandPolicyGetDigest).
		AddHandles(UseHandleContext(policySession)).
		AddExtraSessions(sessions...).
		Run(nil, &policyDigest); err != nil {
		return nil, err
	}

	return policyDigest, nil
}

// PolicyNvWritten executes the TPM2_PolicyNvWritten command to bind a policy to the value of the
// [AttrNVWritten] attribute of the NV index being authorized, and is a deferred assertion.
//
// If this command has been executed previously in this session, and the value of writtenSet
// doesn't match the value provided previously, a *[TPMParameterError] error with an error code of
// [ErrorValue] will be returned.
//
// On successful completion, the policy digest of the session associated with policySession will be
// extended to include the value of writtenSet. A flag will be set on the session context so that
// the value of the [AttrNVWritten] attribute of the NV index being authorized will be compared to
// writtenSet when the session is used.
func (t *TPMContext) PolicyNvWritten(policySession SessionContext, writtenSet bool, sessions ...SessionContext) error {
	return t.StartCommand(CommandPolicyNvWritten).
		AddHandles(UseHandleContext(policySession)).
		AddParams(writtenSet).
		AddExtraSessions(sessions...).
		Run(nil)
}

// func (t *TPMContext) PolicyTemplate(policySession HandleContext, templateHash Digest, sessions ...SessionContext) error {
// }

// func (t *TPMContext) PolicyAuthorizeNV(authContext, nvIndex, policySession HandleContext, authContextAuth interface{}, sessions ...SessionContext) error {
// }
