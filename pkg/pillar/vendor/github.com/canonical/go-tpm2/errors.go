// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"errors"
	"fmt"
)

const (
	// AnyCommandCode is used to match any command code when using IsTPMError,
	// IsTPMHandleError, IsTPMParameterError, IsTPMSessionError and IsTPMWarning.
	AnyCommandCode CommandCode = 0xc0000000

	// AnyErrorCode is used to match any error code when using IsTPMError,
	// IsTPMHandleError, IsTPMParameterError and IsTPMSessionError.
	AnyErrorCode ErrorCode = 0xff

	// AnyHandle is used to match any handle when using IsResourceUnavailableError.
	AnyHandle Handle = 0xffffffff

	// AnyHandleIndex is used to match any handle when using IsTPMHandleError.
	AnyHandleIndex int = -1

	// AnyParameterIndex is used to match any parameter when using IsTPMParameterError.
	AnyParameterIndex int = -1

	// AnySessionIndex is used to match any session when using IsTPMSessionError.
	AnySessionIndex int = -1

	// AnyWarningCode is used to match any warning code when using IsTPMWarning.
	AnyWarningCode WarningCode = 0xff
)

// ResourceUnavailableError is returned from [TPMContext.NewResourceContext] if it is called with
// a handle that does not correspond to a resource that is available on the TPM. This could be
// because the resource doesn't exist on the TPM, or it lives within a hierarchy that is disabled.
type ResourceUnavailableError struct {
	Handle Handle
}

func (e ResourceUnavailableError) Error() string {
	return fmt.Sprintf("a resource at handle 0x%08x is not available on the TPM", e.Handle)
}

func (e ResourceUnavailableError) Is(target error) bool {
	t, ok := target.(ResourceUnavailableError)
	if !ok {
		return false
	}
	return t.Handle == AnyHandle || t.Handle == e.Handle
}

// InvalidResponseError is returned from any [TPMContext] method that executes a TPM command if the
// TPM's response is invalid. Some examples of invalid responses that would result in this error
// are:
//
//   - The response packet was too large.
//   - The response packet could not be unmarshalled.
//   - The size field in the response header doesn't match the actual size.
//   - The response code and response tag were inconsistent.
//   - An error occurred whilst unmarshalling the response auth area or parameters.
//   - The response auth area or parameter area have unused bytes after unmarshalling.
//   - There were an unexpected number of response auths.
//   - A response auth was invalid.
//
// Any session contexts associated with the command that caused this error should be considered
// invalid.
//
// It is possible that the TPM command completed successfully.
//
// If any function that executes a command which allocates objects on the TPM returns this error,
// it is possible that these objects were allocated and now exist on the TPM.
//
// If any function that executes a command which makes persistent changes to the TPM returns this
// error, it is possible that the persistent changes were completed.
type InvalidResponseError struct {
	Command CommandCode
	err     error
}

func (e *InvalidResponseError) Unwrap() error {
	return e.err
}

func (e *InvalidResponseError) Error() string {
	return fmt.Sprintf("TPM returned an invalid response for command %s: %v", e.Command, e.err.Error())
}

// InvalidAuthResponseError is returned from any [TPMContext] method that executes a TPM command if
// one of the response auth HMACs is invalid. If this error occurs, session contexts associated
// with the command that caused this error should be considered invalid.
type InvalidAuthResponseError struct {
	Index int // Index of the session responsible for this error, starting from 1
	msg   string
}

func (e *InvalidAuthResponseError) Error() string {
	return fmt.Sprintf("encountered an error whilst processing the auth response for session %d: %s", e.Index, e.msg)
}

// TctiError is returned from any [TPMContext] method if the underlying [TCTI] returns an error.
// If this error occurs, the underlying connection will generally be unusable for subsequent
// commands.
type TctiError struct {
	Op  string // The operation that caused the error
	err error
}

func (e *TctiError) Error() string {
	return fmt.Sprintf("cannot complete %s operation on TCTI: %v", e.Op, e.err)
}

func (e *TctiError) Unwrap() error {
	return e.err
}

// TPMVendorError represents a TPM response that indicates a vendor-specific error
// (rc & 0x580 == 0x500).
type TPMVendorError struct {
	Command CommandCode  // Command code associated with this error
	Code    ResponseCode // Response code
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid vendor error response code.
func (e *TPMVendorError) ResponseCode() ResponseCode {
	if e.Code.F() || !e.Code.V() || !e.Code.T() {
		panic("invalid vendor error")
	}
	return e.Code
}

func (e *TPMVendorError) Error() string {
	return fmt.Sprintf("TPM returned a vendor defined error whilst executing command %s: 0x%08x", e.Command, e.Code)
}

// WarningCode represents a TPM warning. These are TCG defined format 0 response codes with the
// severity bit set (response codes 0x900 to 0x97f).
type WarningCode uint8

const (
	WarningContextGap     WarningCode = 0x01 // TPM_RC_CONTEXT_GAP
	WarningObjectMemory   WarningCode = 0x02 // TPM_RC_OBJECT_MEMORY
	WarningSessionMemory  WarningCode = 0x03 // TPM_RC_SESSION_MEMORY
	WarningMemory         WarningCode = 0x04 // TPM_RC_MEMORY
	WarningSessionHandles WarningCode = 0x05 // TPM_RC_SESSION_HANDLES
	WarningObjectHandles  WarningCode = 0x06 // TPM_RC_OBJECT_HANDLES

	// WarningLocality corresponds to TPM_RC_LOCALITY and is returned for a command if a policy
	// session is used for authorization and the session includes a TPM2_PolicyLocality assertion, but
	// the command isn't executed with the authorized locality.
	WarningLocality WarningCode = 0x07

	// WarningYielded corresponds to TPM_RC_YIELDED and is returned for any command that is suspended
	// as a hint that the command can be retried. This is handled automatically when executing
	// commands using CommandContext by resubmitting the command.
	WarningYielded WarningCode = 0x08

	// WarningCanceled corresponds to TPM_RC_CANCELED and is returned for any command that is canceled
	// before being able to complete.
	WarningCanceled WarningCode = 0x09

	WarningTesting     WarningCode = 0x0a // TPM_RC_TESTING
	WarningReferenceH0 WarningCode = 0x10 // TPM_RC_REFERENCE_H0
	WarningReferenceH1 WarningCode = 0x11 // TPM_RC_REFERENCE_H1
	WarningReferenceH2 WarningCode = 0x12 // TPM_RC_REFERENCE_H2
	WarningReferenceH3 WarningCode = 0x13 // TPM_RC_REFERENCE_H3
	WarningReferenceH4 WarningCode = 0x14 // TPM_RC_REFERENCE_H4
	WarningReferenceH5 WarningCode = 0x15 // TPM_RC_REFERENCE_H5
	WarningReferenceH6 WarningCode = 0x16 // TPM_RC_REFERENCE_H6
	WarningReferenceS0 WarningCode = 0x18 // TPM_RC_REFERENCE_S0
	WarningReferenceS1 WarningCode = 0x19 // TPM_RC_REFERENCE_S1
	WarningReferenceS2 WarningCode = 0x1a // TPM_RC_REFERENCE_S2
	WarningReferenceS3 WarningCode = 0x1b // TPM_RC_REFERENCE_S3
	WarningReferenceS4 WarningCode = 0x1c // TPM_RC_REFERENCE_S4
	WarningReferenceS5 WarningCode = 0x1d // TPM_RC_REFERENCE_S5
	WarningReferenceS6 WarningCode = 0x1e // TPM_RC_REFERENCE_S6

	// WarningNVRate corresponds to TPM_RC_NV_RATE and is returned for any command that requires NV
	// access if NV access is currently rate limited to prevent the NV memory from wearing out.
	WarningNVRate WarningCode = 0x20

	// WarningLockout corresponds to TPM_RC_LOCKOUT and is returned for any command that requires
	// authorization for an entity that is subject to dictionary attack protection, and the TPM is in
	// dictionary attack lockout mode.
	WarningLockout WarningCode = 0x21

	// WarningRetry corresponds to TPM_RC_RETRY and is returned for any command if the TPM was not
	// able to start the command. This is handled automatically when executing comands using
	// CommandContext by resubmitting the command.
	WarningRetry WarningCode = 0x22

	// WarningNVUnavailable corresponds to TPM_RC_NV_UNAVAILABLE and is returned for any command that
	// requires NV access but NV memory is currently not available.
	WarningNVUnavailable WarningCode = 0x23
)

// TPMWarning represents a TPM response that indicates a warning.
type TPMWarning struct {
	Command CommandCode // Command code associated with this error
	Code    WarningCode // Warning code
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid warning response code.
func (e *TPMWarning) ResponseCode() ResponseCode {
	if ResponseCode(e.Code)&responseCodeE0 != ResponseCode(e.Code) {
		panic("invalid warning code")
	}
	return responseCodeS | responseCodeV | ResponseCode(e.Code)
}

func (e *TPMWarning) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned a warning whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := warningCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func (e *TPMWarning) Is(target error) bool {
	t, ok := target.(*TPMWarning)
	if !ok {
		return false
	}
	return (t.Code == AnyWarningCode || t.Code == e.Code) && (t.Command == AnyCommandCode || t.Command == e.Command)
}

// ErrorCode represents a TPM error. This type represents TCG defined format 0 response codes
// without the severity bit set (response codes 0x100 to 0x17f), and format 1 response codes
// (where rc & 0x80 != 0).
//
// Format 0 error numbers are 7 bits wide and are represented by codes 0x00 to 0x7f. Format 1 error
// numbers are 6 bits wide and are represented by codes 0x80 to 0xbf.
type ErrorCode uint8

const (
	// ErrorInitialize corresponds to TPM_RC_INITIALIZE and is returned for any command executed
	// between a _TPM_Init event and a TPM2_Startup command.
	ErrorInitialize ErrorCode = 0x00

	// ErrorFailure corresponds to TPM_RC_FAILURE and is returned for any command if the TPM is in
	// failure mode.
	ErrorFailure ErrorCode = 0x01

	ErrorSequence  ErrorCode = 0x03 // TPM_RC_SEQUENCE
	ErrorDisabled  ErrorCode = 0x20 // TPM_RC_DISABLED
	ErrorExclusive ErrorCode = 0x21 // TPM_RC_EXCLUSIVE

	// ErrorAuthType corresponds to TPM_RC_AUTH_TYPE and is returned for a command where an
	// authorization is required and the authorization type is expected to be a policy session, but
	// another authorization type has been provided.
	ErrorAuthType ErrorCode = 0x24

	// ErrorAuthMissing corresponds to TPM_RC_AUTH_MISSING and is returned for a command that accepts
	// a ResourceContext argument that requires authorization, but no authorization session has been
	// provided in the command payload.
	ErrorAuthMissing ErrorCode = 0x25

	ErrorPolicy ErrorCode = 0x26 // TPM_RC_POLICY
	ErrorPCR    ErrorCode = 0x27 // TPM_RC_PCR

	// ErrorPCRChanged corresponds to TPM_RC_PCR_CHANGED and is returned for a command where a policy
	// session is used for authorization and the PCR contents have been updated since the last time
	// that they were checked in the session with a TPM2_PolicyPCR assertion.
	ErrorPCRChanged ErrorCode = 0x28

	// ErrorUpgrade corresponds to TPM_RC_UPGRADE and is returned for any command that isn't
	// TPM2_FieldUpgradeData if the TPM is in field upgrade mode.
	ErrorUpgrade ErrorCode = 0x2d

	ErrorTooManyContexts ErrorCode = 0x2e // TPM_RC_TOO_MANY_CONTEXTS

	// ErrorAuthUnavailable corresponds to TPM_RC_AUTH_UNAVAILABLE and is returned for a command where
	// the provided authorization requires the use of the authorization value for an entity, but the
	// authorization value cannot be used. For example, if the entity is an object and the command
	// requires the user auth role but the object does not have the AttrUserWithAuth attribute.
	ErrorAuthUnavailable ErrorCode = 0x2f

	// ErrorReboot corresponds to TPM_RC_REBOOT and is returned for any command if the TPM requires a
	// _TPM_Init event before it will execute any more commands.
	ErrorReboot ErrorCode = 0x30

	ErrorUnbalanced ErrorCode = 0x31 // TPM_RC_UNBALANCED

	// ErrorCommandSize corresponds to TPM_RC_COMMAND_SIZE and indicates that the value of the
	// commandSize field in the command header does not match the size of the command packet
	// transmitted to the TPM.
	ErrorCommandSize ErrorCode = 0x42

	// ErrorCommandCode corresponds to TPM_RC_COMMAND_CODE and is returned for any command that is not
	// implemented by the TPM.
	ErrorCommandCode ErrorCode = 0x43

	ErrorAuthsize ErrorCode = 0x44 // TPM_RC_AUTHSIZE

	// ErrorAuthContext corresponds to TPM_RC_AUTH_CONTEXT and is returned for any command that does
	// not accept any sessions if sessions have been provided in the command payload.
	ErrorAuthContext ErrorCode = 0x45

	ErrorNVRange         ErrorCode = 0x46 // TPM_RC_NV_RANGE
	ErrorNVSize          ErrorCode = 0x47 // TPM_RC_NV_SIZE
	ErrorNVLocked        ErrorCode = 0x48 // TPM_RC_NV_LOCKED
	ErrorNVAuthorization ErrorCode = 0x49 // TPM_RC_NV_AUTHORIZATION
	ErrorNVUninitialized ErrorCode = 0x4a // TPM_RC_NV_UNINITIALIZED
	ErrorNVSpace         ErrorCode = 0x4b // TPM_RC_NV_SPACE
	ErrorNVDefined       ErrorCode = 0x4c // TPM_RC_NV_DEFINED
	ErrorBadContext      ErrorCode = 0x50 // TPM_RC_BAD_CONTEXT
	ErrorCpHash          ErrorCode = 0x51 // TPM_RC_CPHASH
	ErrorParent          ErrorCode = 0x52 // TPM_RC_PARENT
	ErrorNeedsTest       ErrorCode = 0x53 // TPM_RC_NEEDS_TEST

	// ErrorNoResult corresponds to TPM_RC_NO_RESULT and is returned for any command if the TPM
	// cannot process a request due to an unspecified problem.
	ErrorNoResult ErrorCode = 0x54

	ErrorSensitive ErrorCode = 0x55 // TPM_RC_SENSITIVE

	errorCode1Start ErrorCode = 0x80

	ErrorAsymmetric ErrorCode = errorCode1Start + 0x01 // TPM_RC_ASYMMETRIC

	// ErrorAttributes corresponds to TPM_RC_ATTRIBUTES and is returned as a *TPMSessionError for a
	// command in the following circumstances:
	// * More than one SessionContext instance with the AttrCommandEncrypt attribute has been provided.
	// * More than one SessionContext instance with the AttrResponseEncrypt attribute has been provided.
	// * A SessionContext instance referencing a trial session has been provided for authorization.
	ErrorAttributes ErrorCode = errorCode1Start + 0x02

	// ErrorHash corresponds to TPM_RC_HASH and is returned as a *TPMParameterError error for any
	// command that accepts a HashAlgorithmId parameter if the parameter value is not a valid digest
	// algorithm.
	ErrorHash ErrorCode = errorCode1Start + 0x03

	// ErrorValue corresponds to TPM_RC_VALUE and is returned as a *TPMParameterError or
	// *TPMHandleError for any command where an argument value is incorrect or out of range for the
	// command.
	ErrorValue ErrorCode = errorCode1Start + 0x04 // TPM_RC_VALUE

	// ErrorHierarchy corresponds to TPM_RC_HIERARCHY and is returned as a *TPMHandleError error for
	// any command that accepts a ResourceContext or Handle argument if that argument corresponds to
	// a hierarchy on the TPM that has been disabled.
	ErrorHierarchy ErrorCode = errorCode1Start + 0x05

	ErrorKeySize ErrorCode = errorCode1Start + 0x07 // TPM_RC_KEY_SIZE
	ErrorMGF     ErrorCode = errorCode1Start + 0x08 // TPM_RC_MGF

	// ErrorMode corresponds to TPM_RC_MODE and is returned as a *TPMParameterError error for any
	// command that accepts a SymModeId parameter if the parameter value is not a valid symmetric
	// mode.
	ErrorMode ErrorCode = errorCode1Start + 0x09

	// ErrorType corresponds to TPM_RC_TYPE and is returned as a *TPMParameterError error for any
	// command that accepts a ObjectTypeId parameter if the parameter value is not a valid public
	// type.
	ErrorType ErrorCode = errorCode1Start + 0x0a

	ErrorHandle ErrorCode = errorCode1Start + 0x0b // TPM_RC_HANDLE

	// ErrorKDF corresponds to TPM_RC_KDF and is returned as a *TPMParameterError error for any
	// command that accepts a KDFAlgorithmId parameter if the parameter value is not a valid key
	// derivation function.
	ErrorKDF ErrorCode = errorCode1Start + 0x0c

	ErrorRange ErrorCode = errorCode1Start + 0x0d // TPM_RC_RANGE

	// ErrorAuthFail corresponds to TPM_RC_AUTH_FAIL and is returned as a *TPMSessionError error for
	// a command if an authorization check fails. The dictionary attack counter is incremented when
	// this error is returned.
	ErrorAuthFail ErrorCode = errorCode1Start + 0x0e

	// ErrorNonce corresponds to TPM_RC_NONCE and is returned as a *TPMSessionError error for any
	// command where a password authorization has been provided and the authorization session in the
	// command payload contains a non-zero sized nonce field.
	ErrorNonce ErrorCode = errorCode1Start + 0x0f

	// ErrorPP corresponds to TPM_RC_PP and is returned as a *TPMSessionError for a command in the
	// following circumstances:
	// * Authorization of the platform hierarchy is provided and the command requires an assertion of
	//   physical presence that hasn't been provided.
	// * Authorization is provided with a policy session that includes the TPM2_PolicyPhysicalPresence
	//   assertion, and an assertion of physical presence hasn't been provided.
	ErrorPP ErrorCode = errorCode1Start + 0x10

	// ErrorScheme corresponds to TPM_RC_SCHEME and is returned as a *TPMParameterError error for any
	// command that accepts a SigSchemeId or ECCSchemeId parameter if the parameter value is not valid.
	ErrorScheme ErrorCode = errorCode1Start + 0x12

	// ErrorSize corresponds to TPM_RC_SIZE and is returned for a command in the following circumstances:
	// * As a *TPMParameterError if the command accepts a parameter type corresponding to TPM2B or
	//   TPML prefixed types and the size or length field has an invalid value.
	// * As a *TPMError if the TPM's parameter unmarshalling doesn't consume all of the bytes in the
	//   input buffer.
	// * As a *TPMError if the size field of the command's authorization area is an invalid value.
	// * As a *TPMSessionError if the authorization area for a command payload contains more than 3
	//   sessions.
	ErrorSize ErrorCode = errorCode1Start + 0x15

	// ErrorSymmetric corresponds to TPM_RC_SYMMETRIC and is returned for a command in the following
	// circumstances:
	// * As a *TPMParameterError if the command accepts a SymAlgorithmId parameter if the parameter
	//   value is not a valid symmetric algorithm.
	// * As a *TPMSessionError if a SessionContext instance is provided with the AttrCommandEncrypt
	//   attribute set but the session has no symmetric algorithm.
	// * As a *TPMSessionError if a SessionContext instance is provided with the AttrResponseEncrypt
	//   attribute set but the session has no symmetric algorithm.
	ErrorSymmetric ErrorCode = errorCode1Start + 0x16

	// ErrorTag corresponds to TPM_RC_TAG and is returned as a *TPMParameterError error for a command
	// that accepts a StructTag parameter if the parameter value is not the correct value.
	ErrorTag ErrorCode = errorCode1Start + 0x17

	// ErrorSelector corresponds to TPM_RC_SELECTOR and is returned as a *TPMParameterError error for
	// a command that accepts a parameter type corresponding to a TPMU prefixed type if the value of
	// the selector field in the surrounding TPMT prefixed type is incorrect.
	ErrorSelector ErrorCode = errorCode1Start + 0x18

	// ErrorInsufficient corresponds to TPM_RC_INSUFFICIENT and is returned as a *TPMParameterError
	// for a command if there is insufficient data in the TPM's input buffer to complete unmarshalling
	// of the command parameters.
	ErrorInsufficient ErrorCode = errorCode1Start + 0x1a

	ErrorSignature ErrorCode = errorCode1Start + 0x1b // TPM_RC_SIGNATURE
	ErrorKey       ErrorCode = errorCode1Start + 0x1c // TPM_RC_KEY

	// ErrorPolicyFail corresponds to TPM_RC_POLICY_FAIL and is returned as a *TPMSessionError error
	// for a command in the following circumstances:
	// * A policy session is used for authorization and the policy session digest does not match the
	//   authorization policy digest for the entity being authorized.
	// * A policy session is used for authorization and the digest algorithm of the session does not
	//   match the name algorithm of the entity being authorized.
	// * A policy session is used for authorization but the authorization is for the admin or DUP role
	//   and the policy session does not include a TPM2_PolicyCommandCode assertion.
	// * A policy session is used for authorization and the policy session includes a
	//   TPM2_PolicyNvWritten assertion but the entity being authorized is not a NV index.
	// * A policy session is used for authorization, the policy session includes the
	//   TPM2_PolicyNvWritten assertion, but the NV index being authorized does not have the
	//   AttrNVWritten attribute set.
	ErrorPolicyFail ErrorCode = errorCode1Start + 0x1d

	ErrorIntegrity ErrorCode = errorCode1Start + 0x1f // TPM_RC_INTEGRITY
	ErrorTicket    ErrorCode = errorCode1Start + 0x20 // TPM_RC_TICKET

	// ErroReservedBits corresponds to TPM_RC_RESERVED_BITS and is returned as a *TPMParameterError
	// error for a command that accepts a parameter type corresponding to a TPMA prefixed type if the
	// parameter value has reserved bits set.
	ErrorReservedBits ErrorCode = errorCode1Start + 0x21

	// ErrorBadAuth corresponds to TPM_RC_BAD_AUTH and is returned as a *TPMSessionError error for a
	// command if an authorization check fails and the authorized entity is exempt from dictionary
	// attack protections.
	ErrorBadAuth ErrorCode = errorCode1Start + 0x22

	// ErrorExpired corresponds to TPM_RC_EXPIRED and is returned as a *TPMSessionError error for a
	// command if a policy session is used for authorization, and the session has expired.
	ErrorExpired ErrorCode = errorCode1Start + 0x23

	// ErrorPolicyCC corresponds to TPM_RC_POLICY_CC and is returned as a *TPMSessionError error for
	// a command if a policy session is used for authorization, the session includes a
	// TPM2_PolicyCommandCode assertion, but the command code doesn't match the command for which the
	// authorization is being used for.
	ErrorPolicyCC ErrorCode = errorCode1Start + 0x24

	ErrorBinding ErrorCode = errorCode1Start + 0x25 // TPM_RC_BINDING

	// ErrorCurve corresponds to TPM_RC_CURVE and is returned as a *TPMParameterError for a command
	// that accepts a ECCCurve parameter if the parameter value is incorrect.
	ErrorCurve ErrorCode = errorCode1Start + 0x26

	ErrorECCPoint ErrorCode = errorCode1Start + 0x27 // TPM_RC_ECC_POINT
)

// TPMErrorBadTag represents a TPM response that indicates that the tag field of the command header
// was invalid (rc == [ResponseBadTag]). This error will occur when trying to execute a TPM2
// command on a TPM1.2 device (along with a response tag == [TagRspCommand]).
type TPMErrorBadTag struct {
	Command CommandCode
}

// ResponseCode returns a TPM response code for this error.
func (TPMErrorBadTag) ResponseCode() ResponseCode {
	return ResponseBadTag
}

func (e *TPMErrorBadTag) Error() string {
	return fmt.Sprintf("TPM returned a TPM_RC_BAD_TAG error whilst executing command %s", e.Command)
}

// TPMError represents a TPM response that indicates an error that is not associated with a
// specific handle, parameter or session.
type TPMError struct {
	Command CommandCode // Command code associated with this error
	Code    ErrorCode   // Error code
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid error response code.
func (e *TPMError) ResponseCode() ResponseCode {
	if e.Code >= 0x80 {
		code := ResponseCode(e.Code - errorCode1Start)
		if code&responseCodeE1 != code {
			panic("invalid error code")
		}
		return responseCodeF | ResponseCode(e.Code)
	}
	return responseCodeV | ResponseCode(e.Code)
}

func (e *TPMError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error whilst executing command %s: %s", e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func (e *TPMError) Is(target error) bool {
	t, ok := target.(*TPMError)
	if !ok {
		return false
	}
	return (t.Code == AnyErrorCode || t.Code == e.Code) && (t.Command == AnyCommandCode || t.Command == e.Command)
}

// TPMParameterError represents a TPM response that indicates an error that is associated with a
// command parameter.
type TPMParameterError struct {
	*TPMError
	Index int // Index of the parameter associated with this error in the command parameter area, starting from 1
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid parameter error response code.
func (e *TPMParameterError) ResponseCode() ResponseCode {
	code := e.TPMError.ResponseCode()
	if !code.F() {
		panic("invalid error code")
	}
	if e.Index < 0 || e.Index > maxResponseCodeParameterIndex {
		panic("invalid index")
	}
	return (ResponseCode(e.Index) << responseCodeIndexShift) | responseCodeP | code
}

func (e *TPMParameterError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for parameter %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func (e *TPMParameterError) Is(target error) bool {
	t, ok := target.(*TPMParameterError)
	if !ok {
		return false
	}
	return e.TPMError.Is(t.TPMError) && (t.Index == AnyParameterIndex || t.Index == e.Index)
}

func (e *TPMParameterError) Unwrap() error {
	return e.TPMError
}

// TPMSessionError represents a TPM response that indicates an error that is associated with a
// session.
type TPMSessionError struct {
	*TPMError
	Index int // Index of the session associated with this error in the authorization area, starting from 1
}

const (
	maxResponseCodeHandleIndex          = 7
	maxResponseCodeParameterIndex       = 15
	responseCodeIndexIsSession    uint8 = 0x8
)

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid session error response code.
func (e *TPMSessionError) ResponseCode() ResponseCode {
	code := e.TPMError.ResponseCode()
	if !code.F() {
		panic("invalid error code")
	}
	if e.Index < 0 || e.Index > maxResponseCodeHandleIndex {
		panic("invalid index")
	}
	return (ResponseCode(responseCodeIndexIsSession|uint8(e.Index)) << responseCodeIndexShift) | code
}

func (e *TPMSessionError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for session %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func (e *TPMSessionError) Is(target error) bool {
	t, ok := target.(*TPMSessionError)
	if !ok {
		return false
	}
	return e.TPMError.Is(t.TPMError) && (t.Index == AnySessionIndex || t.Index == e.Index)
}

func (e *TPMSessionError) Unwrap() error {
	return e.TPMError
}

// TPMHandleError represents a TPM response that indicates an error that is associated with a
// command handle.
type TPMHandleError struct {
	*TPMError
	// Index is the index of the handle associated with this error in the command handle area, starting from 1. An index of 0 corresponds
	// to an unspecified handle
	Index int
}

// ResponseCode returns a TPM response code for this error.
// It will panic if it cannot be converted to a valid handle error response code.
func (e *TPMHandleError) ResponseCode() ResponseCode {
	code := e.TPMError.ResponseCode()
	if !code.F() {
		panic("invalid error code")
	}
	if e.Index < 0 || e.Index > maxResponseCodeHandleIndex {
		panic("invalid index")
	}
	return (ResponseCode(e.Index) << responseCodeIndexShift) | code
}

func (e *TPMHandleError) Error() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "TPM returned an error for handle %d whilst executing command %s: %s", e.Index, e.Command, e.Code)
	if desc, hasDesc := errorCodeDescriptions[e.Code]; hasDesc {
		fmt.Fprintf(&builder, " (%s)", desc)
	}
	return builder.String()
}

func (e *TPMHandleError) Is(target error) bool {
	t, ok := target.(*TPMHandleError)
	if !ok {
		return false
	}
	return e.TPMError.Is(t.TPMError) && (t.Index == AnyHandleIndex || t.Index == e.Index)
}

func (e *TPMHandleError) Unwrap() error {
	return e.TPMError
}

// IsResourceUnavailableError indicates whether an error is a [ResourceUnavailableError] with the
// specified handle. To test for any handle, use [AnyHandle].
func IsResourceUnavailableError(err error, handle Handle) bool {
	return errors.Is(err, ResourceUnavailableError{Handle: handle})
}

// IsTPMError indicates whether the error or any error within its chain is a *[TPMError] with the
// specified [ErrorCode] and [CommandCode]. To test for any error code, use [AnyErrorCode]. To test
// for any command code, use [AnyCommandCode].
func IsTPMError(err error, code ErrorCode, command CommandCode) bool {
	return errors.Is(err, &TPMError{Command: command, Code: code})
}

// IsTPMHandleError indicates whether the error or any error within its chain is a
// *[TPMHandleError] with the specified [ErrorCode], [CommandCode] and handle index. To test for
// any error code, use [AnyErrorCode]. To test for any command code, use [AnyCommandCode]. To test
// for any handle index, use [AnyHandleIndex].
func IsTPMHandleError(err error, code ErrorCode, command CommandCode, handle int) bool {
	return errors.Is(err, &TPMHandleError{TPMError: &TPMError{Command: command, Code: code}, Index: handle})
}

// IsTPMParameterError indicates whether the error or any error within its chain is a
// *[TPMParameterError] with the specified [ErrorCode], [CommandCode] and parameter index. To test
// for any error code, use [AnyErrorCode]. To test for any command code, use [AnyCommandCode]. To
// test for any parameter index, use [AnyParameterIndex].
func IsTPMParameterError(err error, code ErrorCode, command CommandCode, param int) bool {
	return errors.Is(err, &TPMParameterError{TPMError: &TPMError{Command: command, Code: code}, Index: param})
}

// IsTPMSessionError indicates whether the error or any error within its chain is a
// *[TPMSessionError] with the specified [ErrorCode], [CommandCode] and session index. To test for
// any error code, use [AnyErrorCode]. To test for any command code, use [AnyCommandCode]. To test
// for any session index, use [AnySessionIndex].
func IsTPMSessionError(err error, code ErrorCode, command CommandCode, session int) bool {
	return errors.Is(err, &TPMSessionError{TPMError: &TPMError{Command: command, Code: code}, Index: session})
}

// IsTPMWarning indicates whether the error or any error within its chain is a *[TPMWarning] with
// the specified [WarningCode] and [CommandCode]. To test for any warning code, use
// [AnyWarningCode]. To test for any command code, use [AnyCommandCode].
func IsTPMWarning(err error, code WarningCode, command CommandCode) bool {
	return errors.Is(err, &TPMWarning{Command: command, Code: code})
}

// InvalidResponseCode is returned from [DecodeResponseCode] and any [TPMContext] method that
// executes a command on the TPM if the TPM response code is invalid.
type InvalidResponseCodeError ResponseCode

func (e InvalidResponseCodeError) Error() string {
	return fmt.Sprintf("invalid response code 0x%08x", ResponseCode(e))
}

// DecodeResponseCode decodes the ResponseCode provided via resp. If the specified response code is
// [ResponseSuccess], it returns no error, else it returns an error that is appropriate for the
// response code. The command code is used for adding context to the returned error.
//
// If the response code is invalid, an [InvalidResponseCodeError] error will be returned.
func DecodeResponseCode(command CommandCode, resp ResponseCode) error {
	switch {
	case resp == ResponseSuccess:
		return nil
	case resp == ResponseBadTag:
		return &TPMErrorBadTag{Command: command}
	case resp.F():
		// Format-one error codes
		err := &TPMError{Command: command, Code: ErrorCode(resp.E()) + errorCode1Start}
		switch {
		case resp.P():
			// Associated with a parameter
			if resp.N() == 0 {
				return InvalidResponseCodeError(resp)
			}
			return &TPMParameterError{TPMError: err, Index: int(resp.N())}
		case resp.N()&responseCodeIndexIsSession != 0:
			// Associated with a session
			index := resp.N() &^ responseCodeIndexIsSession
			if index == 0 {
				return InvalidResponseCodeError(resp)
			}
			return &TPMSessionError{TPMError: err, Index: int(index)}
		case resp.N() != 0:
			// Associated with a handle
			return &TPMHandleError{TPMError: err, Index: int(resp.N())}
		default:
			// Not associated with a specific parameter, session or handle
			return err
		}
	default:
		// Format-zero error codes
		switch {
		case !resp.V():
			// A TPM1.2 error that isn't TPM_RC_BAD_TAG
			return InvalidResponseCodeError(resp)
		case resp.T():
			// An error defined by the TPM vendor
			return &TPMVendorError{Command: command, Code: resp}
		case resp.S():
			// A warning
			return &TPMWarning{Command: command, Code: WarningCode(resp.E())}
		default:
			return &TPMError{Command: command, Code: ErrorCode(resp.E())}
		}
	}
}
