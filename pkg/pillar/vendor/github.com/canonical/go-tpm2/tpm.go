// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"time"

	"github.com/canonical/go-tpm2/mu"
)

func makeInvalidArgError(name, msg string) error {
	return fmt.Errorf("invalid %s argument: %s", name, msg)
}

type execMultipleHelperAction interface {
	last() bool
	run(sessions ...SessionContext) error
}

func execMultipleHelper(action execMultipleHelperAction, sessions ...SessionContext) error {
	// Ensure all sessions have the AttrContinueSession attribute
	sessionsOrig := make([]SessionContext, len(sessions))
	copy(sessionsOrig, sessions)

	hasPolicySession := false

	for i := range sessions {
		if sessions[i] == nil {
			continue
		}

		sessionData := sessions[i].(sessionContextInternal).Data()
		if sessionData == nil {
			return errors.New("unusable session context")
		}

		if sessionData.SessionType == SessionTypePolicy {
			hasPolicySession = true
		}

		sessions[i] = sessions[i].IncludeAttrs(AttrContinueSession)
	}

	for !action.last() {
		if hasPolicySession {
			return errors.New("cannot use a policy session for authorization")
		}

		if err := action.run(sessions...); err != nil {
			return err
		}
	}

	// This is the last iteration. Run this command with the original session
	// contexts so that the sessions are evicted if they don't have the
	// AttrContinueSession attribute set.
	return action.run(sessionsOrig...)
}

func isSessionAllowed(commandCode CommandCode) bool {
	switch commandCode {
	case CommandStartup:
		return false
	case CommandContextLoad:
		return false
	case CommandContextSave:
		return false
	case CommandFlushContext:
		return false
	default:
		return true
	}
}

type execContextDispatcher interface {
	RunCommand(commandCode CommandCode, cHandles HandleList, cAuthArea []AuthCommand, cpBytes []byte, rHandle *Handle) (rpBytes []byte, rAuthArea []AuthResponse, err error)
}

type cmdContext struct {
	CommandCode   CommandCode
	Handles       []*CommandHandleContext
	Params        []interface{}
	ExtraSessions []SessionContext
}

type rspContext struct {
	CommandCode      CommandCode
	SessionParams    *sessionParams
	ResponseAuthArea []AuthResponse
	RpBytes          []byte

	Err error
}

type execContext struct {
	dispatcher           execContextDispatcher
	lastExclusiveSession sessionContextInternal
	pendingResponse      *rspContext
}

func (e *execContext) processResponseAuth(r *rspContext) (err error) {
	if r != e.pendingResponse {
		return r.Err
	}

	defer func() {
		r.Err = err
	}()

	e.pendingResponse = nil

	if isSessionAllowed(r.CommandCode) && e.lastExclusiveSession != nil {
		data := e.lastExclusiveSession.Data()
		if data != nil {
			data.IsExclusive = false
		}
		e.lastExclusiveSession = nil
	}

	if err := r.SessionParams.ProcessResponseAuthArea(r.ResponseAuthArea, r.RpBytes); err != nil {
		return &InvalidResponseError{r.CommandCode, fmt.Errorf("cannot process response auth area: %w", err)}
	}

	for _, s := range r.SessionParams.Sessions {
		if s.Session.IsExclusive() {
			e.lastExclusiveSession = s.Session
			break
		}
	}

	return nil
}

func (e *execContext) CompleteResponse(r *rspContext, responseParams ...interface{}) error {
	if err := e.processResponseAuth(r); err != nil {
		return err
	}

	rpBuf := bytes.NewReader(r.RpBytes)

	if _, err := mu.UnmarshalFromReader(rpBuf, responseParams...); err != nil {
		return &InvalidResponseError{r.CommandCode, fmt.Errorf("cannot unmarshal response parameters: %w", err)}
	}

	if rpBuf.Len() > 0 {
		return &InvalidResponseError{r.CommandCode, fmt.Errorf("response parameter area contains %d trailing bytes", rpBuf.Len())}
	}

	return nil
}

func (e *execContext) RunCommand(c *cmdContext, responseHandle *Handle) (*rspContext, error) {
	var handles HandleList
	var handleNames []Name
	sessionParams := newSessionParams()

	for _, h := range c.Handles {
		handles = append(handles, h.handle.Handle())
		handleNames = append(handleNames, h.handle.Name())

		if h.session != nil {
			if err := sessionParams.AppendSessionForResource(h.session, h.handle.(ResourceContext)); err != nil {
				return nil, fmt.Errorf("cannot process HandleContext for command %s at index %d: %v", c.CommandCode, len(handles), err)
			}
		}
	}
	if err := sessionParams.AppendExtraSessions(c.ExtraSessions...); err != nil {
		return nil, fmt.Errorf("cannot process non-auth SessionContext parameters for command %s: %v", c.CommandCode, err)
	}

	if sessionParams.hasDecryptSession() && (len(c.Params) == 0 || !isParamEncryptable(c.Params[0])) {
		return nil, fmt.Errorf("command %s does not support command parameter encryption", c.CommandCode)
	}

	cpBytes, err := mu.MarshalToBytes(c.Params...)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal parameters for command %s: %w", c.CommandCode, err)
	}

	cAuthArea, err := sessionParams.BuildCommandAuthArea(c.CommandCode, handleNames, cpBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot build auth area for command %s: %w", c.CommandCode, err)
	}

	if e.pendingResponse != nil {
		e.processResponseAuth(e.pendingResponse)
	}

	rpBytes, rAuthArea, err := e.dispatcher.RunCommand(c.CommandCode, handles, cAuthArea, cpBytes, responseHandle)
	if err != nil {
		return nil, err
	}

	r := &rspContext{
		CommandCode:      c.CommandCode,
		SessionParams:    sessionParams,
		ResponseAuthArea: rAuthArea,
		RpBytes:          rpBytes}
	e.pendingResponse = r
	return r, nil
}

// TODO: Implement commands from the following sections of part 3 of the TPM library spec:
// Section 14 - Asymmetric Primitives
// Section 15 - Symmetric Primitives
// Section 19 - Ephemeral EC Keys
// Section 26 - Miscellaneous Management Functions
// Section 27 - Field Upgrade

// TPMContext is the main entry point by which commands are executed on a TPM device using this
// package. It provides convenience functions for supported commands and communicates with the
// underlying device via a transmission interface, which is provided to [NewTPMContext].
// Convenience functions are wrappers around [TPMContext.StartCommand], which may be used directly
// for custom commands or commands that aren't supported directly by this package.
//
// Methods that execute commands on the TPM may return errors from the TPM where a command responds
// with a [ResponseCode] other than [ResponseSuccess]. These errors are in the form of *[TPMError],
// *[TPMWarning], *[TPMHandleError], *[TPMSessionError], *[TPMParameterError] and *[TPMVendorError]
// types.
//
// Some commands make use of resources on the TPM, and use of these resources may require
// authorization with one of 3 roles depending on the command: user, admin or duplication. The role
// determines the required authorization type (passphrase, HMAC session, or policy session), which
// is dependent on the type of the resource.
//
// Commands that make use of resources on the TPM accept command handle arguments. Convenience
// methods generally use [ResourceContext] to represent these.
//
// Convenience methods that require authorization for a [ResourceContext] provide an associated
// [SessionContext] argument to represent a session. Setting this to nil specifies passphrase
// authorization. A HMAC or policy session can be used by supplying a [SessionContext] associated
// with a session of the corresponding type.
//
// If the authorization value of a resource is required as part of the authorization (eg, for
// passphrase authorization, a HMAC session that is not bound to the specified resource, or a
// policy session that contains the TPM2_PolicyPassword or TPM2_PolicyAuthValue assertion), it is
// obtained from the [ResourceContext] supplied to the method and should be set by calling
// [ResourceContext].SetAuthValue before the method is called.
//
// Where a command requires authorization with the user role for a resource, the following
// authorization types are permitted:
//
//   - [HandleTypePCR]: passphrase or HMAC session if no auth policy is set, or a policy session if
//     an auth policy is set.
//   - [HandleTypeNVIndex]: passphrase, HMAC session or policy session depending on attributes.
//   - [HandleTypePermanent]: passphrase or HMAC session. A policy session can also be used if an
//     auth policy is set.
//   - [HandleTypeTransient] / [HandleTypePersistent]: policy session. Passphrase or HMAC session
//     can also be used if [AttrWithUserAuth] is set.
//
// Where a command requires authorization with the admin role for a resource, the following
// authorization types are permitted:
//
//   - [HandleTypeNVIndex]: policy session.
//   - [HandleTypeTransient] / [HandleTypePersistent]: policy session. Passphrase or HMAC session
//     can also be used if [AttrAdminWithPolicy] is not set.
//
// Where a command requires authorization with the duplication role for a resource, a policy
// session is required.
//
// Where a policy session is used for a resource that requires authorization with the admin or
// duplication role, the session must contain the TPM2_PolicyCommandCode assertion.
//
// Some convenience methods also accept a variable number of optional [SessionContext] arguments -
// these are for sessions that don't provide authorization for a corresponding TPM resource. These
// sessions may be used for the purposes of session based parameter encryption or command auditing.
type TPMContext struct {
	device                TPMDevice
	tcti                  TCTI
	permanentResources    map[Handle]*permanentContext
	maxSubmissions        uint
	propertiesInitialized bool
	maxBufferSize         uint16
	minPcrSelectSize      uint8
	maxDigestSize         uint16
	maxNVBufferSize       uint16
	execContext           execContext
}

// Close calls Close on the transmission interface.
func (t *TPMContext) Close() error {
	if err := t.tcti.Close(); err != nil {
		return &TctiError{"close", err}
	}

	return nil
}

// RunCommandBytes is a low-level interface for executing a command. The caller is responsible for
// supplying a properly serialized command packet, which can be created with
// [MarshalCommandPacket].
//
// If successful, this function will return the response packet. No checking is performed on this
// response packet. An error will only be returned if the transmission interface returns an error.
//
// Most users will want to use one of the many convenience functions provided by TPMContext
// instead, or [TPMContext.StartCommand] if one doesn't already exist.
func (t *TPMContext) RunCommandBytes(packet CommandPacket) (ResponsePacket, error) {
	if _, err := t.tcti.Write(packet); err != nil {
		return nil, &TctiError{"write", err}
	}

	resp, err := ioutil.ReadAll(t.tcti)
	if err != nil {
		return nil, &TctiError{"read", err}
	}

	return ResponsePacket(resp), nil
}

// RunCommand is a low-level interface for executing a command. The caller supplies the command
// code, list of command handles, command auth area and marshalled command parameters. The caller
// should also supply a pointer to a response handle if the command returns one. On success, the
// response parameter bytes and response auth area are returned. This function does no checking of
// the auth response.
//
// If the TPM returns a response indicating that the command should be retried, this function will
// retry up to a maximum number of times defined by the number supplied to
// [TPMContext.SetMaxSubmissions], if required by the underlying [TPMDevice].
//
// A *[TctiError] will be returned if the transmission interface returns an error.
//
// One of *[TPMWarning], *[TPMError], *[TPMParameterError], *[TPMHandleError] or
// *[TPMSessionError] will be returned if the TPM returns a response code other than
// [ResponseSuccess].
//
// There's almost no need for most users to use this API directly. Most users will want to use one
// of the many convenience functions provided by TPMContext instead, or [TPMContext.StartCommand]
// if one doesn't already exist.
func (t *TPMContext) RunCommand(commandCode CommandCode, cHandles HandleList, cAuthArea []AuthCommand, cpBytes []byte, rHandle *Handle) (rpBytes []byte, rAuthArea []AuthResponse, err error) {
	cmd, err := MarshalCommandPacket(commandCode, cHandles, cAuthArea, cpBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot serialize command packet: %w", err)
	}

	try := uint(1)
	retryDelay := 20 * time.Millisecond

	for {
		var err error
		resp, err := t.RunCommandBytes(cmd)
		if err != nil {
			return nil, nil, err
		}

		var rc ResponseCode
		rc, rpBytes, rAuthArea, err = resp.Unmarshal(rHandle)
		if err != nil {
			return nil, nil, &InvalidResponseError{commandCode, fmt.Errorf("cannot unmarshal response packet: %w", err)}
		}

		err = DecodeResponseCode(commandCode, rc)
		if err == nil {
			return rpBytes, rAuthArea, nil
		}
		if _, isInvalidRc := err.(InvalidResponseCodeError); isInvalidRc {
			return nil, nil, &InvalidResponseError{commandCode, err}
		}

		if !t.device.ShouldRetry() || try >= t.maxSubmissions {
			return nil, nil, err
		}
		if !(IsTPMWarning(err, WarningYielded, commandCode) || IsTPMWarning(err, WarningTesting, commandCode) || IsTPMWarning(err, WarningRetry, commandCode)) {
			return nil, nil, err
		}

		time.Sleep(retryDelay)

		try++
		retryDelay *= 2
	}
}

// StartCommand is the high-level function for beginning the process of executing a command. It
// returns a CommandContext that can be used to assemble a command, properly serialize a command
// packet and then submit the packet for execution via [TPMContext.RunCommand].
//
// Most users will want to use one of the many convenience functions provided by TPMContext,
// which are just wrappers around this.
func (t *TPMContext) StartCommand(commandCode CommandCode) *CommandContext {
	return &CommandContext{
		dispatcher: &t.execContext,
		cmd:        cmdContext{CommandCode: commandCode}}
}

// SetMaxSubmissions sets the maximum number of times that [CommandContext] will attempt to submit
// a command before failing with an error. The default value is 5. Setting this to 1 disables
// resubmission. Note that 1 and 0 behave the same.
//
// Each submission is performed after an incremental delay. The first submission is delayed for
// 20ms, with the delay time doubling for each subsequent submission.
func (t *TPMContext) SetMaxSubmissions(max uint) {
	t.maxSubmissions = max
}

// SetCommandTimeout sets the maximum time that the context will wait for a response before a
// command times out. Set this to [InfiniteTimeout] to disable the timeout entirely, which is
// the default value.
//
// Note that there isn't a way to reattempt to the fetch the result of a command that times out.
// If a command times out, the connection will generally be unusable for future commands.
func (t *TPMContext) SetCommandTimeout(timeout time.Duration) error {
	return t.tcti.SetTimeout(timeout)
}

// InitProperties executes one or more TPM2_GetCapability commands to initialize properties used
// internally by TPMContext. This is normally done automatically by functions that require these
// properties when they are used for the first time, but this function is provided so that the
// command can be audited, and so the exclusivity of an audit session can be preserved.
//
// Any sessions supplied should have the [AttrContinueSession] attribute set.
func (t *TPMContext) InitProperties(sessions ...SessionContext) error {
	props, err := t.GetCapabilityTPMProperties(PropertyFixed, CapabilityMaxProperties, sessions...)
	if err != nil {
		return err
	}

	for _, prop := range props {
		switch prop.Property {
		case PropertyInputBuffer, PropertyMaxDigest, PropertyNVBufferMax:
			if prop.Value > math.MaxUint16 {
				return &InvalidResponseError{CommandGetCapability, fmt.Errorf("property %v out of range", prop.Property)}
			}

			value := uint16(prop.Value)

			switch prop.Property {
			case PropertyInputBuffer:
				t.maxBufferSize = value
			case PropertyMaxDigest:
				t.maxDigestSize = value
			case PropertyNVBufferMax:
				t.maxNVBufferSize = value
			}
		case PropertyPCRSelectMin:
			if prop.Value > math.MaxUint8 {
				return &InvalidResponseError{CommandGetCapability, errors.New("property TPM_PT_PCR_SELECT_MIN out of range")}
			}
			t.minPcrSelectSize = uint8(prop.Value)
		}
	}

	if t.maxBufferSize == 0 {
		t.maxBufferSize = 1024
	}
	if t.maxDigestSize == 0 {
		return &InvalidResponseError{CommandGetCapability, errors.New("missing or invalid TPM_PT_MAX_DIGEST property")}
	}
	if t.maxNVBufferSize == 0 {
		return &InvalidResponseError{CommandGetCapability, errors.New("missing or invalid TPM_PT_NV_BUFFER_MAX property")}
	}
	if t.minPcrSelectSize == 0 {
		return &InvalidResponseError{CommandGetCapability, errors.New("missing or invalid TPM_PT_PCR_SELECT_MIN property")}
	}
	t.propertiesInitialized = true
	return nil
}

func (t *TPMContext) initPropertiesIfNeeded() error {
	if t.propertiesInitialized {
		return nil
	}
	return t.InitProperties()
}

// TPMDevice corresponds a TPM device.
type TPMDevice interface {
	// Open opens a communication channel with the TPM device.
	Open() (TCTI, error)

	// ShouldRetry indicates whether TPMContext should resubmit commands
	// when the TPM response indicates that a command should be retried.
	// Some backends may have already retried, in which case TPMContext
	// should not retry.
	ShouldRetry() bool

	fmt.Stringer
}

// OpenTPMDevice opens the supplied TPM device and returns a new instance of TPMContext which
// communicates with the device using the newly opened communication channel.
func OpenTPMDevice(device TPMDevice) (*TPMContext, error) {
	if device == nil {
		return nil, errors.New("no device")
	}

	tcti, err := device.Open()
	if err != nil {
		return nil, err
	}
	err = tcti.SetTimeout(InfiniteTimeout)
	switch {
	case errors.Is(err, ErrTimeoutNotSupported):
		// ignore
	case err != nil:
		return nil, err
	}

	tpm := new(TPMContext)
	tpm.device = device
	tpm.tcti = tcti
	tpm.permanentResources = make(map[Handle]*permanentContext)
	tpm.maxSubmissions = 5
	tpm.execContext.dispatcher = tpm
	return tpm, nil
}

type dummyTPMDevice struct {
	tcti TCTI
}

func (d *dummyTPMDevice) Open() (TCTI, error) {
	return d.tcti, nil
}

func (d *dummyTPMDevice) ShouldRetry() bool {
	return true
}

func (d *dummyTPMDevice) String() string {
	return ""
}

// NewTPMContext creates a new instance of TPMContext, which communicates with the TPM using the
// transmission interface provided via the tcti parameter. The transmission interface must not be
// nil - it is expected that the caller checks the error returned from the function that is/ used
// to create it.
//
// Deprecated: Use [OpenTPMDevice] instead.
func NewTPMContext(tcti TCTI) *TPMContext {
	if tcti == nil {
		panic("nil transmission interface")
	}

	device := &dummyTPMDevice{tcti: tcti}
	tpm, err := OpenTPMDevice(device)
	if err != nil {
		panic(err)
	}

	return tpm
}
