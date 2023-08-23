// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"

	"github.com/canonical/go-tpm2/mu"
)

// CommandHeader is the header for a TPM command.
type CommandHeader struct {
	Tag         StructTag
	CommandSize uint32
	CommandCode CommandCode
}

// CommandPacket corresponds to a complete command packet including header and payload.
type CommandPacket []byte

// GetCommandCode returns the command code contained within this packet.
func (p CommandPacket) GetCommandCode() (CommandCode, error) {
	var header CommandHeader
	if _, err := mu.UnmarshalFromBytes(p, &header); err != nil {
		return 0, fmt.Errorf("cannot unmarshal header: %w", err)
	}
	return header.CommandCode, nil
}

// Unmarshal unmarshals this command packet, returning the handles, auth area and parameters. The
// parameters will still be in the TPM wire format. The number of command handles associated with
// the command must be supplied by the caller.
func (p CommandPacket) Unmarshal(numHandles int) (handles HandleList, authArea []AuthCommand, parameters []byte, err error) {
	buf := bytes.NewReader(p)

	if buf.Size() > math.MaxUint32 {
		return nil, nil, nil, fmt.Errorf("packet too large (%d bytes)", buf.Size())
	}

	var header CommandHeader
	if _, err := mu.UnmarshalFromReader(buf, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot unmarshal header: %w", err)
	}

	if header.CommandSize != uint32(len(p)) {
		return nil, nil, nil, fmt.Errorf("invalid commandSize value (got %d, packet length %d)", header.CommandSize, len(p))
	}

	handles = make(HandleList, numHandles)
	if _, err := mu.UnmarshalFromReader(buf, mu.Raw(&handles)); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot unmarshal handles: %w", err)
	}

	switch header.Tag {
	case TagSessions:
		var authSize uint32
		if _, err := mu.UnmarshalFromReader(buf, &authSize); err != nil {
			return nil, nil, nil, fmt.Errorf("cannot unmarshal auth area size: %w", err)
		}
		r := &io.LimitedReader{R: buf, N: int64(authSize)}
		for r.N > 0 {
			var auth AuthCommand
			if _, err := mu.UnmarshalFromReader(r, &auth); err != nil {
				return nil, nil, nil, fmt.Errorf("cannot unmarshal auth at index %d: %w", len(authArea), err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
	default:
		return nil, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	parameters, err = ioutil.ReadAll(buf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot read parameters: %w", err)
	}

	return handles, authArea, parameters, nil
}

// MarshalCommandPacket serializes a complete TPM packet from the provided arguments. The
// parameters argument must already be serialized to the TPM wire format.
//
// This will return an error if the supplied parameters cannot be represented correctly
// by the TPM wire format.
func MarshalCommandPacket(command CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte) (CommandPacket, error) {
	header := CommandHeader{CommandCode: command}
	var payload []byte

	switch {
	case len(authArea) > 0:
		header.Tag = TagSessions

		aBytes, err := mu.MarshalToBytes(mu.Raw(authArea))
		if err != nil {
			return nil, fmt.Errorf("cannot marshal authArea: %w", err)
		}
		if int64(len(aBytes)) > math.MaxUint32 {
			return nil, errors.New("authArea is too large")
		}
		payload = mu.MustMarshalToBytes(mu.Raw(handles), uint32(len(aBytes)), mu.Raw(aBytes), mu.Raw(parameters))
	case len(authArea) == 0:
		header.Tag = TagNoSessions

		payload = mu.MustMarshalToBytes(mu.Raw(handles), mu.Raw(parameters))
	}

	if int64(len(payload)) > math.MaxUint32-int64(binary.Size(header)) {
		return nil, errors.New("total payload is too large")
	}

	header.CommandSize = uint32(binary.Size(header) + len(payload))

	return mu.MustMarshalToBytes(header, mu.Raw(payload)), nil
}

// MustMarshalCommandPacket serializes a complete TPM packet from the provided arguments.
// The parameters argument must already be serialized to the TPM wire format.
//
// This will panic if the supplied parameters cannot be represented correctly by the TPM
// wire format.
func MustMarshalCommandPacket(commandCode CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte) CommandPacket {
	b, err := MarshalCommandPacket(commandCode, handles, authArea, parameters)
	if err != nil {
		panic(err)
	}
	return b
}

// ResponseHeader is the header for the TPM's response to a command.
type ResponseHeader struct {
	Tag          StructTag
	ResponseSize uint32
	ResponseCode ResponseCode
}

// ResponsePacket corresponds to a complete response packet including header and payload.
type ResponsePacket []byte

// Unmarshal deserializes the response packet and returns the response code, handle, parameters
// and auth area. The parameters will still be in the TPM wire format. The caller supplies a
// pointer to which the response handle will be written. The pointer must be supplied if the
// command returns a handle, and must be nil if the command does not return a handle, else
// the response will be incorrectly unmarshalled.
func (p ResponsePacket) Unmarshal(handle *Handle) (rc ResponseCode, parameters []byte, authArea []AuthResponse, err error) {
	buf := bytes.NewReader(p)

	if buf.Size() > math.MaxUint32 {
		return 0, nil, nil, fmt.Errorf("packet too large (%d bytes)", buf.Size())
	}

	var header ResponseHeader
	if _, err := mu.UnmarshalFromReader(buf, &header); err != nil {
		return 0, nil, nil, fmt.Errorf("cannot unmarshal header: %w", err)
	}

	if header.ResponseSize != uint32(buf.Size()) {
		return 0, nil, nil, fmt.Errorf("invalid responseSize value (got %d, packet length %d)", header.ResponseSize, len(p))
	}

	switch header.Tag {
	case TagRspCommand:
		if header.ResponseCode != ResponseBadTag {
			return 0, nil, nil, fmt.Errorf("[TPM_ST_RSP_COMMAND]: %w", InvalidResponseCodeError(header.ResponseCode))
		}
		if buf.Len() != 0 {
			return 0, nil, nil, fmt.Errorf("invalid packet length for TPM_ST_RSP_COMMAND response (%d bytes)", buf.Size())
		}
	case TagSessions:
		if header.ResponseCode != ResponseSuccess {
			return 0, nil, nil, fmt.Errorf("[TPM_ST_SESSIONS]: %w", InvalidResponseCodeError(header.ResponseCode))
		}
	case TagNoSessions:
		if header.ResponseCode != ResponseSuccess && buf.Len() != 0 {
			return 0, nil, nil, fmt.Errorf("invalid packet length for unsuccessful TPM_ST_NO_SESSIONS response (%d bytes)", buf.Size())
		}
	default:
		return 0, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	switch header.Tag {
	case TagSessions, TagNoSessions:
		if header.ResponseCode == ResponseSuccess && handle != nil {
			if _, err := mu.UnmarshalFromReader(buf, handle); err != nil {
				return 0, nil, nil, fmt.Errorf("cannot unmarshal handle: %w", err)
			}
		}
	default:
	}

	switch header.Tag {
	case TagRspCommand:
	case TagSessions:
		var parameterSize uint32
		if _, err := mu.UnmarshalFromReader(buf, &parameterSize); err != nil {
			return 0, nil, nil, fmt.Errorf("cannot unmarshal parameterSize: %w", err)
		}

		if parameterSize > uint32(buf.Len()) {
			return 0, nil, nil, fmt.Errorf("invalid parameterSize (got %d, remaining packet bytes %d)", parameterSize, buf.Len())
		}

		parameters = make([]byte, parameterSize)
		if _, err := io.ReadFull(buf, parameters); err != nil {
			return 0, nil, nil, fmt.Errorf("cannot read parameters: %w", err)
		}

		for buf.Len() > 0 {
			var auth AuthResponse
			if _, err := mu.UnmarshalFromReader(buf, &auth); err != nil {
				return 0, nil, nil, fmt.Errorf("cannot unmarshal auth at index %d: %w", len(authArea), err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
		parameters, err = ioutil.ReadAll(buf)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("cannot read parameters: %w", err)
		}
	}

	return header.ResponseCode, parameters, authArea, nil
}

// CommandHandleContext is used to supply a [HandleContext] to a [CommandContext].
type CommandHandleContext struct {
	handle  HandleContext
	session SessionContext
}

// Handle returns the HandleContext.
func (c *CommandHandleContext) Handle() HandleContext {
	return c.handle
}

// Session returns the SessionContext if the handle requires authorization.
func (c *CommandHandleContext) Session() SessionContext {
	return c.session
}

// UseResourceContextWithAuth creates a CommandHandleContext for a [ResourceContext] that
// requires authorization in a command. The supplied [SessionContext] is the session used for
// authorization and determines the type of authorization used for the specified resource:
//
//   - If SessionContext is nil, then passphrase authorization is used.
//   - If SessionContext is a HMAC session, then HMAC authorization is used.
//   - If SessionContext is a policy session, then policy authorization is used.
//
// If the authorization value of the resource is required as part of the authorization (eg, for
// passphrase authorization, a HMAC session that is not bound to the specified resource, or a
// policy session that contains the TPM2_PolicyPassword or TPM2_PolicyAuthValue assertion), it is
// obtained from the supplied ResourceContext, and should be set by calling
// [ResourceContext].SetAuthValue before the command is executed.
//
// Resources that require authorization will require authorization with one of 3 roles, depending
// on the command: user, admin or duplication. The role determines the required authorization
// type, which is dependent on the type of the resource.
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
//     can also be used if AttrWithUserAuth is set.
//
// Where a command requires authorization with the admin role for a resource, the following
// authorization types are permitted:
//
//   - [HandleTypeNVIndex]: policy session.
//   - [HandleTypeTransient] / [HandleTypePersistent]: policy session. Passphrase or HMAC session
//     can also be used if AttrAdminWithPolicy is not set.
//
// Where a command requires authorization with the duplication role for a resource, a policy
// session is required.
//
// Where a policy session is used for a resource that requires authorization with the admin or
// duplication role, the session must contain the TPM2_PolicyCommandCode assertion.
//
// If the ResourceContext is nil, then [HandleNull] is used.
func UseResourceContextWithAuth(r ResourceContext, s SessionContext) *CommandHandleContext {
	if r == nil {
		r = nullResource()
	}
	if s == nil {
		s = pwSession()
	}
	return &CommandHandleContext{handle: r, session: s}
}

// UseHandleContext creates a CommandHandleContext for any [HandleContext] that does not require
// authorization. If the HandleContext is nil, then [HandleNull] is used.
func UseHandleContext(h HandleContext) *CommandHandleContext {
	if h == nil {
		h = nullResource()
	}
	return &CommandHandleContext{handle: h}
}

type commandDispatcher interface {
	RunCommand(c *cmdContext, responseHandle *Handle) (*rspContext, error)
	CompleteResponse(r *rspContext, responseParams ...interface{}) error
}

// CommandContext provides an API for building a command to execute via a [TPMContext].
type CommandContext struct {
	dispatcher commandDispatcher
	cmd        cmdContext
}

// ResponseContext contains the context required to validate a response and obtain response
// parameters.
type ResponseContext struct {
	dispatcher commandDispatcher
	rsp        *rspContext
}

// Complete performs validation of the response auth area and updates internal [SessionContext]
// state. If a response HMAC is invalid, an error will be returned. The caller supplies a command
// dependent number of pointers to the response parameters.
//
// If a SessionContext supplied to the original [CommandContext] has the [AttrResponseEncrypt]
// attribute set, then the first response parameter will be decrypted using the properties of that
// SessionContext.
func (c *ResponseContext) Complete(responseParams ...interface{}) error {
	return c.dispatcher.CompleteResponse(c.rsp, responseParams...)
}

// AddHandles appends the supplied command handle contexts to this command.
func (c *CommandContext) AddHandles(handles ...*CommandHandleContext) *CommandContext {
	c.cmd.Handles = append(c.cmd.Handles, handles...)
	return c
}

// AddParams appends the supplied command parameters to this command.
func (c *CommandContext) AddParams(params ...interface{}) *CommandContext {
	c.cmd.Params = append(c.cmd.Params, params...)
	return c
}

// AddExtraSessions adds the supplied additional session contexts to this command. These sessions
// are not used for authorization of any resources, but can be used for command or response
// parameter encryption, or command auditing.
func (c *CommandContext) AddExtraSessions(sessions ...SessionContext) *CommandContext {
	c.cmd.ExtraSessions = append(c.cmd.ExtraSessions, sessions...)
	return c
}

// RunWithoutProcessingResponse executes the command defined by this context using the [TPMContext]
// that created it. The caller supplies a pointer to the response handle if the command returns
// one.
//
// If a [SessionContext] used for this command has the [AttrCommandEncrypt] attribute set, then the
// first command parameter will be encrypted using the properties of that SessionContext.
//
// If the TPM returns a response indicating that the command should be retried, this function will
// retry up to a maximum number of times defined by the number supplied to
// [TPMContext.SetMaxSubmissions].
//
// This performs no validation of the response auth area. Instead, a ResponseContext is returned
// and the caller is expected to call [ResponseContext.Complete]. This is useful for commands that
// change an authorization value, where the response HMAC is computed with a key based on the new
// value.
//
// A *[TctiError] will be returned if the transmission interface returns an error.
//
// One of *[TPMWarning], *[TPMError], *[TPMParameterError], *[TPMHandleError] or *[TPMSessionError]
// will be returned if the TPM returns a response code other than [ResponseSuccess].
func (c *CommandContext) RunWithoutProcessingResponse(responseHandle *Handle) (*ResponseContext, error) {
	r, err := c.dispatcher.RunCommand(&c.cmd, responseHandle)
	if err != nil {
		return nil, err
	}
	return &ResponseContext{
		dispatcher: c.dispatcher,
		rsp:        r}, nil
}

// Run executes the command defined by this context using the [TPMContext] that created it. The
// caller supplies a pointer to the response handle if the command returns one, and a command
// dependent number of pointers to response parameters.
//
// If a [SessionContext] used for this command has the [AttrCommandEncrypt] attribute set, then
// the first command parameter will be encrypted using the properties of that SessionContext.
//
// If a SessionContext used for this command has the [AttrResponseEncrypt] attribute set, then the
// first response parameter will be decrypted using the properties of that SessionContext.
//
// If the TPM returns a response indicating that the command should be retried, this function will
// retry up to a maximum number of times defined by the number supplied to
// [TPMContext.SetMaxSubmissions].
//
// This performs validation of the response auth area and updates internal SessionContext state.
// If a response HMAC is invalid, an error will be returned.
//
// A *[TctiError] will be returned if the transmission interface returns an error.
//
// One of *[TPMWarning], *[TPMError], *[TPMParameterError], *[TPMHandleError] or *[TPMSessionError]
// will be returned if the TPM returns a response code other than [ResponseSuccess].
func (c *CommandContext) Run(responseHandle *Handle, responseParams ...interface{}) error {
	r, err := c.RunWithoutProcessingResponse(responseHandle)
	if err != nil {
		return err
	}
	return r.Complete(responseParams...)
}
