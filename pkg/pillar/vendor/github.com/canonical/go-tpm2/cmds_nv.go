// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 31 - Non-volatile Storage

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2/mu"
)

// NVDefineSpaceRaw executes the TPM2_NV_DefineSpace command to reserve space to hold the data
// associated with a NV index described by the publicInfo parameter. The Index field of publicInfo
// defines the handle at which the index should be reserved. The NameAlg field defines the digest
// algorithm for computing the name of the NV index. The Attrs field is used to describe attributes
// for the index, as well as its type. An authorization policy for the index can be defined using
// the AuthPolicy field of publicInfo. The Size field defines the size of the index.
//
// The auth parameter specifies an authorization value for the NV index.
//
// The authContext parameter specifies the hierarchy used for authorization, and should correspond
// to [HandlePlatform] or [HandleOwner]. The command requires authorization with the user auth role
// for the specified hierarchy, with session based authorization provided via
// authContextAuthSession.
//
// If the Attrs field of publicInfo has [AttrNVPolicyDelete] set but TPM2_NV_UndefineSpaceSpecial
// isn't supported, or the Attrs field defines a type that is unsupported, a *[TPMParameterError]
// error with an error code of [ErrorAttributes] will be returned for parameter index 2.
//
// If the AuthPolicy field of publicInfo defines an authorization policy digest then the digest
// length must match the size of the name algorithm defined by the NameAlg field of publicInfo,
// else a *[TPMParameterError] error with an error code of [ErrorSize] will be returned for
// parameter index 2.
//
// If the length of auth is greater than the name algorithm selected by the NameAlg field of the
// publicInfo parameter, a *[TPMParameterError] error with an error code of [ErrorSize] will be
// returned for parameter index 1.
//
// If authContext corresponds to [HandlePlatform] but the [AttrPhEnableNV] attribute is clear, a
// *[TPMHandleError] error with an error code of [ErrorHierarchy] will be returned.
//
// If the type indicated by the Attrs field of publicInfo isn't supported by the TPM, a
// *[TPMParameterError] error with an error code of [ErrorAttributes] will be returned for
// parameter index 2.
//
// If the type defined by publicInfo is [NVTypeCounter], [NVTypeBits], [NVTypePinPass] or
// [NVTypePinFail], the Size field of publicInfo must be 8. If the type defined by publicInfo is
// [NVTypeExtend], the Size field of publicInfo must match the size of the name algorithm defined
// by the NameAlg field. If the size is unexpected, or the size for an index of type
// [NVTypeOrdinary] is too large, a *[TPMParameterError] error with an error code of [ErrorSize]
// will be returned for parameter index 2.
//
// If the type defined by publicInfo is [NVTypeCounter], then the Attrs field must not have the
// [AttrNVClearStClear] attribute set, else a *[TPMParameterError] error with an error code of
// [ErrorAttributes] will be returned for parameter index 2.
//
// If the type defined by publicInfo is [NVTypePinFail], then the Attrs field must have the
// [AttrNVNoDA] attribute set. If the type is either [NVTypePinPass] or [NVTypePinFail], then the
// Attrs field must have the [AttrNVAuthWrite], [AttrNVGlobalLock] and [AttrNVWriteDefine]
// attributes clear, else a *[TPMParameterError] error with an error code of [ErrorAttributes] will
// be returned for parameter index 2.
//
// If the Attrs field of publicInfo has either [AttrNVWriteLocked], [AttrNVReadLocked] or
// [AttrNVWritten] set, a *[TPMParameterError] error with an error code of [ErrorAttributes] will
// be returned for parameter index 2.
//
// The Attrs field of publicInfo must have one of either [AttrNVPPWrite], [AttrNVOwnerWrite],
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] set, and must also have one of either [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] or [AttrNVPolicyRead set]. If there is no way to read or
// write an index, a *[TPMParameterError] error with an error code of [ErrorAttributes] will be
// returned for parameter index 2.
//
// If the Attrs field of publicInfo has [AttrNVClearStClear] set, a *[TPMParameterError] error with
// an error code of [ErrorAttributes] will be returned for parameter index 2 if
// [AttrNVWriteDefine] is set.
//
// If authContext corresponds to [HandlePlatform], then the Attrs field of publicInfo must have the
// [AttrNVPlatformCreate] attribute set. If authContext corresponds to [HandleOwner], then the
// [AttrNVPlatformCreate] attributes must be clear, else a *[TPMHandleError] error with an error
// code of [ErrorAttributes] will be returned.
//
// If the Attrs field of publicInfo has the [AttrNVPolicyDelete] attribute set, then
// [HandlePlatform] must be used for authorization via authContext, else a *[TPMParameterError]
// error with an error code of [ErrorAttributes] will be returned for parameter index 2.
//
// If an index is already defined at the location specified by the Index field of publicInfo, a
// *[TPMError] error with an error code of [ErrorNVDefined] will be returned.
//
// If there is insufficient space for the index, a *[TPMError] error with an error code of
// [ErrorNVSpace] will be returned.
//
// On successful completion, the NV index will be defined.
func (t *TPMContext) NVDefineSpaceRaw(authContext ResourceContext, auth Auth, publicInfo *NVPublic, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.StartCommand(CommandNVDefineSpace).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession)).
		AddParams(auth, mu.Sized(publicInfo)).
		AddExtraSessions(sessions...).
		Run(nil)
}

// NVDefineSpace executes the TPM2_NV_DefineSpace command to reserve space to hold the data
// associated with a NV index described by the publicInfo parameter. The Index field of publicInfo
// defines the handle at which the index should be reserved. The NameAlg field defines the digest
// algorithm for computing the name of the NV index. The Attrs field is used to describe attributes
// for the index, as well as its type. An authorization policy for the index can be defined using
// the AuthPolicy field of publicInfo. The Size field defines the size of the index.
//
// The name algorithm must be linked into the current binary. To create an NV index with a name
// algorithm that is not available, use [TPMContext.NVDefineSpaceRaw].
//
// The auth parameter specifies an authorization value for the NV index.
//
// The authContext parameter specifies the hierarchy used for authorization, and should correspond
// to [HandlePlatform] or [HandleOwner]. The command requires authorization with the user auth role
// for the specified hierarchy, with session based authorization provided via
// authContextAuthSession.
//
// If the Attrs field of publicInfo has [AttrNVPolicyDelete] set but TPM2_NV_UndefineSpaceSpecial
// isn't supported, or the Attrs field defines a type that is unsupported, a *[TPMParameterError]
// error with an error code of [ErrorAttributes] will be returned for parameter index 2.
//
// If the AuthPolicy field of publicInfo defines an authorization policy digest then the digest
// length must match the size of the name algorithm defined by the NameAlg field of publicInfo,
// else a *[TPMParameterError] error with an error code of [ErrorSize] will be returned for
// parameter index 2.
//
// If the length of auth is greater than the name algorithm selected by the NameAlg field of the
// publicInfo parameter, a *[TPMParameterError] error with an error code of [ErrorSize] will be
// returned for parameter index 1.
//
// If authContext corresponds to [HandlePlatform] but the [AttrPhEnableNV] attribute is clear, a
// *[TPMHandleError] error with an error code of [ErrorHierarchy] will be returned.
//
// If the type indicated by the Attrs field of publicInfo isn't supported by the TPM, a
// *[TPMParameterError] error with an error code of [ErrorAttributes] will be returned for
// parameter index 2.
//
// If the type defined by publicInfo is [NVTypeCounter], [NVTypeBits], [NVTypePinPass] or
// [NVTypePinFail], the Size field of publicInfo must be 8. If the type defined by publicInfo is
// [NVTypeExtend], the Size field of publicInfo must match the size of the name algorithm defined
// by the NameAlg field. If the size is unexpected, or the size for an index of type
// [NVTypeOrdinary] is too large, a *[TPMParameterError] error with an error code of [ErrorSize]
// will be returned for parameter index 2.
//
// If the type defined by publicInfo is [NVTypeCounter], then the Attrs field must not have the
// [AttrNVClearStClear] attribute set, else a *[TPMParameterError] error with an error code of
// [ErrorAttributes] will be returned for parameter index 2.
//
// If the type defined by publicInfo is [NVTypePinFail], then the Attrs field must have the
// [AttrNVNoDA] attribute set. If the type is either [NVTypePinPass] or [NVTypePinFail], then the
// Attrs field must have the [AttrNVAuthWrite], [AttrNVGlobalLock] and [AttrNVWriteDefine]
// attributes clear, else a *[TPMParameterError] error with an error code of [ErrorAttributes] will
// be returned for parameter index 2.
//
// If the Attrs field of publicInfo has either [AttrNVWriteLocked], [AttrNVReadLocked] or
// [AttrNVWritten] set, a *[TPMParameterError] error with an error code of [ErrorAttributes] will
// be returned for parameter index 2.
//
// The Attrs field of publicInfo must have one of either [AttrNVPPWrite], [AttrNVOwnerWrite],
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] set, and must also have one of either [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] or [AttrNVPolicyRead set]. If there is no way to read or
// write an index, a *[TPMParameterError] error with an error code of [ErrorAttributes] will be
// returned for parameter index 2.
//
// If the Attrs field of publicInfo has [AttrNVClearStClear] set, a *[TPMParameterError] error with
// an error code of [ErrorAttributes] will be returned for parameter index 2 if
// [AttrNVWriteDefine] is set.
//
// If authContext corresponds to [HandlePlatform], then the Attrs field of publicInfo must have the
// [AttrNVPlatformCreate] attribute set. If authContext corresponds to [HandleOwner], then the
// [AttrNVPlatformCreate] attributes must be clear, else a *[TPMHandleError] error with an error
// code of [ErrorAttributes] will be returned.
//
// If the Attrs field of publicInfo has the [AttrNVPolicyDelete] attribute set, then
// [HandlePlatform] must be used for authorization via authContext, else a *[TPMParameterError]
// error with an error code of [ErrorAttributes] will be returned for parameter index 2.
//
// If an index is already defined at the location specified by the Index field of publicInfo, a
// *[TPMError] error with an error code of [ErrorNVDefined] will be returned.
//
// If there is insufficient space for the index, a *[TPMError] error with an error code of
// [ErrorNVSpace] will be returned.
//
// On successful completion, the NV index will be defined and a ResourceContext corresponding to
// the new index will be returned. It will not be necessary to call [ResourceContext].SetAuthValue
// on the returned ResourceContext - this function sets the correct authorization value so that it
// can be used in subsequent commands that require knowledge of it.
func (t *TPMContext) NVDefineSpace(authContext ResourceContext, auth Auth, publicInfo *NVPublic, authContextAuthSession SessionContext, sessions ...SessionContext) (ResourceContext, error) {
	if publicInfo == nil {
		return nil, makeInvalidArgError("publicInfo", "nil value")
	}
	name, err := publicInfo.ComputeName()
	if err != nil {
		return nil, fmt.Errorf("cannot compute name from public info: %v", err)
	}

	if err := t.NVDefineSpaceRaw(authContext, auth, publicInfo, authContextAuthSession, sessions...); err != nil {
		return nil, err
	}

	var public *NVPublic
	// publicInfo already marshalled correctly, so this can't fail.
	mu.MustCopyValue(&public, publicInfo)

	rc := newNVIndexContext(name, public)
	rc.authValue = make([]byte, len(auth))
	copy(rc.authValue, auth)

	return rc, nil
}

// NVUndefineSpace executes the TPM2_NV_UndefineSpace command to remove the NV index associated
// with nvIndex, and free the resources used by it. If the index has the [AttrNVPolicyDelete]
// attribute set, then a *[TPMHandleError] error with an error code of [ErrorAttributes] will be
// returned for handle index 2.
//
// The authContext parameter specifies the hierarchy used for authorization and should correspond
// to either [HandlePlatform] or [HandleOwner]. The command requires authorization with the user
// auth role for the specified hierarchy, with session based authorization provided via
// authContextAuthSession.
//
// If authContext corresponds to [HandleOwner] and the NV index has the [AttrNVPlatformCreate]
// attribute set, then a *TPMError error with an error code of ErrorNVAuthorization will be
// returned.
//
// On successful completion, nvIndex will be invalidated.
func (t *TPMContext) NVUndefineSpace(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.StartCommand(CommandNVUndefineSpace).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	nvIndex.(handleContextInternal).Invalidate()
	return nil
}

// NVUndefineSpaceSpecial executes the TPM2_NV_UndefineSpaceSpecial command to remove the NV index
// associated with nvIndex, and free the resources used by it. If the NV index does not have the
// [AttrNVPolicyDelete] attribute set, then a *[TPMHandleError] error with an error code of
// [ErrorAttributes] will be returned for handle index 1.
//
// The platform parameter must correspond to [HandlePlatform]. The command requires authorization
// with the user auth role for the platform hierarchy, with session based authorization provided
// via platformAuthSession. The command requires authorization with the admin role for nvIndex,
// with the session provided via nvIndexAuthSession.
//
// On successful completion, nvIndex will be invalidated.
func (t *TPMContext) NVUndefineSpaceSpecial(nvIndex, platform ResourceContext, nvIndexAuthSession, platformAuthSession SessionContext, sessions ...SessionContext) error {
	r, err := t.StartCommand(CommandNVUndefineSpaceSpecial).
		AddHandles(UseResourceContextWithAuth(nvIndex, nvIndexAuthSession), UseResourceContextWithAuth(platform, platformAuthSession)).
		AddExtraSessions(sessions...).
		RunWithoutProcessingResponse(nil)
	if err != nil {
		return err
	}

	// If the HMAC key for this command includes the authorization value for nvIndex (eg, because the PolicyAuthValue assertion was
	// executed), the TPM will respond with a HMAC generated with a key based on an empty auth value.
	nvIndex.SetAuthValue(nil)

	err = r.Complete()
	nvIndex.(handleContextInternal).Invalidate()
	return err
}

// NVReadPublic executes the TPM2_NV_ReadPublic command to read the public area of the NV index
// associated with nvIndex.
func (t *TPMContext) NVReadPublic(nvIndex HandleContext, sessions ...SessionContext) (nvPublic *NVPublic, nvName Name, err error) {
	if err := t.StartCommand(CommandNVReadPublic).
		AddHandles(UseHandleContext(nvIndex)).
		AddExtraSessions(sessions...).
		Run(nil, mu.Sized(&nvPublic), &nvName); err != nil {
		return nil, nil, err
	}
	return nvPublic, nvName, nil
}

// NVWriteRaw executes the TPM2_NV_Write command to write data to the NV index associated with
// nvIndex, at the specified offset.
//
// The command requires authorization, defined by the state of the [AttrNVPPWrite],
// [AttrNVOwnerWrite], [AttrNVAuthWrite] and [AttrNVPolicyWrite] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPWrite] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerWrite]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *TPMError error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthWrite] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyWrite] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVWriteLocked] attribute set, a *[TPMError] error with an error code
// of [ErrorNVLocked] will be returned.
//
// If the type of the index is [NVTypeCounter], [NVTypeBits] or [NVTypeExtend], a *[TPMError] error
// with an error code of [ErrorAttributes] will be returned.
//
// If the value of offset is outside of the bounds of the index, a *[TPMParameterError] error with
// an error code of [ErrorValue] will be returned for parameter index 2.
//
// If the length of the data and the specified offset would result in a write outside of the bounds
// of the index, or if the index has the [AttrNVWriteAll] attribute set and the size of the data
// doesn't match the size of the index, a *[TPMError] error with an error code of [ErrorNVRange]
// will be returned.
//
// On successful completion, the [AttrNVWritten] flag will be set if this is the first time that
// the index has been written to. The name of nvIndex will be updated accordingly as long as it
// wasn't created with [NewLimitedResourceContext].
func (t *TPMContext) NVWriteRaw(authContext, nvIndex ResourceContext, data MaxNVBuffer, offset uint16, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.StartCommand(CommandNVWrite).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddParams(data, offset).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	if nv, isNv := nvIndex.(nvIndexContextInternal); isNv {
		nv.SetAttr(AttrNVWritten)
	}
	return nil
}

type nvWriteHelperContext struct {
	authContext ResourceContext
	nvIndex     ResourceContext
	data        []byte
	offset      uint16
	tpm         *TPMContext

	total uint16
}

func (c *nvWriteHelperContext) last() bool {
	return len(c.data[c.total:]) <= int(c.tpm.maxNVBufferSize)
}

func (c *nvWriteHelperContext) run(sessions ...SessionContext) error {
	d := c.data[c.total:]
	if len(d) > int(c.tpm.maxNVBufferSize) {
		d = d[:c.tpm.maxNVBufferSize]
	}

	if err := c.tpm.NVWriteRaw(c.authContext, c.nvIndex, d, c.offset+c.total, sessions[0], sessions[1:]...); err != nil {
		return err
	}

	c.total += uint16(len(d))
	return nil
}

// NVWrite executes the TPM2_NV_Write command to write data to the NV index associated with
// nvIndex, at the specified offset.
//
// The command requires authorization, defined by the state of the [AttrNVPPWrite],
// [AttrNVOwnerWrite], [AttrNVAuthWrite] and [AttrNVPolicyWrite] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPWrite] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerWrite]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *TPMError error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthWrite] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyWrite] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If data is too large to be written in a single command, this function will re-execute the
// TPM2_NV_Write command until all data is written. In this case, authContextAuthSession must not
// be a policy session.
//
// If the index has the [AttrNVWriteLocked] attribute set, a *[TPMError] error with an error code
// of [ErrorNVLocked] will be returned.
//
// If the type of the index is [NVTypeCounter], [NVTypeBits] or [NVTypeExtend], a *[TPMError] error
// with an error code of [ErrorAttributes] will be returned.
//
// If the value of offset is outside of the bounds of the index, a *[TPMParameterError] error with
// an error code of [ErrorValue] will be returned for parameter index 2.
//
// If the length of the data and the specified offset would result in a write outside of the bounds
// of the index, or if the index has the [AttrNVWriteAll] attribute set and the size of the data
// doesn't match the size of the index, a *[TPMError] error with an error code of [ErrorNVRange]
// will be returned.
//
// On successful completion, the [AttrNVWritten] flag will be set if this is the first time that
// the index has been written to.
func (t *TPMContext) NVWrite(authContext, nvIndex ResourceContext, data []byte, offset uint16, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.initPropertiesIfNeeded(); err != nil {
		return err
	}

	sessionsCopy := []SessionContext{authContextAuthSession}
	sessionsCopy = append(sessionsCopy, sessions...)

	context := &nvWriteHelperContext{
		authContext: authContext,
		nvIndex:     nvIndex,
		data:        data,
		offset:      offset,
		tpm:         t}

	return execMultipleHelper(context, sessionsCopy...)
}

// NVSetPinCounterParams is a convenience function for [TPMContext.NVWrite] for updating the
// contents of the NV pin pass or NV pin fail index associated with nvIndex. If the type of nvIndex
// is not NVTypePinPass of NVTypePinFail, an error will be returned. This will return an error if
// nvIndex was created with [NewLimitedResourceContext].
//
// The command requires authorization, defined by the state of the [AttrNVPPWrite],
// [AttrNVOwnerWrite], [AttrNVAuthWrite] and [AttrNVPolicyWrite] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPWrite] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerWrite]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *TPMError error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthWrite] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyWrite] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVWriteLocked] attribute set, a *[TPMError] error with an error code
// of [ErrorNVLocked] will be returned.
//
// On successful completion, the [AttrNVWritten] flag will be set if this is the first time that
// the index has been written to.
func (t *TPMContext) NVSetPinCounterParams(authContext, nvIndex ResourceContext, params *NVPinCounterParams, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	context, isNv := nvIndex.(nvIndexContextInternal)
	if !isNv {
		return errors.New("nvIndex does not correspond to a NV index")
	}
	if context.Attrs().Type() != NVTypePinPass && context.Attrs().Type() != NVTypePinFail {
		return errors.New("nvIndex does not correspond to a PIN pass or PIN fail index")
	}
	data := mu.MustMarshalToBytes(params)
	return t.NVWrite(authContext, nvIndex, data, 0, authContextAuthSession, sessions...)
}

// NVIncrement executes the TPM2_NV_Increment command to increment the counter associated with
// nvIndex.
//
// The command requires authorization, defined by the state of the [AttrNVPPWrite],
// [AttrNVOwnerWrite], [AttrNVAuthWrite] and [AttrNVPolicyWrite] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPWrite] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerWrite]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *TPMError error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthWrite] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyWrite] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVWriteLocked] attribute set, a *[TPMError] error with an error code
// of [ErrorNVLocked] will be returned.
//
// If the type of the index is not [NVTypeCounter], a *[TPMHandleError] error with an error code of
// [ErrorAttributes] will be returned for handle index 2.
//
// On successful completion, the [AttrNVWritten] flag will be set if this is the first time that
// the index has been written to. The name of nvIndex will be updated accordingly as long as it
// wasn't created with [NewLimitedResourceContext].
func (t *TPMContext) NVIncrement(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.StartCommand(CommandNVIncrement).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	if nv, isNv := nvIndex.(nvIndexContextInternal); isNv {
		nv.SetAttr(AttrNVWritten)
	}
	return nil
}

// NVExtend executes the TPM2_NV_Extend command to extend data to the NV index associated with
// nvIndex, using the index's name algorithm.
//
// The command requires authorization, defined by the state of the [AttrNVPPWrite],
// [AttrNVOwnerWrite], [AttrNVAuthWrite] and [AttrNVPolicyWrite] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPWrite] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerWrite]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *TPMError error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthWrite] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyWrite] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVWriteLocked] attribute set, a *[TPMError] error with an error code
// of [ErrorNVLocked] will be returned.
//
// If the type of the index is not [NVTypeExtend], a *TPMHandleError error with an error code of
// [ErrorAttributes] will be returned for handle index 2.
//
// On successful completion, the [AttrNVWritten] flag will be set if this is the first time that
// the index has been written to. The name of nvIndex will be updated accordingly as long as it
// wasn't created with [NewLimitedResourceContext].
func (t *TPMContext) NVExtend(authContext, nvIndex ResourceContext, data MaxNVBuffer, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.StartCommand(CommandNVExtend).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddParams(data).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	if nv, isNv := nvIndex.(nvIndexContextInternal); isNv {
		nv.SetAttr(AttrNVWritten)
	}
	return nil
}

// NVSetBits executes the TPM2_NV_SetBits command to OR the value of bits with the contents of the
// NV index associated with nvIndex.
//
// The command requires authorization, defined by the state of the [AttrNVPPWrite],
// [AttrNVOwnerWrite], [AttrNVAuthWrite] and [AttrNVPolicyWrite] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPWrite] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerWrite]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *TPMError error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthWrite] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyWrite] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVWriteLocked] attribute set, a *[TPMError] error with an error code
// of [ErrorNVLocked] will be returned.
//
// If the type of the index is not [NVTypeBits], a *[TPMHandleError] error with an error code of
// [ErrorAttributes] will be returned for handle index 2.
//
// On successful completion, the [AttrNVWritten] flag will be set if this is the first time that
// the index has been written to. The name of nvIndex will be updated accordingly as long as it
// wasn't created with [NewLimitedResourceContext].
func (t *TPMContext) NVSetBits(authContext, nvIndex ResourceContext, bits uint64, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.StartCommand(CommandNVSetBits).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddParams(bits).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	if nv, isNv := nvIndex.(nvIndexContextInternal); isNv {
		nv.SetAttr(AttrNVWritten)
	}
	return nil
}

// NVWriteLock executes the TPM2_NV_WriteLock command to inhibit further writes to the NV index
// associated with nvIndex.
//
// The command requires authorization, defined by the state of the [AttrNVPPWrite],
// [AttrNVOwnerWrite], [AttrNVAuthWrite] and [AttrNVPolicyWrite] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPWrite] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerWrite]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthWrite] or [AttrNVPolicyWrite] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *TPMError error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthWrite] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyWrite] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has neither the [AttrNVWriteDefine] or [AttrNVWriteStClear] attributes set, then a
// *[TPMHandleError] error with an error code of [ErrorAttributes] will be returned for handle
// index 2.
//
// On successful completion, the [AttrNVWriteLocked] attribute will be set. The name of nvIndex
// will be updated accordingly as long as it wasn't created with [NewLimitedResourceContext].
// The attribute will be cleared again (and writes will be reenabled) on the next TPM reset or TPM
// restart unless the index has the [AttrNVWriteDefine] attribute set and [AttrNVWritten] attribute
// is set.
func (t *TPMContext) NVWriteLock(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.StartCommand(CommandNVWriteLock).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	if nv, isNv := nvIndex.(nvIndexContextInternal); isNv {
		nv.SetAttr(AttrNVWriteLocked)
	}
	return nil
}

// NVGlobalWriteLock executes the TPM2_NV_GlobalWriteLock command to inhibit further writes for all
// NV indexes that have the [AttrNVGlobalLock] attribute set.
//
// The authContext parameter specifies a hierarchy, and should correspond to either
// [HandlePlatform] or [HandleOwner]. The command requires the user auth role for authContext, with
// session based authorization provided via authContextAuthSession.
//
// On successful completion, the [AttrNVWriteLocked] attribute will be set for all NV indexes that
// have the [AttrNVGlobalLock] attribute set. If an index also has the [AttrNVWriteDefine]
// attribute set, this will permanently inhibit further writes unless [AttrNVWritten] is clear.
// ResourceContext instances associated with NV indices that are updated as a consequence of this
// function will no longer be able to be used because the name will be incorrect.
func (t *TPMContext) NVGlobalWriteLock(authContext ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.StartCommand(CommandNVGlobalWriteLock).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession)).
		AddExtraSessions(sessions...).
		Run(nil)
}

// NVReadRaw executes the TPM2_NV_Read command to read the contents of the NV index associated with
// nvIndex. The amount of data to read, and the offset within the index are defined by the size and
// offset parameters.
//
// The command requires authorization, defined by the state of the [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] and [AttrNVPolicyRead] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPRead] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerRead]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthRead] or [AttrNVPolicyRead] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *[TPMError] error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthRead] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyRead] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVReadLocked] attribute set, a *[TPMError] error with an error code of
// [ErrorNVLocked] will be returned.
//
// If the index has not been initialized (ie, the [AttrNVWritten] attribute is not set), a
// *[TPMError] error with an error code of [ErrorNVUninitialized] will be returned.
//
// If the value of size is too large, a *[TPMParameterError] error with an error code of
// [ErrorValue] will be returned for parameter index 1.
//
// If the value of offset falls outside of the bounds of the index, a *[TPMParameterError] error
// with an error code of [ErrorValue] will be returned for parameter index 2.
//
// If the data selection falls outside of the bounds of the index, a *[TPMError] error with an
// error code of [ErrorNVRange] will be returned.
//
// On successful completion, the requested data will be returned.
func (t *TPMContext) NVReadRaw(authContext, nvIndex ResourceContext, size, offset uint16, authContextAuthSession SessionContext, sessions ...SessionContext) (data MaxNVBuffer, err error) {
	if err := t.StartCommand(CommandNVRead).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddParams(size, offset).
		AddExtraSessions(sessions...).
		Run(nil, &data); err != nil {
		return nil, err
	}

	return data, nil
}

type nvReadHelperContext struct {
	authContext ResourceContext
	nvIndex     ResourceContext
	size        uint16
	offset      uint16
	tpm         *TPMContext

	data []byte
}

func (c *nvReadHelperContext) last() bool {
	return c.size <= c.tpm.maxNVBufferSize
}

func (c *nvReadHelperContext) run(sessions ...SessionContext) error {
	sz := c.size
	if c.size > c.tpm.maxNVBufferSize {
		sz = c.tpm.maxNVBufferSize
	}

	data, err := c.tpm.NVReadRaw(c.authContext, c.nvIndex, sz, c.offset, sessions[0], sessions[1:]...)
	if err != nil {
		return err
	}
	c.data = append(c.data, data...)

	c.size -= sz
	c.offset += sz

	return nil
}

// NVRead executes the TPM2_NV_Read command to read the contents of the NV index associated with
// nvIndex. The amount of data to read, and the offset within the index are defined by the size and
// offset parameters.
//
// The command requires authorization, defined by the state of the [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] and [AttrNVPolicyRead] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPRead] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerRead]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthRead] or [AttrNVPolicyRead] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *[TPMError] error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthRead] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyRead] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the requested data can not be read in a single command, this function will re-execute the
// TPM2_NV_Read command until all data is read. In this case, authContextAuth should not correspond
// to a policy session.
//
// If the index has the [AttrNVReadLocked] attribute set, a *[TPMError] error with an error code of
// [ErrorNVLocked] will be returned.
//
// If the index has not been initialized (ie, the [AttrNVWritten] attribute is not set), a
// *[TPMError] error with an error code of [ErrorNVUninitialized] will be returned.
//
// If the value of size is too large, a *[TPMParameterError] error with an error code of
// [ErrorValue] will be returned for parameter index 1.
//
// If the value of offset falls outside of the bounds of the index, a *[TPMParameterError] error
// with an error code of [ErrorValue] will be returned for parameter index 2.
//
// If the data selection falls outside of the bounds of the index, a *[TPMError] error with an
// error code of [ErrorNVRange] will be returned.
//
// On successful completion, the requested data will be returned.
func (t *TPMContext) NVRead(authContext, nvIndex ResourceContext, size, offset uint16, authContextAuthSession SessionContext, sessions ...SessionContext) (data []byte, err error) {
	if err := t.initPropertiesIfNeeded(); err != nil {
		return nil, err
	}

	sessionsCopy := []SessionContext{authContextAuthSession}
	sessionsCopy = append(sessionsCopy, sessions...)

	context := &nvReadHelperContext{
		authContext: authContext,
		nvIndex:     nvIndex,
		size:        size,
		offset:      offset,
		tpm:         t}

	if err := execMultipleHelper(context, sessionsCopy...); err != nil {
		return nil, err
	}
	return context.data, nil
}

func (t *TPMContext) nvReadUint64(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) (uint64, error) {
	data, err := t.NVRead(authContext, nvIndex, 8, 0, authContextAuthSession, sessions...)
	if err != nil {
		return 0, err
	}
	if len(data) != binary.Size(uint64(0)) {
		return 0, &InvalidResponseError{CommandNVRead, fmt.Errorf("unexpected number of bytes returned (got %d)", len(data))}
	}
	return binary.BigEndian.Uint64(data), nil
}

// NVReadBits is a convenience function for [TPMContext.NVRead] for reading the contents of the NV
// bit field index associated with nvIndex. If the type of nvIndex is not [NVTypeBits], an error
// will be returned. This will return an error if nvIndex was created with
// [NewLimitedResourceContext].
//
// The command requires authorization, defined by the state of the [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] and [AttrNVPolicyRead] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPRead] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerRead]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthRead] or [AttrNVPolicyRead] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *[TPMError] error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthRead] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyRead] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVReadLocked] attribute set, a *[TPMError] error with an error code of
// [ErrorNVLocked] will be returned.
//
// If the index has not been initialized (ie, the [AttrNVWritten] attribute is not set), a
// *[TPMError] error with an error code of [ErrorNVUninitialized] will be returned.
//
// On successful completion, the current bitfield value will be returned.
func (t *TPMContext) NVReadBits(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) (uint64, error) {
	context, isNv := nvIndex.(nvIndexContextInternal)
	if !isNv {
		return 0, errors.New("nvIndex does not correspond to a NV index")
	}
	if context.Attrs().Type() != NVTypeBits {
		return 0, errors.New("nvIndex does not correspond to a bit field")
	}
	return t.nvReadUint64(authContext, nvIndex, authContextAuthSession, sessions...)
}

// NVReadCounter is a convenience function for [TPMContext.NVRead] for reading the contents of the
// NV counter index associated with nvIndex. If the type of nvIndex is not [NVTypeCounter], an
// error will be returned. This will return an error if nvIndex was created with
// [NewLimitedResourceContext].
//
// The command requires authorization, defined by the state of the [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] and [AttrNVPolicyRead] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPRead] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerRead]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthRead] or [AttrNVPolicyRead] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *[TPMError] error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthRead] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyRead] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVReadLocked] attribute set, a *[TPMError] error with an error code of
// [ErrorNVLocked] will be returned.
//
// If the index has not been initialized (ie, the [AttrNVWritten] attribute is not set), a
// *[TPMError] error with an error code of [ErrorNVUninitialized] will be returned.
//
// On successful completion, the current counter value will be returned.
func (t *TPMContext) NVReadCounter(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) (uint64, error) {
	context, isNv := nvIndex.(nvIndexContextInternal)
	if !isNv {
		return 0, errors.New("nvIndex does not correspond to a NV index")
	}
	if context.Attrs().Type() != NVTypeCounter {
		return 0, errors.New("nvIndex does not correspond to a counter")
	}
	return t.nvReadUint64(authContext, nvIndex, authContextAuthSession, sessions...)
}

// NVReadPinCounterParams is a convenience function for [TPMContext.NVRead] for reading the
// contents of the NV pin pass or NV pin fail index associated with nvIndex. If the type of nvIndex
// is not [NVTypePinPass] or [NVTypePinFail], an error will be returned. This will return an error
// if nvIndex was created with [NewLimitedResourceContext].
//
// The command requires authorization, defined by the state of the [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] and [AttrNVPolicyRead] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPRead] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerRead]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthRead] or [AttrNVPolicyRead] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *[TPMError] error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthRead] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyRead] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index has the [AttrNVReadLocked] attribute set, a *[TPMError] error with an error code of
// [ErrorNVLocked] will be returned.
//
// If the index has not been initialized (ie, the [AttrNVWritten] attribute is not set), a
// *[TPMError] error with an error code of [ErrorNVUninitialized] will be returned.
//
// On successful completion, the current PIN count and limit will be returned.
func (t *TPMContext) NVReadPinCounterParams(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) (*NVPinCounterParams, error) {
	context, isNv := nvIndex.(nvIndexContextInternal)
	if !isNv {
		return nil, errors.New("nvIndex does not correspond to a NV index")
	}
	if context.Attrs().Type() != NVTypePinPass && context.Attrs().Type() != NVTypePinFail {
		return nil, errors.New("nvIndex does not correspond to a PIN pass or PIN fail index")
	}
	data, err := t.NVRead(authContext, nvIndex, 8, 0, authContextAuthSession, sessions...)
	if err != nil {
		return nil, err
	}
	var res NVPinCounterParams
	if _, err := mu.UnmarshalFromBytes(data, &res); err != nil {
		return nil, &InvalidResponseError{CommandNVRead, fmt.Errorf("cannot unmarshal response bytes: %w", err)}
	}
	return &res, nil
}

// NVReadLock executes the TPM2_NV_ReadLock command to inhibit further reads of the NV index
// associated with nvIndex.
//
// The command requires authorization, defined by the state of the [AttrNVPPRead],
// [AttrNVOwnerRead], [AttrNVAuthRead] and [AttrNVPolicyRead] attributes. The handle used for
// authorization is specified via authContext. If the NV index has the [AttrNVPPRead] attribute,
// authorization can be satisfied with [HandlePlatform]. If the NV index has the [AttrNVOwnerRead]
// attribute, authorization can be satisfied with [HandleOwner]. If the NV index has the
// [AttrNVAuthRead] or [AttrNVPolicyRead] attribute, authorization can be satisfied with nvIndex.
// The command requires authorization with the user auth role for authContext, with session based
// authorization provided via authContextAuthSession. If the resource associated with authContext
// is not permitted to authorize this access, a *[TPMError] error with an error code of
// [ErrorNVAuthorization] will be returned.
//
// If nvIndex is being used for authorization and the [AttrNVAuthRead] attribute is defined, the
// authorization can be satisfied by demonstrating knowledge of the authorization value, either via
// cleartext or HMAC authorization. If nvIndex is being used for authorization and the
// [AttrNVPolicyRead] attribute is defined, the authorization can be satisfied using a policy
// session with a digest that matches the authorization policy for the index.
//
// If the index doesn't have the [AttrNVReadStClear] attribute set, then a *[TPMHandleError] error
// with an error code of [ErrorAttributes] will be returned for handle index 2.
//
// On successful completion, the [AttrNVReadLocked] attribute will be set. The name of nvIndex will
// be updated accordingly as long as it wasn't created with [NewLimitedResourceContext]. The
// attribute will be cleared again (and reads will be reenabled) on the next TPM reset or TPM
// restart.
func (t *TPMContext) NVReadLock(authContext, nvIndex ResourceContext, authContextAuthSession SessionContext, sessions ...SessionContext) error {
	if err := t.StartCommand(CommandNVReadLock).
		AddHandles(UseResourceContextWithAuth(authContext, authContextAuthSession), UseHandleContext(nvIndex)).
		AddExtraSessions(sessions...).
		Run(nil); err != nil {
		return err
	}

	if nv, isNv := nvIndex.(nvIndexContextInternal); isNv {
		nv.SetAttr(AttrNVReadLocked)
	}
	return nil
}

// NVChangeAuth executes the TPM2_NV_ChangeAuth command to change the authorization value for the
// NV index associated with nvIndex, setting it to the new value defined by newAuth. The command
// requires the admin auth role for nvIndex, with the session provided via nvIndexAuthSession.
//
// If the size of newAuth is greater than the name algorithm for the index, a *[TPMParameterError]
// error with an error code of [ErrorSize] will be returned.
//
// On successful completion, the authorization value of the NV index associated with nvIndex will
// be set to the value of newAuth, and nvIndex will be updated to reflect this - it isn't necessary
// to update nvIndex with [ResourceContext].SetAuthValue in order to use it in authorization roles
// that require knowledge of the authorization value for the index.
func (t *TPMContext) NVChangeAuth(nvIndex ResourceContext, newAuth Auth, nvIndexAuthSession SessionContext, sessions ...SessionContext) error {
	r, err := t.StartCommand(CommandNVChangeAuth).
		AddHandles(UseResourceContextWithAuth(nvIndex, nvIndexAuthSession)).
		AddParams(newAuth).
		AddExtraSessions(sessions...).
		RunWithoutProcessingResponse(nil)
	if err != nil {
		return err
	}

	// If the session is not bound to nvIndex, the TPM will respond with a HMAC generated with a key derived from newAuth. If the
	// session is bound, the TPM will respond with a HMAC generated from the original key
	nvIndex.SetAuthValue(newAuth)

	return r.Complete()
}

// func (t *TPMContext) NVCertify(signContext, authContext, nvIndex HandleContext, qualifyingData Data,
//	inScheme *SigScheme, size, offset uint16, signContextAuth, authContextAuth interface{},
//	sessions ...SessionContext) (*Attest, *Signature, error) {
// }
