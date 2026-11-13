// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 28 - Context Management

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2/mu"
)

// ContextSave executes the TPM2_ContextSave command on the handle referenced by saveContext, in
// order to save the context associated with that handle outside of the TPM. The TPM encrypts and
// integrity protects the context with a key derived from the hierarchy proof. If saveContext does
// not correspond to a transient object or a session, then it will return an error.
//
// On successful completion, it returns a Context instance that can be passed to
// [TPMContext.ContextLoad]. Note that this function wraps the context data returned from the TPM
// with some host-side state associated with the resource, so that it can be restored fully in
// [TPMContext.ContextLoad]. If saveContext corresponds to a session, the host-side state that is
// added to the returned context blob includes the session key.
//
// If saveContext corresponds to a session, then TPM2_ContextSave also removes resources associated
// with the session from the TPM (it becomes a saved session rather than a loaded session). In this
// case, saveContext is marked as not loaded and can only be used as an argument to
// [TPMContext.FlushContext].
//
// If saveContext corresponds to a session and no more contexts can be saved, a *[TPMError] error
// will be returned with an error code of [ErrorTooManyContexts]. If a context ID cannot be
// assigned for the session, a *[TPMWarning] error with a warning code of [WarningContextGap] will
// be returned.
func (t *TPMContext) ContextSave(saveContext HandleContext) (context *Context, err error) {
	if err := t.StartCommand(CommandContextSave).
		AddHandles(UseHandleContext(saveContext)).
		Run(nil, &context); err != nil {
		return nil, err
	}

	if saveContext == nil {
		return nil, &InvalidResponseError{CommandContextSave, errors.New("expected an error because no saveContext was supplied")}
	}

	blob, err := mu.MarshalToBytes(saveContext.SerializeToBytes(), context.Blob)
	if err != nil {
		return nil, fmt.Errorf("cannot wrap context blob: %w", err)
	}
	context.Blob = blob

	switch c := saveContext.(type) {
	case sessionContextInternal:
		c.Unload()
	}

	return context, nil
}

// ContextLoad executes the TPM2_ContextLoad command with the supplied Context, in order to restore
// a context previously saved from [TPMContext.ContextSave].
//
// If the size field of the integrity HMAC in the context blob is greater than the size of the
// largest digest algorithm, a *[TPMError] with an error code of [ErrorSize] is returned. If the
// context blob is shorter than the size indicated for the integrity HMAC, a *[TPMError] with an
// error code of [ErrorInsufficient] is returned.
//
// If the size of the context's integrity HMAC does not match the context integrity digest
// algorithm for the TPM, or the context blob is too short, a *[TPMParameterError] error with an
// error code of [ErrorSize] will be returned. If the integrity HMAC check fails, a
// *[TPMParameterError] with an error code of [ErrorIntegrity] will be returned.
//
// If the hierarchy that the context is part of is disabled, a *[TPMParameterError] error with an
// error code of [ErrorHierarchy] will be returned.
//
// If the context corresponds to a session but the handle doesn't reference a saved session or the
// sequence number is invalid, a *[TPMParameterError] error with an error code of [ErrorHandle]
// will be returned.
//
// If the context corresponds to a session and no more sessions can be created until the oldest
// session is context loaded, and context doesn't correspond to the oldest session, a *[TPMWarning]
// error with a warning code of [WarningContextGap] will be returned.
//
// If there are no more slots available for objects or loaded sessions, a *[TPMWarning] error with
// a warning code of either [WarningSessionMemory] or [WarningObjectMemory] will be returned.
//
// On successful completion, it returns a HandleContext which corresponds to the resource loaded in
// to the TPM. The returned context will be equivalent to the HandleContext originally passed to
// [TPMContext.ContextSave].
func (t *TPMContext) ContextLoad(context *Context) (loadedContext HandleContext, err error) {
	if context == nil {
		return nil, makeInvalidArgError("context", "nil value")
	}

	var contextData []byte
	var blob ContextData
	if _, err := mu.UnmarshalFromBytes(context.Blob, &contextData, &blob); err != nil {
		return nil, fmt.Errorf("cannot unmarshal context blob: %w", err)
	}

	hc, _, err := NewHandleContextFromBytes(contextData)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal handle context: %w", err)
	}

	switch hc.Handle().Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		if hc.Handle() != context.SavedHandle {
			return nil, errors.New("host and TPM context blobs have inconsistent handles")
		}
	case HandleTypeTransient:
	default:
		return nil, errors.New("unexpected context type")
	}

	tpmContext := Context{
		Sequence:    context.Sequence,
		SavedHandle: context.SavedHandle,
		Hierarchy:   context.Hierarchy,
		Blob:        blob}

	var loadedHandle Handle

	if err := t.StartCommand(CommandContextLoad).
		AddParams(tpmContext).
		Run(&loadedHandle); err != nil {
		return nil, err
	}

	switch hc.Handle().Type() {
	case HandleTypeTransient:
		if loadedHandle.Type() != HandleTypeTransient {
			return nil, &InvalidResponseError{CommandContextLoad, fmt.Errorf("handle %v returned from TPM is the wrong type", loadedHandle)}
		}
		hc.(handleContextInternal).SetHandle(loadedHandle)
	case HandleTypeHMACSession, HandleTypePolicySession:
		if loadedHandle != context.SavedHandle {
			return nil, &InvalidResponseError{CommandContextLoad, fmt.Errorf("handle %v returned from TPM is incorrect", loadedHandle)}
		}
		if sc, isSession := hc.(sessionContextInternal); isSession {
			sc.Data().IsExclusive = false
		}
	default:
		panic("not reached")
	}
	return hc, nil
}

// FlushContext executes the TPM2_FlushContext command on the handle referenced by flushContext,
// in order to flush resources associated with it from the TPM. If flushContext does not correspond
// to a transient object or a session, then it will return with an error.
//
// On successful completion, flushContext is invalidated. If flushContext corresponded to a
// session, then it will no longer be possible to restore that session with
// [TPMContext.ContextLoad], even if it was previously saved with [TPMContext.ContextSave].
func (t *TPMContext) FlushContext(flushContext HandleContext) error {
	if flushContext == nil {
		return makeInvalidArgError("flushContext", "nil value")
	}

	if err := t.StartCommand(CommandFlushContext).AddParams(flushContext.Handle()).Run(nil); err != nil {
		return err
	}

	flushContext.(handleContextInternal).Invalidate()
	return nil
}

// EvictControl executes the TPM2_EvictControl command on the handle referenced by object. To
// persist a transient object, object should correspond to the transient object and
// persistentHandle should specify the persistent handle to which the resource associated with
// object should be persisted. To evict a persistent object, object should correspond to the
// persistent object and persistentHandle should be the handle associated with that resource.
//
// The auth parameter should be a ResourceContext that corresponds to a hierarchy - it should be
// [HandlePlatform] for objects within the platform hierarchy, or [HandleOwner] for objects within
// the storage or endorsement hierarchies. If auth is a ResourceContext corresponding to
// [HandlePlatform] but object corresponds to an object outside of the platform hierarchy, or auth
// is a ResourceContext corresponding to [HandleOwner] but object corresponds to an object inside
// of the platform hierarchy, a *[TPMHandleError] error with an error code of [ErrorHierarchy] will
// be returned for handle index 2. The auth handle requires authorization with the user auth role,
// with session based authorization provided via authAuthSession.
//
// If object corresponds to a transient object that only has a public part loaded, or which has the
// [AttrStClear] attribute set, then a *[TPMHandleError] error with an error code of
// [ErrorAttributes] will ba returned for handle index 2.
//
// If object corresponds to a persistent object and persistentHandle is not the handle for that
// object, a *[TPMHandleError] error with an error code of [ErrorHandle] will be returned for
// handle index 2.
//
// If object corresponds to a transient object and persistentHandle is not in the correct range
// determined by the value of auth, a *[TPMParameterError] error with an error code of [ErrorRange]
// will be returned.
//
// If there is insuffient space to persist a transient object, a *[TPMError] error with an error
// code of [ErrorNVSpace] will be returned. If a persistent object already exists at the specified
// handle, a *[TPMError] error with an error code of [ErrorNVDefined] will be returned.
//
// On successful completion of persisting a transient object, it returns a ResourceContext that
// corresponds to the persistent object. If object was created with [NewLimitedResourceContext],
// then a similarly limited context will be returned for the new persistent object. On successful
// completion of evicting a persistent object, it returns a nil ResourceContext, and object will be
// invalidated.
func (t *TPMContext) EvictControl(auth, object ResourceContext, persistentHandle Handle, authAuthSession SessionContext, sessions ...SessionContext) (ResourceContext, error) {
	var public *Public
	if object != nil && object.Handle() != persistentHandle {
		// We are persisting an object
		if obj, isObj := object.(objectContextInternal); isObj {
			// This is not a limited ResourceContext - copy the public area
			if err := mu.CopyValue(&public, obj.GetPublic()); err != nil {
				return nil, fmt.Errorf("cannot copy public area of object: %v", err)
			}
		}
	}

	if err := t.StartCommand(CommandEvictControl).
		AddHandles(UseResourceContextWithAuth(auth, authAuthSession), UseHandleContext(object)).
		AddParams(persistentHandle).
		Run(nil); err != nil {
		return nil, err
	}

	if object == nil {
		return nil, &InvalidResponseError{CommandEvictControl, errors.New("expected an error")}
	}
	name := make(Name, len(object.Name()))
	copy(name, object.Name())

	switch {
	case object.Handle() == persistentHandle:
		object.(handleContextInternal).Invalidate()
		return nil, nil
	case public != nil:
		return newObjectContext(persistentHandle, name, public), nil
	default:
		return newLimitedResourceContext(persistentHandle, name), nil
	}
}
