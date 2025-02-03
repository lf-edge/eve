// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/canonical/go-tpm2/mu"
)

// HandleContext corresponds to an entity that resides on the TPM. Implementations of HandleContext
// maintain some host-side state in order to be able to participate in sessions. They are
// invalidated when used in a command that results in the entity being flushed or evicted from the
// TPM. Once invalidated, they can no longer be used.
type HandleContext interface {
	// Handle returns the handle of the corresponding entity on the TPM. If the HandleContext has been
	// invalidated then this will return HandleUnassigned.
	Handle() Handle
	Name() Name                        // The name of the entity
	SerializeToBytes() []byte          // Return a byte slice containing the serialized form of this HandleContext
	SerializeToWriter(io.Writer) error // Write the serialized form of this HandleContext to the supplied io.Writer
}

type handleContextInternalMixin interface {
	Invalidate()
	SetHandle(handle Handle)
}

type handleContextInternal interface {
	HandleContext
	handleContextInternalMixin
}

// SessionContext is a HandleContext that corresponds to a session on the TPM.
type SessionContext interface {
	HandleContext
	HashAlg() HashAlgorithmId // The session's digest algorithm. Will be HashAlgorithmNul if the context corresponds to a saved session.
	NonceTPM() Nonce          // The most recent TPM nonce value. Can be empty if this context corresponds to a saved session.
	IsAudit() bool            // Whether the session has been used for audit
	IsExclusive() bool        // Whether the most recent response from the TPM indicated that the session is exclusive for audit purposes

	Attrs() SessionAttributes                         // The attributes associated with this session
	SetAttrs(attrs SessionAttributes)                 // Set the attributes that will be used for this SessionContext
	WithAttrs(attrs SessionAttributes) SessionContext // Return a duplicate of this SessionContext with the specified attributes

	// IncludeAttrs returns a duplicate of this SessionContext and its attributes with the specified attributes included.
	IncludeAttrs(attrs SessionAttributes) SessionContext
	// ExcludeAttrs returns a duplicate of this SessionContext and its attributes with the specified attributes excluded.
	ExcludeAttrs(attrs SessionAttributes) SessionContext
}

type sessionContextInternal interface {
	SessionContext
	handleContextInternalMixin

	Data() *sessionContextData
	Unload()
}

// ResourceContext is a HandleContext that corresponds to a non-session entity on the TPM.
type ResourceContext interface {
	HandleContext

	// SetAuthValue sets the authorization value that will be used in authorization roles where
	// knowledge of the authorization value is required. Functions that create resources on the TPM
	// and return a ResourceContext will set this automatically, else it will need to be set manually.
	SetAuthValue([]byte)
}

type resourceContextInternal interface {
	ResourceContext
	handleContextInternalMixin

	GetAuthValue() []byte
}

type objectContextInternal interface {
	resourceContextInternal

	GetPublic() *Public
}

type nvIndexContextInternal interface {
	resourceContextInternal

	GetPublic() *NVPublic
	SetAttr(a NVAttributes)
	ClearAttr(a NVAttributes)
	Attrs() NVAttributes
}

type handleContextType uint8

const (
	handleContextTypeLimited handleContextType = iota
	handleContextTypePermanent
	handleContextTypeObject
	handleContextTypeNvIndex
	handleContextTypeSession
	handleContextTypeLimitedResource
)

type sessionContextData struct {
	IsAudit        bool
	IsExclusive    bool
	HashAlg        HashAlgorithmId
	SessionType    SessionType
	PolicyHMACType policyHMACType
	IsBound        bool
	BoundEntity    Name
	SessionKey     []byte
	NonceCaller    Nonce
	NonceTPM       Nonce
	Symmetric      *SymDef
}

type sessionContextDataWrapper struct {
	Data *sessionContextData `tpm2:"sized"`
}

type handleContextU struct {
	Object  *Public
	NV      *NVPublic
	Session *sessionContextDataWrapper
}

func (d *handleContextU) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(handleContextType) {
	case handleContextTypeLimited, handleContextTypePermanent, handleContextTypeLimitedResource:
		return mu.NilUnionValue
	case handleContextTypeObject:
		return &d.Object
	case handleContextTypeNvIndex:
		return &d.NV
	case handleContextTypeSession:
		return &d.Session
	default:
		return nil
	}
}

type handleContext struct {
	Type handleContextType
	H    Handle
	N    Name
	Data *handleContextU
}

func (h *handleContext) Handle() Handle {
	return h.H
}

func (h *handleContext) Name() Name {
	return h.N
}

func (h *handleContext) SerializeToBytes() []byte {
	data := mu.MustMarshalToBytes(h)

	hash := crypto.SHA256.New()
	hash.Write(data)
	return mu.MustMarshalToBytes(HashAlgorithmSHA256, hash.Sum(nil), data)
}

func (h *handleContext) SerializeToWriter(w io.Writer) error {
	data := mu.MustMarshalToBytes(h)

	hash := crypto.SHA256.New()
	hash.Write(data)
	_, err := mu.MarshalToWriter(w, HashAlgorithmSHA256, hash.Sum(nil), data)
	return err
}

func (h *handleContext) Invalidate() {
	h.H = HandleUnassigned
	h.N = make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(h.N, uint32(h.H))
}

func (h *handleContext) SetHandle(handle Handle) {
	h.H = handle
}

func (h *handleContext) checkValid() error {
	switch h.Type {
	case handleContextTypeLimited, handleContextTypePermanent, handleContextTypeObject, handleContextTypeNvIndex, handleContextTypeLimitedResource:
		return nil
	case handleContextTypeSession:
		data := h.Data.Session.Data
		if data == nil {
			return nil
		}
		if !data.HashAlg.Available() {
			return errors.New("digest algorithm for session context is not available")
		}
		switch data.SessionType {
		case SessionTypeHMAC, SessionTypePolicy, SessionTypeTrial:
		default:
			return errors.New("invalid session type for session context")
		}
		if data.PolicyHMACType > policyHMACTypeMax {
			return errors.New("invalid policy session HMAC type for session context")
		}
		return nil
	default:
		// shouldn't happen because it should have failed to unmarshal
		panic("invalid context type")
	}
}

func newLimitedHandleContext(handle Handle) *handleContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &handleContext{
		Type: handleContextTypeLimited,
		H:    handle,
		N:    name}
}

type resourceContext struct {
	handleContext
	authValue []byte
}

func newLimitedResourceContext(handle Handle, name Name) *resourceContext {
	return &resourceContext{
		handleContext: handleContext{
			Type: handleContextTypeLimitedResource,
			H:    handle,
			N:    name}}
}

func (r *resourceContext) SetAuthValue(authValue []byte) {
	r.authValue = authValue
}

func (r *resourceContext) GetAuthValue() []byte {
	return bytes.TrimRight(r.authValue, "\x00")
}

type permanentContext struct {
	resourceContext
}

func (r *permanentContext) Invalidate() {}

func newPermanentContext(handle Handle) *permanentContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &permanentContext{
		resourceContext: resourceContext{
			handleContext: handleContext{
				Type: handleContextTypePermanent,
				H:    handle,
				N:    name}}}
}

func nullResource() ResourceContext {
	return newPermanentContext(HandleNull)
}

type objectContext struct {
	resourceContext
}

func (r *objectContext) GetPublic() *Public {
	return r.Data.Object
}

func newObjectContext(handle Handle, name Name, public *Public) *objectContext {
	return &objectContext{
		resourceContext: resourceContext{
			handleContext: handleContext{
				Type: handleContextTypeObject,
				H:    handle,
				N:    name,
				Data: &handleContextU{Object: public}}}}
}

func (t *TPMContext) newObjectContextFromTPM(context HandleContext, sessions ...SessionContext) (ResourceContext, error) {
	pub, name, _, err := t.ReadPublic(context, sessions...)
	if err != nil {
		return nil, err
	}
	if pub.NameAlg.Available() && !pub.compareName(name) {
		return nil, &InvalidResponseError{CommandReadPublic, errors.New("name and public area returned from TPM don't match")}
	}
	return newObjectContext(context.Handle(), name, pub), nil
}

type nvIndexContext struct {
	resourceContext
}

func (r *nvIndexContext) GetPublic() *NVPublic {
	return r.Data.NV
}

func (r *nvIndexContext) SetAttr(a NVAttributes) {
	r.Data.NV.Attrs |= a
	r.N = r.Data.NV.Name()
}

func (r *nvIndexContext) ClearAttr(a NVAttributes) {
	r.Data.NV.Attrs &= ^a
	r.N = r.Data.NV.Name()
}

func (r *nvIndexContext) Attrs() NVAttributes {
	return r.Data.NV.Attrs
}

func newNVIndexContext(name Name, public *NVPublic) *nvIndexContext {
	return &nvIndexContext{
		resourceContext: resourceContext{
			handleContext: handleContext{
				Type: handleContextTypeNvIndex,
				H:    public.Index,
				N:    name,
				Data: &handleContextU{NV: public}}}}
}

func (t *TPMContext) newNVIndexContextFromTPM(context HandleContext, sessions ...SessionContext) (ResourceContext, error) {
	pub, name, err := t.NVReadPublic(context, sessions...)
	if err != nil {
		return nil, err
	}
	if pub.NameAlg.Available() && !pub.compareName(name) {
		return nil, &InvalidResponseError{CommandNVReadPublic, errors.New("name and public area returned from TPM don't match")}
	}
	if pub.Index != context.Handle() {
		return nil, &InvalidResponseError{CommandNVReadPublic, errors.New("unexpected index in public area")}
	}
	return newNVIndexContext(name, pub), nil
}

type sessionContext struct {
	*handleContext
	attrs SessionAttributes
}

func (r *sessionContext) HashAlg() HashAlgorithmId {
	d := r.Data()
	if d == nil {
		return HashAlgorithmNull
	}
	return d.HashAlg
}

func (r *sessionContext) NonceTPM() Nonce {
	d := r.Data()
	if d == nil {
		return nil
	}
	return d.NonceTPM
}

func (r *sessionContext) IsAudit() bool {
	d := r.Data()
	if d == nil {
		return false
	}
	return d.IsAudit
}

func (r *sessionContext) IsExclusive() bool {
	d := r.Data()
	if d == nil {
		return false
	}
	return d.IsExclusive
}

func (r *sessionContext) Attrs() SessionAttributes {
	attrs := r.attrs
	if attrs&AttrAuditExclusive > 0 {
		attrs |= AttrAudit
	}
	if attrs&AttrAuditReset > 0 {
		attrs |= AttrAudit
	}
	return attrs
}

func (r *sessionContext) SetAttrs(attrs SessionAttributes) {
	r.attrs = attrs
}

func (r *sessionContext) WithAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{handleContext: r.handleContext, attrs: attrs}
}

func (r *sessionContext) IncludeAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{handleContext: r.handleContext, attrs: r.attrs | attrs}
}

func (r *sessionContext) ExcludeAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{handleContext: r.handleContext, attrs: r.attrs &^ attrs}
}

func (r *sessionContext) Data() *sessionContextData {
	return r.handleContext.Data.Session.Data
}

func (r *sessionContext) Unload() {
	r.handleContext.Data.Session.Data = nil
}

func (r *sessionContext) SetHandle(handle Handle) {
	panic("calling SetHandle on sessionContext is invalid")
}

func newSessionContext(handle Handle, data *sessionContextData) *sessionContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &sessionContext{
		handleContext: &handleContext{
			Type: handleContextTypeSession,
			H:    handle,
			N:    name,
			Data: &handleContextU{Session: &sessionContextDataWrapper{Data: data}}}}
}

func pwSession() SessionContext {
	return newSessionContext(HandlePW, new(sessionContextData)).WithAttrs(AttrContinueSession)
}

func (t *TPMContext) newResourceContextFromTPM(handle HandleContext, sessions ...SessionContext) (rc ResourceContext, err error) {
	switch handle.Handle().Type() {
	case HandleTypeNVIndex:
		rc, err = t.newNVIndexContextFromTPM(handle, sessions...)
	case HandleTypeTransient, HandleTypePersistent:
		rc, err = t.newObjectContextFromTPM(handle, sessions...)
	default:
		panic("invalid handle type")
	}

	switch {
	case IsTPMWarning(err, WarningReferenceH0, AnyCommandCode):
		return nil, ResourceUnavailableError{handle.Handle()}
	case IsTPMHandleError(err, ErrorHandle, AnyCommandCode, AnyHandleIndex):
		return nil, ResourceUnavailableError{handle.Handle()}
	case err != nil:
		return nil, err
	}

	return rc, nil
}

// NewResourceContext creates and returns a new ResourceContext for the specified handle. It will
// execute a command to read the public area from the TPM in order to initialize state that
// is maintained on the host side. A [ResourceUnavailableError] error will be returned if the
// specified handle references a resource that doesn't exist.
//
// The public area and name returned from the TPM are checked for consistency as long as the
// corresponding name algorithm is linked into the current binary.
//
// If any sessions are supplied, the public area is read from the TPM twice. The second time uses
// the supplied sessions.
//
// This function will panic if handle doesn't correspond to a NV index, transient object or
// persistent object.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value
// of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func (t *TPMContext) NewResourceContext(handle Handle, sessions ...SessionContext) (ResourceContext, error) {
	rc, err := t.newResourceContextFromTPM(newLimitedHandleContext(handle))
	if err != nil {
		return nil, err
	}

	if len(sessions) == 0 {
		return rc, nil
	}

	return t.newResourceContextFromTPM(rc, sessions...)
}

// CreateResourceContextFromTPM creates and returns a new ResourceContext for the specified handle.
// It will execute a command to read the public area from the TPM in order to initialize state that
// is maintained on the host side. A [ResourceUnavailableError] error will be returned if the
// specified handle references a resource that doesn't exist.
//
// The public area and name returned from the TPM are checked for consistency as long as the
// corresponding name algorithm is linked into the current binary.
//
// If any sessions are supplied, the public area is read from the TPM twice. The second time uses
// the supplied sessions.
//
// This function will panic if handle doesn't correspond to a NV index, transient object or
// persistent object.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value
// of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// Deprecated: Use [TPMContext.NewResourceContext] instead.
func (t *TPMContext) CreateResourceContextFromTPM(handle Handle, sessions ...SessionContext) (ResourceContext, error) {
	return t.NewResourceContext(handle, sessions...)
}

// NewLimitedHandleContext creates a new HandleContext for the specified handle. The returned
// HandleContext can not be used in any commands other than [TPMContext.FlushContext],
// [TPMContext.ReadPublic] or [TPMContext.NVReadPublic], and it cannot be used with any sessions.
//
// This function will panic if handle doesn't correspond to a session, transient or persistent
// object, or NV index.
func NewLimitedHandleContext(handle Handle) HandleContext {
	switch handle.Type() {
	case HandleTypeNVIndex, HandleTypeHMACSession, HandleTypePolicySession, HandleTypeTransient, HandleTypePersistent:
		return newLimitedHandleContext(handle)
	default:
		panic("invalid handle type")
	}
}

// CreatePartialHandleContext creates a new HandleContext for the specified handle. The returned
// HandleContext is partial and cannot be used in any command other than [TPMContext.FlushContext],
// [TPMContext.ReadPublic] or [TPMContext.NVReadPublic], and it cannot be used with any sessions.
//
// This function will panic if handle doesn't correspond to a session, transient or persistent
// object, or NV index.
//
// Deprecated: Use [NewLimitedHandleContext].
func CreatePartialHandleContext(handle Handle) HandleContext {
	return NewLimitedHandleContext(handle)
}

// GetPermanentContext returns a ResourceContext for the specified permanent handle or PCR handle.
//
// This function will panic if handle does not correspond to a permanent or PCR handle.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value
// of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func (t *TPMContext) GetPermanentContext(handle Handle) ResourceContext {
	switch handle.Type() {
	case HandleTypePermanent, HandleTypePCR:
		if rc, exists := t.permanentResources[handle]; exists {
			return rc
		}

		rc := newPermanentContext(handle)
		t.permanentResources[handle] = rc
		return rc
	default:
		panic("invalid handle type")
	}
}

// OwnerHandleContext returns the ResouceContext corresponding to the owner hiearchy.
func (t *TPMContext) OwnerHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleOwner)
}

// NulHandleContext returns the ResourceContext corresponding to the null hiearchy.
func (t *TPMContext) NullHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleNull)
}

// LockoutHandleContext returns the ResourceContext corresponding to the lockout hiearchy.
func (t *TPMContext) LockoutHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleLockout)
}

// EndorsementHandleContext returns the ResourceContext corresponding to the endorsement hiearchy.
func (t *TPMContext) EndorsementHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleEndorsement)
}

// PlatformHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformHandleContext() ResourceContext {
	return t.GetPermanentContext(HandlePlatform)
}

// PlatformNVHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformNVHandleContext() ResourceContext {
	return t.GetPermanentContext(HandlePlatformNV)
}

// PCRHandleContext returns the ResourceContext corresponding to the PCR at the specified index.
// It will panic if pcr is not a valid PCR index.
func (t *TPMContext) PCRHandleContext(pcr int) ResourceContext {
	h := Handle(pcr)
	if h.Type() != HandleTypePCR {
		panic("invalid PCR index")
	}
	return t.GetPermanentContext(h)
}

// NewHandleContextFromReader returns a new HandleContext created from the serialized data read
// from the supplied io.Reader. This should contain data that was previously created by
// [HandleContext].SerializeToBytes or [HandleContext].SerializeToWriter.
//
// If the supplied data corresponds to a session then a [SessionContext] will be returned, else a
// [ResourceContext] will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func NewHandleContextFromReader(r io.Reader) (HandleContext, error) {
	var integrityAlg HashAlgorithmId
	var integrity []byte
	var b []byte
	if _, err := mu.UnmarshalFromReader(r, &integrityAlg, &integrity, &b); err != nil {
		return nil, fmt.Errorf("cannot unpack context blob and checksum: %w", err)
	}

	if !integrityAlg.Available() {
		return nil, errors.New("invalid checksum algorithm")
	}
	h := integrityAlg.NewHash()
	h.Write(b)
	if !bytes.Equal(h.Sum(nil), integrity) {
		return nil, errors.New("invalid checksum")
	}

	var data *handleContext
	n, err := mu.UnmarshalFromBytes(b, &data)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal context data: %w", err)
	}
	if n < len(b) {
		return nil, errors.New("context blob contains trailing bytes")
	}

	if data.Type == handleContextTypePermanent {
		return nil, errors.New("cannot create a permanent context from serialized data")
	}

	if err := data.checkValid(); err != nil {
		return nil, err
	}

	var hc HandleContext
	switch data.Type {
	case handleContextTypeLimited:
		hc = data
	case handleContextTypeObject:
		hc = &objectContext{resourceContext: resourceContext{handleContext: *data}}
	case handleContextTypeNvIndex:
		hc = &nvIndexContext{resourceContext: resourceContext{handleContext: *data}}
	case handleContextTypeSession:
		hc = &sessionContext{handleContext: data}
	case handleContextTypeLimitedResource:
		hc = &resourceContext{handleContext: *data}
	default:
		panic("not reached")
	}

	return hc, nil
}

// CreateHandleContextFromReader returns a new HandleContext created from the serialized data read
// from the supplied io.Reader. This should contain data that was previously created by
// [HandleContext].SerializeToBytes or [HandleContext].SerializeToWriter.
//
// If the supplied data corresponds to a session then a [SessionContext] will be returned, else a
// [ResourceContext] will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// Deprecated: Use [NewHandleContextFromReader].
func CreateHandleContextFromReader(r io.Reader) (HandleContext, error) {
	return NewHandleContextFromReader(r)
}

// NewHandleContextFromBytes returns a new HandleContext created from the serialized data read
// from the supplied byte slice. This should contain data that was previously created by
// [HandleContext].SerializeToBytes or [HandleContext].SerializeToWriter.
//
// If the supplied data corresponds to a session then a [SessionContext] will be returned, else a
// [ResourceContext] will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func NewHandleContextFromBytes(b []byte) (HandleContext, int, error) {
	buf := bytes.NewReader(b)
	rc, err := NewHandleContextFromReader(buf)
	if err != nil {
		return nil, 0, err
	}
	return rc, len(b) - buf.Len(), nil
}

// NewLimitedResourceContext creates a new ResourceContext with the specified handle and name. The
// returned ResourceContext has limited functionality - eg, it cannot be used in functions that
// require knowledge of the public area associated with the resource (such as
// [TPMContext.StartAuthSession] and some NV functions).
//
// This function will panic if handle doesn't correspond to a transient or persistent object, or an
// NV index.
func NewLimitedResourceContext(handle Handle, name Name) ResourceContext {
	switch handle.Type() {
	case HandleTypeNVIndex, HandleTypeTransient, HandleTypePersistent:
		return newLimitedResourceContext(handle, name)
	default:
		panic("invalid handle type")
	}
}

// CreateHandleContextFromBytes returns a new HandleContext created from the serialized data read
// from the supplied byte slice. This should contain data that was previously created by
// [HandleContext].SerializeToBytes or [HandleContext].SerializeToWriter.
//
// If the supplied data corresponds to a session then a [SessionContext] will be returned, else a
// [ResourceContext] will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// Deprecated: Use [NewHandleContextFromBytes].
func CreateHandleContextFromBytes(b []byte) (HandleContext, int, error) {
	return NewHandleContextFromBytes(b)
}

// NewNVIndexResourceContextFromPub returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// This requires that the associated name algorithm is linked into the current binary.
func NewNVIndexResourceContextFromPub(pub *NVPublic) (ResourceContext, error) {
	name, err := pub.ComputeName()
	if err != nil {
		return nil, fmt.Errorf("cannot compute name from public area: %v", err)
	}
	return newNVIndexContext(name, pub), nil
}

// NewNVIndexResourceContext returns a new ResourceContext created from the provided public area
// and associated name. This is useful for creating a ResourceContext for an object that uses a
// name algorithm that is not available. If subsequent use of the returned ResourceContext requires
// knowledge of the authorization value of the corresponding TPM resource, this should be provided
// by calling [ResourceContext].SetAuthValue.
func NewNVIndexResourceContext(pub *NVPublic, name Name) ResourceContext {
	return newNVIndexContext(name, pub)
}

// CreateNVIndexResourceContextFromPublic returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// This requires that the associated name algorithm is linked into the current binary.
//
// Deprecated: Use [NewNVIndexResourceContextFromPub].
func CreateNVIndexResourceContextFromPublic(pub *NVPublic) (ResourceContext, error) {
	return NewNVIndexResourceContextFromPub(pub)
}

// NewObjectResourceContextFromPub returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// This requires that the associated name algorithm is linked into the current binary.
func NewObjectResourceContextFromPub(handle Handle, pub *Public) (ResourceContext, error) {
	switch handle.Type() {
	case HandleTypeTransient, HandleTypePersistent:
		name, err := pub.ComputeName()
		if err != nil {
			return nil, fmt.Errorf("cannot compute name from public area: %v", err)
		}
		return newObjectContext(handle, name, pub), nil
	default:
		return nil, errors.New("invalid handle type")
	}
}

// NewObjectResourceContext returns a new ResourceContext created from the provided public area and
// associated name. This is useful for creating a ResourceContext for an object that uses a name
// algorithm that is not available. If subsequent use of the returned ResourceContext requires
// knowledge of the authorization value of the corresponding TPM resource, this should be provided
// by calling [ResourceContext].SetAuthValue.
//
// This will panic if the handle type is not [HandleTypeTransient] or [HandleTypePersistent].
func NewObjectResourceContext(handle Handle, pub *Public, name Name) ResourceContext {
	switch handle.Type() {
	case HandleTypeTransient, HandleTypePersistent:
		return newObjectContext(handle, name, pub)
	default:
		panic("invalid handle type")
	}
}

// CreateObjectResourceContextFromPublic returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// This requires that the associated name algorithm is linked into the current binary.
//
// Deprecated: Use [NewObjectResourceContextFromPub].
func CreateObjectResourceContextFromPublic(handle Handle, pub *Public) (ResourceContext, error) {
	return NewObjectResourceContextFromPub(handle, pub)
}
