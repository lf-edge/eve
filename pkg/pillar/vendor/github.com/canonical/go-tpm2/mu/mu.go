// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"runtime"
	"strings"
)

const (
	// maxListLength is the maximum theoretical length of a TPML type that can be
	// supported, although no lists are this long in practise. TPML types have a
	// uint32 length field and are represented in go as slices. The length of a
	// slice is represented as a go int, which is either 32-bit or 64-bit, so set
	// the maximum to the highest number that can be represented by an int32
	maxListLength = math.MaxInt32
)

var (
	sized1BytesType        reflect.Type = reflect.TypeOf(Sized1Bytes(nil))
	customMarshallerType   reflect.Type = reflect.TypeOf((*customMarshallerIface)(nil)).Elem()
	customUnmarshallerType reflect.Type = reflect.TypeOf((*customUnmarshallerIface)(nil)).Elem()
	nilValueType           reflect.Type = reflect.TypeOf(NilUnionValue)
	rawBytesType           reflect.Type = reflect.TypeOf(RawBytes(nil))
	unionType              reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
)

// InvalidSelectorError may be returned as a wrapped error from [UnmarshalFromBytes] or
// [UnmarshalFromReader] when a union type indicates that a selector value is invalid.
type InvalidSelectorError struct {
	Selector reflect.Value
}

func (e *InvalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.Selector)
}

type customMarshallerIface interface {
	Marshal(w io.Writer) error
}

type customUnmarshallerIface interface {
	Unmarshal(r io.Reader) error
}

// CustomMarshaller is implemented by types that require custom marshalling
// behaviour because they are non-standard and not directly supported by this
// package.
//
// If the implementation makes a recursive call in to this package, it should
// return errors from any recursive call without wrapping. This allows the full
// context of the error to be surfaced from the originating call.
type CustomMarshaller interface {
	// Marshal should serialize the value to the supplied writer.
	// The implementation of this should take a value receiver, but if
	// it takes a pointer receiver then the value must be addressable.
	Marshal(w io.Writer) error

	// Unmarshal should unserialize the value from the supplied reader.
	// The implementation of this should take a pointer receiver.
	Unmarshal(r io.Reader) error
}

var _ CustomMarshaller = struct {
	customMarshallerIface
	customUnmarshallerIface
}{}

type empty struct{}

// NilUnionValue is a special value, the type of which should be returned from implementations
// of [Union].Select to indicate that a union contains no data for a particular selector value.
var NilUnionValue empty

// RawBytes is a special byte slice type which is marshalled and unmarshalled without a
// size field. The slice must be pre-allocated to the correct length by the caller during
// unmarshalling.
type RawBytes []byte

// Sized1Bytes is a special byte slice which is marshalled and unmarhalled with a
// single byte size field. This is to faciliate the TPMS_PCR_SELECT type, which
// looks like any other variable sized type (TPML and TPM2B types) with a size
// field and variable sized payload, only TPMS_PCR_SELECT has a single byte size
// field.
type Sized1Bytes []byte

type wrappedValue struct {
	value interface{}
	opts  *options
}

// Raw converts the supplied value, which should be a slice, to a raw slice.
// A raw slice is one that is marshalled without a corresponding size or
// length field.
//
// To unmarshal a raw slice, the supplied value must be a pointer to the
// preallocated destination slice.
func Raw(val interface{}) *wrappedValue {
	return &wrappedValue{value: val, opts: &options{raw: true}}
}

// Sized converts the supplied value to a sized value.
//
// To marshal a sized value, the supplied value must be a pointer to the actual
// value.
//
// To unmarshal a sized value, the supplied value must be a pointer to the
// destination pointer that will point to the unmarshalled value.
func Sized(val interface{}) *wrappedValue {
	return &wrappedValue{value: val, opts: &options{sized: true}}
}

// Union is implemented by structure types that correspond to TPMU prefixed TPM types.
// A struct that contains a union member automatically becomes a tagged union. The
// selector field is the first member of the tagged union, unless overridden with the
// `tpm2:"selector:<field_name>"` tag.
//
// Go doesn't have support for unions - TPMU types must be implemented with
// a struct that contains a field for each possible value.
//
// Implementations of this must be addressable when marshalling.
type Union interface {
	// Select is called by this package to map the supplied selector value
	// to a field. The returned value must be a pointer to the selected field.
	// For this to work correctly, implementations must take a pointer receiver.
	//
	// If the supplied selector value maps to no data, return NilUnionValue.
	//
	// If nil is returned, this is interpreted as an error.
	Select(selector reflect.Value) interface{}
}

type containerNode struct {
	value  reflect.Value
	custom bool
	index  int
	entry  [1]uintptr
}

type containerStack []containerNode

func (s containerStack) push(node containerNode) containerStack {
	return append(s, node)
}

func (s containerStack) pop() containerStack {
	return s[:len(s)-1]
}

func (s containerStack) top() *containerNode {
	return &s[len(s)-1]
}

func (s containerStack) String() string {
	str := new(bytes.Buffer)
	str.WriteString("=== BEGIN STACK ===\n")
	for i := len(s) - 1; i >= 0; i-- {
		switch {
		case s[i].custom && s[i].entry != [1]uintptr{0}:
			frames := runtime.CallersFrames(s[i].entry[:])
			frame, _ := frames.Next()
			fmt.Fprintf(str, "... %s location %s:%d, argument %d\n", s[i].value.Type(), frame.File, frame.Line, s[i].index)
		case s[i].custom:
			fmt.Fprintf(str, "... %s\n", s[i].value.Type())
		case s[i].value.Kind() == reflect.Struct:
			fmt.Fprintf(str, "... %s field %s\n", s[i].value.Type(), s[i].value.Type().Field(s[i].index).Name)
		case s[i].value.Kind() == reflect.Slice:
			fmt.Fprintf(str, "... %s index %d\n", s[i].value.Type(), s[i].index)
		default:
			panic("unsupported kind")
		}
	}
	str.WriteString("=== END STACK ===\n")

	return str.String()
}

// Error is returned from any function in this package to provide context
// of where an error occurred.
type Error struct {
	// Index indicates the argument on which this error occurred.
	Index int

	Op string

	entry    [1]uintptr
	stack    containerStack
	leafType reflect.Type
	err      error
}

func (e *Error) Error() string {
	s := new(bytes.Buffer)
	fmt.Fprintf(s, "cannot %s argument %d whilst processing element of type %s: %v", e.Op, e.Index, e.leafType, e.err)
	if len(e.stack) != 0 {
		fmt.Fprintf(s, "\n\n%s", e.stack)
	}
	return s.String()
}

func (e *Error) Unwrap() error {
	return e.err
}

// Type returns the type of the value on which this error occurred.
func (e *Error) Type() reflect.Type {
	return e.leafType
}

// Depth returns the depth of the value on which this error occurred.
func (e *Error) Depth() int {
	return len(e.stack)
}

// Container returns the type of the container at the specified depth.
//
// If the returned type is a structure, the returned index corresponds
// to the index of the field in that structure.
//
// If the returned type is a slice, the returned index corresponds to
// the index in that slice.
//
// If the returned type implements the [CustomMarshaller] and
// [CustomUnmarshaller] interfaces, the returned index corresponds to
// the argument index in the recursive call in to one of the marshalling
// or unmarshalling APIs. The returned frame indicates where this
// recursive call originated from.
func (e *Error) Container(depth int) (containerType reflect.Type, index int, entry runtime.Frame) {
	var frame runtime.Frame
	if e.stack[depth].entry != [1]uintptr{0} {
		frames := runtime.CallersFrames(e.stack[depth].entry[:])
		frame, _ = frames.Next()
	}

	return e.stack[depth].value.Type(), e.stack[depth].index, frame
}

type fatalError struct {
	index int
	entry [1]uintptr
	stack containerStack
	err   interface{}
}

func (e *fatalError) Error() string {
	s := new(bytes.Buffer)
	fmt.Fprintf(s, "%v", e.err)
	if len(e.stack) > 0 {
		fmt.Fprintf(s, "\n\n%s", e.stack)
	}
	return s.String()
}

type options struct {
	selector string
	sized    bool
	raw      bool
	ignore   bool
	sized1   bool
}

func (o *options) enterSizedType(v reflect.Value) (exit func()) {
	orig := *o
	o.sized = false
	if v.Kind() == reflect.Slice {
		o.raw = true
	}
	return func() {
		*o = orig
	}
}

func parseStructFieldMuOptions(f reflect.StructField) (out *options) {
	out = new(options)

	s := f.Tag.Get("tpm2")
	for _, part := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(part, "selector:"):
			out.selector = part[9:]
		case part == "sized":
			out.sized = true
		case part == "raw":
			out.raw = true
		case part == "ignore":
			out.ignore = true
		case part == "sized1":
			out.sized1 = true
		}
	}

	return out
}

// TPMKind indicates the TPM type class associated with a Go type
type TPMKind int

const (
	// TPMKindUnsupported indicates that a go type has no corresponding
	// TPM type class.
	TPMKindUnsupported TPMKind = iota

	// TPMKindPrimitive indicates that a go type corresponds to one
	// of the primitive TPM types (UINT8, BYTE, INT8, BOOL, UINT16,
	// INT16, UINT32, INT32, UINT64, INT64, TPM_ALG_ID, any TPMA_
	// prefixed type).
	TPMKindPrimitive

	// TPMKindSized indicates that a go type corresponds to a
	// TPM2B prefixed TPM type.
	TPMKindSized

	// TPMKindList indicates that a go type corresponds to a
	// TPML prefixed TPM type.
	TPMKindList

	// TPMKindStruct indicates that a go type corresponds to a
	// TPMS prefixed TPM type.
	TPMKindStruct

	// TPMKindTaggedUnion indicates that a go type corresponds
	// to a TPMT prefixed TPM type.
	TPMKindTaggedUnion

	// TPMKindUnion indicates that a go type corresponds to a
	// TPMU prefixed TPM type.
	TPMKindUnion

	// TPMKindCustom correponds to a go type that defines its own
	// marshalling behaviour.
	TPMKindCustom

	// TPMKindRaw corresponds to a go slice that is marshalled
	// without a size field. It behaves like a sequence of
	// individual values.
	TPMKindRaw

	// TPMKindSized1Bytes indicates that a go type corresponds to
	// a variable sized byte slice with a single byte size field,
	// and is a special type used to support TPMS_PCR_SELECT.
	TPMKindSized1Bytes

	TPMKindFixedBytes

	tpmKindIgnore
)

func isCustom(t reflect.Type) bool {
	if t.Kind() != reflect.Ptr {
		t = reflect.PtrTo(t)
	}
	return t.Implements(customMarshallerType) && t.Implements(customUnmarshallerType)
}

func isUnion(t reflect.Type) bool {
	if t.Kind() != reflect.Ptr {
		t = reflect.PtrTo(t)
	}
	return t.Elem().Kind() == reflect.Struct && t.Implements(unionType)
}

func tpmKind(t reflect.Type, o *options) (TPMKind, error) {
	if o == nil {
		var def options
		o = &def
	}

	if o.ignore {
		return tpmKindIgnore, nil
	}

	sizeSpecifiers := 0
	if o.sized {
		sizeSpecifiers += 1
	}
	if o.raw {
		sizeSpecifiers += 1
	}
	if o.sized1 {
		sizeSpecifiers += 1
	}
	if sizeSpecifiers > 1 {
		return TPMKindUnsupported, errors.New(`only one of "sized", "raw" and "sized1" may be specified`)
	}

	if t.Kind() != reflect.Ptr && isCustom(t) {
		if sizeSpecifiers != 0 || o.selector != "" {
			return TPMKindUnsupported, errors.New("invalid options for custom type")
		}
		return TPMKindCustom, nil
	}

	switch t.Kind() {
	case reflect.Bool, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if sizeSpecifiers != 0 || o.selector != "" {
			return TPMKindUnsupported, errors.New("invalid options for primitive type")
		}
		return TPMKindPrimitive, nil
	case reflect.Ptr:
		switch {
		case t.Elem().Kind() != reflect.Struct:
			// Ignore "sized" for pointers to non-structures. If this parameter is
			// present, we'll return an error after dereferencing.
			return TPMKindUnsupported, nil
		case o.sized:
			return TPMKindSized, nil
		default:
			return TPMKindUnsupported, nil
		}
	case reflect.Slice:
		switch {
		case o.sized || o.selector != "":
			return TPMKindUnsupported, errors.New("invalid options for slice type")
		case o.raw && t == sized1BytesType:
			return TPMKindUnsupported, errors.New(`"raw" option is invalid with Sized1Bytes type`)
		case t == sized1BytesType || o.sized1:
			return TPMKindSized1Bytes, nil
		case t == rawBytesType || o.raw:
			return TPMKindRaw, nil
		case t.Elem().Kind() == reflect.Uint8:
			return TPMKindSized, nil
		default:
			return TPMKindList, nil
		}
	case reflect.Struct:
		if sizeSpecifiers > 0 {
			return TPMKindUnsupported, errors.New("invalid options for struct type")
		}

		k := TPMKindStruct

		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				// structs with unexported fields are unsupported
				return TPMKindUnsupported, errors.New("struct type with unexported fields")
			}
			if isUnion(f.Type) {
				k = TPMKindTaggedUnion
				break
			}
		}

		if isUnion(t) {
			if k == TPMKindTaggedUnion {
				return TPMKindUnsupported, errors.New("struct type cannot represent both a union and tagged union")
			}
			return TPMKindUnion, nil
		}

		if o.selector != "" {
			return TPMKindUnsupported, errors.New(`"selector" option is invalid with struct types that don't represent unions`)
		}

		return k, nil
	case reflect.Array:
		switch {
		case sizeSpecifiers != 0 || o.selector != "":
			return TPMKindUnsupported, errors.New("invalid options for array type")
		case t.Elem().Kind() != reflect.Uint8:
			return TPMKindUnsupported, errors.New("unsupported array type")
		}
		return TPMKindFixedBytes, nil
	default:
		return TPMKindUnsupported, fmt.Errorf("unsupported kind: %v", t.Kind())
	}

}

// DetermineTPMKind returns the TPMKind associated with the supplied go value. It will
// automatically dereference pointer types.
//
// This doesn't mean that the supplied go value can actually be handled by this package
// because it doesn't recurse into containers.
func DetermineTPMKind(i interface{}) TPMKind {
	var t reflect.Type
	var o *options

	switch v := i.(type) {
	case *wrappedValue:
		t = reflect.TypeOf(v.value)
		o = v.opts
	default:
		t = reflect.TypeOf(i)
	}

	for {
		k, err := tpmKind(t, o)
		switch {
		case err != nil:
			return TPMKindUnsupported
		case k == TPMKindUnsupported:
			t = t.Elem()
		default:
			return k
		}
	}
}

type context struct {
	caller [1]uintptr     // address of the function calling into the public API
	mode   string         // marshal or unmarshal
	index  int            // current argument index
	stack  containerStack // type stack for this context

	parent *context // parent context associated with a call from a custom type
}

func (c *context) checkInfiniteRecursion(v reflect.Value) {
	ctx := c
	for ctx != nil {
		for _, n := range ctx.stack {
			if n.value.Type() == v.Type() {
				panic(fmt.Sprintf("infinite recursion detected when processing type %s", v.Type()))
			}
		}
		ctx = ctx.parent
	}
}

func (c *context) enterStructField(s reflect.Value, i int) (exit func()) {
	c.checkInfiniteRecursion(s)
	c.stack = c.stack.push(containerNode{value: s, index: i})

	return func() {
		c.stack = c.stack.pop()
	}
}

func (c *context) enterListElem(l reflect.Value, i int) (exit func()) {
	c.stack = c.stack.push(containerNode{value: l, index: i})

	return func() {
		c.stack = c.stack.pop()
	}
}

func (c *context) enterUnionElem(u reflect.Value, opts *options) (elem reflect.Value, exit func(), err error) {
	valid := false
	if len(c.stack) > 0 {
		if k, _ := tpmKind(c.stack.top().value.Type(), nil); k == TPMKindTaggedUnion {
			valid = true
		}
	}
	if !valid {
		panic(fmt.Sprintf("union type %s is not inside a struct", u.Type()))
	}

	var selectorVal reflect.Value
	if opts == nil || opts.selector == "" {
		selectorVal = c.stack.top().value.Field(0)
	} else {
		selectorVal = c.stack.top().value.FieldByName(opts.selector)
		if !selectorVal.IsValid() {
			panic(fmt.Sprintf("selector name %s for union type %s does not reference a valid field",
				opts.selector, u.Type()))
		}
	}

	if !u.CanAddr() {
		panic(fmt.Sprintf("union type %s needs to be addressable", u.Type()))
	}

	p := u.Addr().Interface().(Union).Select(selectorVal)
	switch {
	case p == nil:
		return reflect.Value{}, nil, &InvalidSelectorError{selectorVal}
	case p == NilUnionValue:
		return reflect.Value{}, nil, nil
	}
	pv := reflect.ValueOf(p)

	index := -1
	for i := 0; i < u.NumField(); i++ {
		if u.Field(i).Addr().Interface() == pv.Interface() {
			index = i
			break
		}
	}
	if index == -1 {
		panic(fmt.Sprintf("Union.Select implementation for type %s returned a non-member pointer",
			u.Type()))
	}

	return pv.Elem(), c.enterStructField(u, index), nil
}

func (c *context) enterCustomType(v reflect.Value) (exit func()) {
	c.checkInfiniteRecursion(v)
	c.stack = c.stack.push(containerNode{value: v, custom: true})

	return func() {
		c.stack = c.stack.pop()
	}
}

func (c *context) wrapOrNewError(value reflect.Value, err error) error {
	muErr, isMuErr := err.(*Error)
	if !isMuErr {
		return c.newError(value, err)
	}

	stack := make(containerStack, len(c.stack))
	copy(stack, c.stack)

	stack = append(stack, containerNode{value: value, custom: true, index: muErr.Index, entry: muErr.entry})

	return &Error{
		Index:    c.index,
		Op:       c.mode,
		entry:    c.caller,
		stack:    append(stack, muErr.stack...),
		leafType: muErr.leafType,
		err:      muErr.err}
}

func (c *context) newError(value reflect.Value, err error) error {
	if err == io.EOF {
		// All io.EOF is unexpected
		err = io.ErrUnexpectedEOF
	}

	stack := make(containerStack, len(c.stack))
	copy(stack, c.stack)

	return &Error{
		Index:    c.index,
		Op:       c.mode,
		entry:    c.caller,
		stack:    stack,
		leafType: value.Type(),
		err:      err}
}

func (c *context) wrapFatal(err interface{}) *fatalError {
	f, ok := err.(*fatalError)
	if !ok {
		return &fatalError{
			index: c.index,
			entry: c.caller,
			stack: c.stack,
			err:   err}
	}

	stack := make(containerStack, len(c.stack))
	copy(stack, c.stack)
	stack.top().index = f.index
	stack.top().entry = f.entry

	return &fatalError{
		index: c.index,
		entry: c.caller,
		stack: append(stack, f.stack...),
		err:   f.err}
}

type marshaller struct {
	*context
	w      io.Writer
	nbytes int
}

func newMarshaller(caller [1]uintptr, w io.Writer) *marshaller {
	var parent *context
	if m, ok := w.(*marshaller); ok {
		parent = m.context
	}
	return &marshaller{
		context: &context{
			caller: caller,
			mode:   "marshal",
			parent: parent},
		w: w}
}

func (m *marshaller) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.nbytes += n
	return
}

func (m *marshaller) marshalSized(v reflect.Value, opts *options) error {
	if v.IsNil() {
		if err := binary.Write(m, binary.BigEndian, uint16(0)); err != nil {
			return m.newError(v, err)
		}
		return nil
	}

	if opts == nil {
		opts = new(options)
	}
	exit := opts.enterSizedType(v)
	defer exit()

	tmpBuf := new(bytes.Buffer)
	sm := &marshaller{context: m.context, w: tmpBuf}
	if err := sm.marshalValue(v, opts); err != nil {
		return err
	}
	if tmpBuf.Len() > math.MaxUint16 {
		return m.newError(v, fmt.Errorf("sized value size of %d is larger than 2^16-1", tmpBuf.Len()))
	}
	if err := binary.Write(m, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return m.newError(v, err)
	}
	if _, err := tmpBuf.WriteTo(m); err != nil {
		return m.newError(v, err)
	}
	return nil
}

func (m *marshaller) marshalSized1Bytes(v reflect.Value) error {
	if v.Len() > math.MaxUint8 {
		return m.newError(v, fmt.Errorf("value size of %d is larger than 2^8-1", v.Len()))
	}
	if err := binary.Write(m, binary.BigEndian, uint8(v.Len())); err != nil {
		return m.newError(v, err)
	}
	return m.marshalRaw(v)
}

func (m *marshaller) marshalFixedBytes(v reflect.Value) error {
	if err := binary.Write(m, binary.BigEndian, v.Interface()); err != nil {
		return m.newError(v, err)
	}
	return nil
}

func (m *marshaller) marshalRawList(v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		exit := m.enterListElem(v, i)
		if err := m.marshalValue(v.Index(i), nil); err != nil {
			exit()
			return err
		}
		exit()
	}
	return nil
}

func (m *marshaller) marshalRaw(v reflect.Value) error {
	switch v.Type().Elem().Kind() {
	case reflect.Uint8:
		if _, err := m.Write(v.Bytes()); err != nil {
			return m.newError(v, err)
		}
		return nil
	default:
		return m.marshalRawList(v)
	}
}

func (m *marshaller) marshalPtr(v reflect.Value, opts *options) error {
	p := v
	if v.IsNil() {
		p = reflect.New(v.Type().Elem())
	}
	return m.marshalValue(p.Elem(), opts)
}

func (m *marshaller) marshalPrimitive(v reflect.Value) error {
	if err := binary.Write(m, binary.BigEndian, v.Interface()); err != nil {
		return m.newError(v, err)
	}
	return nil
}

func (m *marshaller) marshalList(v reflect.Value) error {
	if v.Len() > maxListLength {
		return m.newError(v, fmt.Errorf("slice length of %d is out of range", v.Len()))
	}

	// Marshal length field
	if err := binary.Write(m, binary.BigEndian, uint32(v.Len())); err != nil {
		return m.newError(v, err)
	}

	return m.marshalRawList(v)
}

func (m *marshaller) marshalStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		exit := m.enterStructField(v, i)
		if err := m.marshalValue(v.Field(i), parseStructFieldMuOptions(v.Type().Field(i))); err != nil {
			exit()
			return err
		}
		exit()
	}

	return nil
}

func (m *marshaller) marshalUnion(v reflect.Value, opts *options) error {
	// Ignore during marshalling - let the TPM unmarshalling catch it
	elem, exit, _ := m.enterUnionElem(v, opts)
	if !elem.IsValid() {
		return nil
	}
	err := m.marshalValue(elem, nil)
	exit()
	return err
}

func (m *marshaller) marshalCustom(v reflect.Value) error {
	if !v.Type().Implements(customMarshallerType) {
		// support Marshal() implementations that take a pointer receiver.
		if !v.CanAddr() {
			panic(fmt.Sprintf("custom type %s needs to be addressable", v.Type()))
		}
		v = v.Addr()
	}

	exit := m.enterCustomType(v)

	if err := v.Interface().(customMarshallerIface).Marshal(m); err != nil {
		exit()
		return m.wrapOrNewError(v, err)
	}

	exit()
	return nil
}

func (m *marshaller) marshalValue(v reflect.Value, opts *options) error {
	kind, err := tpmKind(v.Type(), opts)

	switch {
	case err != nil:
		panic(fmt.Sprintf("cannot marshal unsupported type %s (%v)", v.Type(), err))
	case kind == TPMKindUnsupported:
		return m.marshalPtr(v, opts)
	case kind == tpmKindIgnore:
		return nil
	}

	switch kind {
	case TPMKindPrimitive:
		return m.marshalPrimitive(v)
	case TPMKindSized:
		return m.marshalSized(v, opts)
	case TPMKindList:
		return m.marshalList(v)
	case TPMKindStruct, TPMKindTaggedUnion:
		return m.marshalStruct(v)
	case TPMKindUnion:
		return m.marshalUnion(v, opts)
	case TPMKindCustom:
		return m.marshalCustom(v)
	case TPMKindRaw:
		return m.marshalRaw(v)
	case TPMKindSized1Bytes:
		return m.marshalSized1Bytes(v)
	case TPMKindFixedBytes:
		return m.marshalFixedBytes(v)
	}

	panic("unhandled kind")
}

func (m *marshaller) marshal(vals ...interface{}) (int, error) {
	defer func() {
		if err := recover(); err != nil {
			panic(m.wrapFatal(err))
		}
	}()

	for i, v := range vals {
		m.index = i

		var opts *options
		switch w := v.(type) {
		case *wrappedValue:
			v = w.value
			opts = w.opts
		default:
		}

		if err := m.marshalValue(reflect.ValueOf(v), opts); err != nil {
			return m.nbytes, err
		}
	}
	return m.nbytes, nil
}

type unmarshaller struct {
	*context
	r      io.Reader
	nbytes int
}

func newUnmarshaller(caller [1]uintptr, r io.Reader) *unmarshaller {
	var parent *context
	if u, ok := r.(*unmarshaller); ok {
		parent = u.context
	}
	return &unmarshaller{
		context: &context{
			caller: caller,
			mode:   "unmarshal",
			parent: parent},
		r: r}
}

func (u *unmarshaller) Read(p []byte) (n int, err error) {
	n, err = u.r.Read(p)
	u.nbytes += n
	return
}

func (u *unmarshaller) unmarshalSized(v reflect.Value, opts *options) error {
	var size uint16
	if err := binary.Read(u, binary.BigEndian, &size); err != nil {
		return u.newError(v, err)
	}

	// v is either:
	// - a pointer kind, in which case it is a pointer to a struct. This
	//   is the sized structure case.
	// - a slice kind, in which case the slice is always a byte slice. This
	//   is the sized buffer case.
	switch {
	case size == 0:
		// zero sized structure. Clear the pointer if it was pre-set and
		// then return early.
		v.Set(reflect.Zero(v.Type()))
		return nil
	case v.Kind() == reflect.Slice && (v.IsNil() || v.Cap() < int(size)):
		// sized buffer with no pre-allocated buffer or a pre-allocated
		// buffer that isn't large enough. Allocate a new one.
		v.Set(reflect.MakeSlice(v.Type(), int(size), int(size)))
	case v.Kind() == reflect.Slice:
		// sized buffer with pre-allocated buffer that is large enough.
		v.SetLen(int(size))
	}

	if opts == nil {
		opts = new(options)
	}
	exit := opts.enterSizedType(v)
	defer exit()

	su := &unmarshaller{context: u.context, r: io.LimitReader(u, int64(size))}
	return su.unmarshalValue(v, opts)
}

func (u *unmarshaller) unmarshalSized1Bytes(v reflect.Value) error {
	var size uint8
	if err := binary.Read(u, binary.BigEndian, &size); err != nil {
		return u.newError(v, err)
	}

	switch {
	case size == 0:
		// zero sized. Set the slice to nil if it was pre-set.
		v.Set(reflect.Zero(v.Type()))
		return nil
	case v.IsNil() || v.Cap() < int(size):
		// No pre-allocated slice or one that isn't big enough.
		// Allocate a new one.
		v.Set(reflect.MakeSlice(v.Type(), int(size), int(size)))
	default:
		// Reuse the pre-allocated slice.
		v.SetLen(int(size))
	}

	return u.unmarshalRaw(v)
}

func (u *unmarshaller) unmarshalFixedBytes(v reflect.Value) error {
	if err := binary.Read(u, binary.BigEndian, v.Addr().Interface()); err != nil {
		return u.newError(v, err)
	}
	return nil
}

func (u *unmarshaller) unmarshalRawList(v reflect.Value, n int) (reflect.Value, error) {
	for i := 0; i < n; i++ {
		v = reflect.Append(v, reflect.Zero(v.Type().Elem()))
		exit := u.enterListElem(v, i)
		if err := u.unmarshalValue(v.Index(i), nil); err != nil {
			exit()
			return reflect.Value{}, err
		}
		exit()
	}
	return v, nil
}

func (u *unmarshaller) unmarshalRaw(v reflect.Value) error {
	switch v.Type().Elem().Kind() {
	case reflect.Uint8:
		if _, err := io.ReadFull(u, v.Bytes()); err != nil {
			return u.newError(v, err)
		}
		return nil
	default:
		_, err := u.unmarshalRawList(v.Slice(0, 0), v.Len())
		return err
	}
}

func (u *unmarshaller) unmarshalPtr(v reflect.Value, opts *options) error {
	if v.IsNil() {
		v.Set(reflect.New(v.Type().Elem()))
	}
	return u.unmarshalValue(v.Elem(), opts)
}

func (u *unmarshaller) unmarshalPrimitive(v reflect.Value) error {
	if err := binary.Read(u, binary.BigEndian, v.Addr().Interface()); err != nil {
		return u.newError(v, err)
	}
	return nil
}

func (u *unmarshaller) unmarshalList(v reflect.Value) error {
	// Unmarshal the length
	var length uint32
	if err := binary.Read(u, binary.BigEndian, &length); err != nil {
		return u.newError(v, err)
	}

	switch {
	case length > maxListLength:
		return u.newError(v, fmt.Errorf("list length of %d is out of range", length))
	case v.IsNil() && length > 0:
		// Try to reuse the existing slice, although it may be
		// reallocated later if the capacity isn't large enough
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
	case length == 0:
		// Clear any existing slice
		v.Set(reflect.Zero(v.Type()))
	}

	s, err := u.unmarshalRawList(v.Slice(0, 0), int(length))
	if err != nil {
		return err
	}
	v.Set(s)
	return nil
}

func (u *unmarshaller) unmarshalStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		exit := u.enterStructField(v, i)
		if err := u.unmarshalValue(v.Field(i), parseStructFieldMuOptions(v.Type().Field(i))); err != nil {
			exit()
			return err
		}
		exit()
	}
	return nil
}

func (u *unmarshaller) unmarshalUnion(v reflect.Value, opts *options) error {
	elem, exit, err := u.enterUnionElem(v, opts)
	if err != nil {
		return u.newError(v, err)
	}
	if !elem.IsValid() {
		return nil
	}
	err = u.unmarshalValue(elem, nil)
	exit()
	return err
}

func (u *unmarshaller) unmarshalCustom(v reflect.Value) error {
	if !v.CanAddr() {
		panic(fmt.Sprintf("custom type %s needs to be addressable", v.Type()))
	}

	exit := u.enterCustomType(v)

	if err := v.Addr().Interface().(customUnmarshallerIface).Unmarshal(u); err != nil {
		exit()
		return u.wrapOrNewError(v, err)
	}

	exit()
	return nil
}

func (u *unmarshaller) unmarshalValue(v reflect.Value, opts *options) error {
	kind, err := tpmKind(v.Type(), opts)

	switch {
	case err != nil:
		panic(fmt.Sprintf("cannot unmarshal unsupported type %s (%v)", v.Type(), err))
	case kind == TPMKindUnsupported:
		return u.unmarshalPtr(v, opts)
	case kind == tpmKindIgnore:
		return nil
	}

	switch kind {
	case TPMKindPrimitive:
		return u.unmarshalPrimitive(v)
	case TPMKindSized:
		return u.unmarshalSized(v, opts)
	case TPMKindList:
		return u.unmarshalList(v)
	case TPMKindStruct, TPMKindTaggedUnion:
		return u.unmarshalStruct(v)
	case TPMKindUnion:
		return u.unmarshalUnion(v, opts)
	case TPMKindCustom:
		return u.unmarshalCustom(v)
	case TPMKindRaw:
		return u.unmarshalRaw(v)
	case TPMKindSized1Bytes:
		return u.unmarshalSized1Bytes(v)
	case TPMKindFixedBytes:
		return u.unmarshalFixedBytes(v)
	}

	panic("unhandled kind")
}

func (u *unmarshaller) unmarshal(vals ...interface{}) (int, error) {
	defer func() {
		if err := recover(); err != nil {
			panic(u.wrapFatal(err))
		}
	}()

	for i, v := range vals {
		u.index = i

		var opts *options
		switch w := v.(type) {
		case *wrappedValue:
			v = w.value
			opts = w.opts
		default:
		}

		val := reflect.ValueOf(v)
		if val.Kind() != reflect.Ptr {
			panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", reflect.TypeOf(v)))
		}

		if val.IsNil() {
			panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", val.Type()))
		}

		if err := u.unmarshalValue(val.Elem(), opts); err != nil {
			return u.nbytes, err
		}
	}
	return u.nbytes, nil
}

func marshalToWriter(skip int, w io.Writer, vals ...interface{}) (int, error) {
	var caller [1]uintptr
	runtime.Callers(skip+1, caller[:])

	m := newMarshaller(caller, w)
	return m.marshal(vals...)
}

// MarshalToWriter marshals vals to w in the TPM wire format, according
// to the rules specified in the package description.
//
// Pointers are automatically dereferenced. Nil pointers are marshalled to
// the zero value for the pointed to type, unless the pointer is to a
// sized structure (a struct field with the 'tpm2:"sized"` tag), in which
// case a value of zero size is marshalled.
//
// The number of bytes written to w are returned. If this function does
// not complete successfully, it will return an error and the number of
// bytes written.
//
// This function only returns an error if a sized value (sized buffer,
// sized structure or list) is too large for its corresponding size field,
// or if the supplied io.Writer returns an error.
func MarshalToWriter(w io.Writer, vals ...interface{}) (int, error) {
	return marshalToWriter(2, w, vals...)
}

// MustMarshalToWriter is the same as [MarshalToWriter], except that it panics if it encounters an error.
func MustMarshalToWriter(w io.Writer, vals ...interface{}) int {
	n, err := marshalToWriter(2, w, vals...)
	if err != nil {
		panic(err)
	}
	return n
}

func marshalToBytes(skip int, vals ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := marshalToWriter(skip+1, buf, vals...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalToBytes marshals vals to TPM wire format, according to the rules
// specified in the package description.
//
// Pointers are automatically dereferenced. Nil pointers are marshalled to
// the zero value for the pointed to type, unless the pointer is to a
// sized structure (a struct field with the 'tpm2:"sized"` tag), in which
// case a value of zero size is marshalled.
//
// The number of bytes written to w are returned. If this function does
// not complete successfully, it will return an error and the number of
// bytes written.
//
// This function only returns an error if a sized value (sized buffer,
// sized structure or list) is too large for its corresponding size field.
func MarshalToBytes(vals ...interface{}) ([]byte, error) {
	return marshalToBytes(2, vals...)
}

// MustMarshalToBytes is the same as [MarshalToBytes], except that it panics if it encounters an error.
func MustMarshalToBytes(vals ...interface{}) []byte {
	b, err := marshalToBytes(2, vals...)
	if err != nil {
		panic(err)
	}
	return b
}

func unmarshalFromReader(skip int, r io.Reader, vals ...interface{}) (n int, err error) {
	var caller [1]uintptr
	runtime.Callers(skip+1, caller[:])

	u := newUnmarshaller(caller, r)
	return u.unmarshal(vals...)
}

// UnmarshalFromReader unmarshals data in the TPM wire format from r to
// vals, according to the rules specified in the package description. The
// values supplied to this function must be pointers to the destination
// values.
//
// Pointers are automatically dererefenced. If a pointer is nil, then
// memory is allocated for the value and the pointer is initialized
// accordingly, unless the pointer is to a sized structure (a struct field
// with the 'tpm2:"sized"' tag) and the value being unmarshalled has a
// zero size, in which case the pointer is cleared. If a pointer is
// already initialized by the caller, then this function will unmarshal
// to the already allocated memory.
//
// Slices are allocated automatically, unless the caller has already
// allocated a slice in which case it will be used if it has a large
// enough capacity. Zero length slices are unmarshalled as nil.
//
// This can unmarshal raw slices (those without a corresponding size or
// length fields, represented by the [RawBytes] type or a slice value
// referenced from a struct field with the 'tpm2:"raw"' tag), but the
// caller must pre-allocate a slice of the correct size first. This
// function cannot allocate a slice because it doesn't have a way to
// determine the size to allocate.
//
// The number of bytes read from r are returned. If this function does
// not complete successfully, it will return an error and the number of
// bytes read. In this case, partial results may have been unmarshalled
// to the supplied destination values.
func UnmarshalFromReader(r io.Reader, vals ...interface{}) (int, error) {
	return unmarshalFromReader(2, r, vals...)
}

// UnmarshalFromReader unmarshals data in the TPM wire format from b to
// vals, according to the rules specified in the package description.
// The values supplied to this function must be pointers to the
// destination values.
//
// Pointers are automatically dererefenced. If a pointer is nil, then
// memory is allocated for the value and the pointer is initialized
// accordingly, unless the pointer is to a sized structure (a struct field
// with the 'tpm2:"sized"' tag) and the value being unmarshalled has a
// zero size, in which case the pointer is cleared. If a pointer is
// already initialized by the caller, then this function will unmarshal
// to the already allocated memory.
//
// Slices are allocated automatically, unless the caller has already
// allocated a slice in which case it will be used if it has a large
// enough capacity. Zero length slices are unmarshalled as nil.
//
// This can unmarshal raw slices (those without a corresponding size or
// length fields, represented by the [RawBytes] type or a slice value
// referenced from a struct field with the 'tpm2:"raw"' tag), but the
// caller must pre-allocate a slice of the correct size first. This
// function cannot allocate a slice because it doesn't have a way to
// determine the size to allocate.
//
// The number of bytes consumed from b are returned. If this function
// does not complete successfully, it will return an error and the number
// of bytes consumed. In this case, partial results may have been
// unmarshalled to the supplied destination values.
func UnmarshalFromBytes(b []byte, vals ...interface{}) (int, error) {
	buf := bytes.NewReader(b)
	return unmarshalFromReader(2, buf, vals...)
}

func copyValue(skip int, dst, src interface{}) error {
	var wrappedSrc *wrappedValue
	switch s := src.(type) {
	case *wrappedValue:
		wrappedSrc = s
	default:
		wrappedSrc = &wrappedValue{value: s}
	}

	switch d := dst.(type) {
	case *wrappedValue:
		_ = d
		panic("can only pass options to the source")
	}

	dstV := reflect.ValueOf(dst)
	if dstV.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", reflect.TypeOf(dst)))
	}
	if dstV.IsNil() {
		panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", dstV.Type()))
	}

	dstLocal := dst

	isInterface := false
	if dstV.Elem().Kind() == reflect.Interface {
		if !reflect.TypeOf(wrappedSrc.value).Implements(dstV.Elem().Type()) {
			panic(fmt.Sprintf("type %s does not implement destination interface %s", reflect.TypeOf(src), dstV.Elem().Type()))
		}
		dstLocal = reflect.New(reflect.TypeOf(wrappedSrc.value)).Interface()
		isInterface = true
	}

	wrappedDst := &wrappedValue{value: dstLocal, opts: wrappedSrc.opts}

	buf := new(bytes.Buffer)
	if _, err := marshalToWriter(skip+1, buf, wrappedSrc); err != nil {
		return err
	}
	if _, err := unmarshalFromReader(skip+1, buf, wrappedDst); err != nil {
		return err
	}

	if isInterface {
		dstV.Elem().Set(reflect.ValueOf(dstLocal).Elem())
	}

	return nil
}

// CopyValue copies the value of src to dst. The destination must be a
// pointer to the actual destination value. This works by serializing the
// source value in the TPM wire format and the deserializing it again into
// the destination.
//
// This will return an error for any reason that would cause [MarshalToBytes] or
// [UnmarshalFromBytes] to return an error.
func CopyValue(dst, src interface{}) error {
	return copyValue(2, dst, src)
}

// MustCopyValue is the same as [CopyValue] except that it panics if it encounters an error.
func MustCopyValue(dst, src interface{}) {
	if err := copyValue(2, dst, src); err != nil {
		panic(err)
	}
}

// IsValid determines whether the supplied value is representable by
// the TPM wire format. It returns false if the type would cause a panic
// during marshalling or unmarshalling.
func IsValid(v interface{}) (valid bool) {
	defer func() {
		if err := recover(); err != nil {
			valid = false
		}
	}()

	var d interface{}
	if err := CopyValue(&d, v); err != nil {
		return false
	}

	return true
}

// DeepEqual determines whether the supplied values are deeply equal.
// Values are deeply equal if they have the same type and have the same
// representation when serialized. This will return false if either value
// cannot be represented by the TPM wire format.
func DeepEqual(x, y interface{}) (equal bool) {
	if reflect.TypeOf(x) != reflect.TypeOf(y) {
		return false
	}

	defer func() {
		if err := recover(); err != nil {
			equal = false
		}
	}()

	x2 := MustMarshalToBytes(x)
	y2 := MustMarshalToBytes(y)
	return bytes.Equal(x2, y2)
}
