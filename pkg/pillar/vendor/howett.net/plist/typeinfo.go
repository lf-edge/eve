package plist

import (
	"reflect"
	"strings"
	"sync"
)

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

// typeInfo holds details for the plist representation of a type.
type typeInfo struct {
	fields []fieldInfo
}

// fieldInfo holds details for the plist representation of a single field.
type fieldInfo struct {
	idx  []int
	name string

	// omitEmptyDepthMap stores, for each entry in idx, whether at that level the user had specified
	// omitempty. This matters for anonymous embedded structs, where the index path to a given field
	// may traverse different struct types
	//
	// For example, given struct S{ *I } and struct I{ V int }, the path to V is [0,0].
	// If S.I were marked `omitempty`, we would need to record that omitempty was seen at the first index entry.
	//    *I,         int
	// [   0,           0 ]
	// [omit, do not omit ]
	//
	// As an optimization, we store it as a bit field. This means anonymous embedded structs more than 64 entries
	// may forget their omitempty states.
	omitEmptyDepthMap uint64
}

var tinfoMap = make(map[reflect.Type]*typeInfo)
var tinfoLock sync.RWMutex

// getTypeInfo returns the typeInfo structure with details necessary
// for marshalling and unmarshalling typ.
func getTypeInfo(typ reflect.Type) (*typeInfo, error) {
	tinfoLock.RLock()
	tinfo, ok := tinfoMap[typ]
	tinfoLock.RUnlock()
	if ok {
		return tinfo, nil
	}
	tinfo = &typeInfo{}
	if typ.Kind() == reflect.Struct {
		n := typ.NumField()
		for i := 0; i < n; i++ {
			f := typ.Field(i)
			if f.PkgPath != "" || f.Tag.Get("plist") == "-" {
				continue // Private field
			}

			finfo, err := structFieldInfo(typ, &f)
			if err != nil {
				return nil, err
			}

			// For embedded structs, embed its fields.
			if f.Anonymous {
				t := f.Type
				if t.Kind() == reflect.Ptr {
					t = t.Elem()
				}
				if t.Kind() == reflect.Struct {
					inner, err := getTypeInfo(t)
					if err != nil {
						return nil, err
					}
					for _, innerFinfo := range inner.fields {
						innerFinfo.idx = append(finfo.idx, innerFinfo.idx...)
						innerFinfo.omitEmptyDepthMap = finfo.omitEmptyDepthMap | (innerFinfo.omitEmptyDepthMap << uint(len(finfo.idx)))
						if err := addFieldInfo(typ, tinfo, &innerFinfo); err != nil {
							return nil, err
						}
					}
					continue
				}
			}

			// Add the field if it doesn't conflict with other fields.
			if err := addFieldInfo(typ, tinfo, finfo); err != nil {
				return nil, err
			}
		}
	}
	tinfoLock.Lock()
	tinfoMap[typ] = tinfo
	tinfoLock.Unlock()
	return tinfo, nil
}

// structFieldInfo builds and returns a fieldInfo for f.
func structFieldInfo(typ reflect.Type, f *reflect.StructField) (*fieldInfo, error) {
	finfo := &fieldInfo{idx: f.Index}

	// Split the tag from the xml namespace if necessary.
	tag := f.Tag.Get("plist")

	// Parse flags.
	tokens := strings.Split(tag, ",")
	tag = tokens[0]
	if len(tokens) > 1 {
		tag = tokens[0]
		for _, flag := range tokens[1:] {
			switch flag {
			case "omitempty":
				finfo.omitEmptyDepthMap = 1 << uint(len(f.Index)-1)
			}
		}
	}

	if tag == "" {
		// If the name part of the tag is completely empty,
		// use the field name
		finfo.name = f.Name
		return finfo, nil
	}

	finfo.name = tag
	return finfo, nil
}

// addFieldInfo adds finfo to tinfo.fields if there are no
// conflicts, or if conflicts arise from previous fields that were
// obtained from deeper embedded structures than finfo. In the latter
// case, the conflicting entries are dropped.
// A conflict occurs when the path (parent + name) to a field is
// itself a prefix of another path, or when two paths match exactly.
// It is okay for field paths to share a common, shorter prefix.
func addFieldInfo(typ reflect.Type, tinfo *typeInfo, newf *fieldInfo) error {
	var conflicts []int
	// First, figure all conflicts. Most working code will have none.
	for i := range tinfo.fields {
		oldf := &tinfo.fields[i]
		if newf.name == oldf.name {
			conflicts = append(conflicts, i)
		}
	}

	// Without conflicts, add the new field and return.
	if conflicts == nil {
		tinfo.fields = append(tinfo.fields, *newf)
		return nil
	}

	// If any conflict is shallower, ignore the new field.
	// This matches the Go field resolution on embedding.
	for _, i := range conflicts {
		if len(tinfo.fields[i].idx) < len(newf.idx) {
			return nil
		}
	}

	// Otherwise, the new field is shallower, and thus takes precedence,
	// so drop the conflicting fields from tinfo and append the new one.
	for c := len(conflicts) - 1; c >= 0; c-- {
		i := conflicts[c]
		copy(tinfo.fields[i:], tinfo.fields[i+1:])
		tinfo.fields = tinfo.fields[:len(tinfo.fields)-1]
	}
	tinfo.fields = append(tinfo.fields, *newf)
	return nil
}

// valueForWriting returns v's field value corresponding to finfo.
// It's equivalent to v.FieldByIndex(finfo.idx), but initializes
// and dereferences pointers as necessary.
func (finfo *fieldInfo) valueForWriting(v reflect.Value) reflect.Value {
	for i, x := range finfo.idx {
		if i > 0 {
			t := v.Type()
			if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct {
				if v.IsNil() {
					v.Set(reflect.New(v.Type().Elem()))
				}
				v = v.Elem()
			}
		}
		v = v.Field(x)
	}
	return v
}

// valueForWriting returns v's field value corresponding to finfo.
// It's equivalent to v.FieldByIndex(finfo.idx), but bails out if one of the
// indices indicated that it should be omitted if it's empty and it is empty.
func (finfo *fieldInfo) value(v reflect.Value) reflect.Value {
	for i, x := range finfo.idx {
		t := v.Type()
		if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct {
			v = v.Elem()
		}

		v = v.Field(x)

		if (finfo.omitEmptyDepthMap&(1<<uint(i))) != 0 && isEmptyValue(v) {
			return reflect.Value{}
		}
	}
	return v
}
