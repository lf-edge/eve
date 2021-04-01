// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	maxLargeLen = 1024 * 1024
)

// removeLarge checks that the pubsub:"large" tags are only on supported
// types and clears those.
func removeLarge(log *base.LogObject, item interface{}) error {
	return writeLargeImpl(log, item, "")
}

// writeAndRemoveLarge checks that the pubsub:"large" tags are only on supported
// types, writes those to dirname.fieldname and clears them.
func writeAndRemoveLarge(log *base.LogObject, item interface{}, dirname string) error {
	return writeLargeImpl(log, item, dirname)
}

// writeLargeImpl walks the struct and, if dirname is set, writes to a file
// the top-level fields which have a pubsub:"large" tag,
// then it sets those fields to zero length.
// Currently only supports string and byte slices
func writeLargeImpl(log *base.LogObject, item interface{}, dirname string) error {
	if false {
		val := reflect.ValueOf(item) // could be any underlying type

		// if its a pointer, resolve its value
		if val.Kind() == reflect.Ptr {
			val = reflect.Indirect(val)
		}

		// should double check we now have a struct (could still be anything)
		if val.Kind() != reflect.Struct {
			panic("unexpected type " + val.Kind().String())
		}
		// XXX    s := val
	}
	s := reflect.ValueOf(item).Elem() // could be any underlying type
	// XXX typeOfT := s.Type()
	typeOfT := reflect.TypeOf(item).Elem()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		v, ok := typeOfT.Field(i).Tag.Lookup("pubsub")
		ignored := (ok && v == "large")
		log.Tracef("%d: %s %s (ignored %t) = %v\n", i,
			typeOfT.Field(i).Name, f.Type(), ignored, f.Interface())
		if !ignored {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			if len(f.String()) >= maxLargeLen {
				err := fmt.Errorf("pubsub:large too large string %d bytes for %s",
					len(f.String()), typeOfT.Field(i).Name)
				return err
			}

		case reflect.Slice:
			if f.Type().Elem().Kind() != reflect.Uint8 {
				err := fmt.Errorf("pubsub:large slice of different than uint8: %s for %s",
					f.Type().Elem().Kind().String(),
					typeOfT.Field(i).Name)
				return err
			}
			if len(f.Bytes()) > maxLargeLen {
				err := fmt.Errorf("pubsub:large too large byte slice %d bytes for %s",
					len(f.Bytes()), typeOfT.Field(i).Name)
				return err
			}
		default:
			err := fmt.Errorf("pubsub:large on unsupported type %s for %s",
				f.Type().String(), typeOfT.Field(i).Name)
			return err
		}
		b, err := json.Marshal(f.Interface())
		if err != nil {
			err := fmt.Errorf("pubsub:large Marshal failed for %s: %v",
				typeOfT.Field(i).Name, err)
			return err
		}
		if dirname != "" {
			err = ensureDir(dirname)
			if err != nil {
				err := fmt.Errorf("pubsub:large ensureDir filed for %s: %v",
					dirname, err)
				return err
			}
			filename := fmt.Sprintf("%s/%s",
				dirname, typeOfT.Field(i).Name)
			err = ioutil.WriteFile(filename, b, 0644)
			if err != nil {
				err := fmt.Errorf("pubsub:large write filed for %s: %v",
					filename, err)
				return err
			}
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString("")
		case reflect.Slice:
			f.SetBytes(nil)
		}
	}
	return nil
}

func ensureDir(dirname string) error {
	_, err := os.Stat(dirname)
	if err != nil {
		err := os.MkdirAll(dirname, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}
