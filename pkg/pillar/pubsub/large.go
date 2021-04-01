// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/lf-edge/eve/pkg/pillar/base"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
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
	s := reflect.ValueOf(item).Elem()
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
		length := 0
		switch f.Kind() {
		case reflect.String:
			length = len(f.String())
			if length >= maxLargeLen {
				err := fmt.Errorf("pubsub:large too large string %d bytes for %s",
					length, typeOfT.Field(i).Name)
				return err
			}

		case reflect.Slice:
			if f.Type().Elem().Kind() != reflect.Uint8 {
				err := fmt.Errorf("pubsub:large slice of different than uint8: %s for %s",
					f.Type().Elem().Kind().String(),
					typeOfT.Field(i).Name)
				return err
			}
			length = len(f.Bytes())
			if length > maxLargeLen {
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
			// Need zero length check to avoid writing "null" etc
			if length == 0 {
				err = ioutil.WriteFile(filename, nil, 0644)
			} else {
				err = ioutil.WriteFile(filename, b, 0644)
			}
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

// readLarge walks the struct and uses readfile to fill those which have
// pubsub:"large" tag
// Note that file can be missing if the publisher has e.g., unpublished
func readLarge(log *base.LogObject, item interface{}, dirname string) error {
	s := reflect.ValueOf(item).Elem()
	typeOfT := reflect.TypeOf(item).Elem()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		v, ok := typeOfT.Field(i).Tag.Lookup("pubsub")
		ignored := (ok && v == "large")
		log.Tracef("%d: %s %s (ignored %t)",
			i, typeOfT.Field(i).Name, f.Type(), ignored)
		if !ignored {
			continue
		}
		filename := fmt.Sprintf("%s/%s",
			dirname, typeOfT.Field(i).Name)
		out, _, err := fileutils.StatAndRead(log, filename, maxLargeLen+1)
		if err != nil {
			if !os.IsNotExist(err) && err != io.EOF {
				return err
			}
		}
		if len(out) == 0 {
			continue
		}
		b := []byte(out)
		switch f.Kind() {
		case reflect.String:
			var str string
			err = json.Unmarshal(b, &str)
			if err != nil {
				panic(err)
			}
			f.SetString(str)
		case reflect.Slice:
			// Must Unmarshal into []byte to get base64 decode
			var bytes []byte
			err = json.Unmarshal(b, &bytes)
			if err != nil {
				panic(err)
			}
			f.SetBytes(bytes)
		}
	}
	return nil
}
