// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// deepCopy returns the same type as what is passed as input
func deepCopy(in interface{}) interface{} {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal("json Marshal in deepCopy", err)
	}
	p := reflect.New(reflect.TypeOf(in))
	output := p.Interface()
	if err := json.Unmarshal(b, output); err != nil {
		log.Fatal("json Unmarshal in deepCopy", err)
	}
	val := reflect.ValueOf(output)
	if val.Kind() != reflect.Ptr {
		log.Fatalf("Not a pointer: %s", val.Kind())
	}
	val = val.Elem()
	return val.Interface()
}

// template is a struct; returns a value of the same struct type
func parseTemplate(sb []byte, template interface{}) (interface{}, error) {
	p := reflect.New(reflect.TypeOf(template))
	output := p.Interface()
	if err := json.Unmarshal(sb, output); err != nil {
		return nil, err
	}
	val := reflect.ValueOf(output)
	if val.Kind() != reflect.Ptr {
		log.Fatalf("Not a pointer: %s", val.Kind())
	}
	val = val.Elem()
	return val.Interface(), nil
}

func lookupSlave(slaveCollection localCollection, key string) *interface{} {
	for slaveKey := range slaveCollection {
		if slaveKey == key {
			res := slaveCollection[slaveKey]
			return &res
		}
	}
	return nil
}

// TypeToName given a particular object, get the desired name for it
func TypeToName(something interface{}) string {
	t := reflect.TypeOf(something)
	out := strings.Split(t.String(), ".")
	return out[len(out)-1]
}

// WriteRename write data to a fmpfile and then rename it to a desired name
func WriteRename(fileName string, b []byte) error {
	dirName := filepath.Dir(fileName)
	// Do atomic rename to avoid partially written files
	tmpfile, err := ioutil.TempFile(dirName, "pubsub")
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(b)
	if err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	if err := tmpfile.Close(); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	if err := os.Rename(tmpfile.Name(), fileName); err != nil {
		errStr := fmt.Sprintf("WriteRename(%s): %s",
			fileName, err)
		return errors.New(errStr)
	}
	return nil
}
