// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// deepCopy returns the same type as what is passed as input
func deepCopy(log *base.LogObject, in interface{}) interface{} {
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
func parseTemplate(log *base.LogObject, sb []byte, targetType reflect.Type) (interface{}, error) {
	p := reflect.New(targetType)
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

func lookupLocal(localCollection LocalCollection, key string) []byte {
	for localKey := range localCollection {
		if localKey == key {
			res := localCollection[localKey]
			return res
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
