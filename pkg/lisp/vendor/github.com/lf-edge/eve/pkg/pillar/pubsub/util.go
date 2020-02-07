// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
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
func parseTemplate(sb []byte, targetType reflect.Type) (interface{}, error) {
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

func lookupSlave(slaveCollection LocalCollection, key string) []byte {
	for slaveKey := range slaveCollection {
		if slaveKey == key {
			res := slaveCollection[slaveKey]
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
