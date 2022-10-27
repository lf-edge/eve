// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"syscall"

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

// ConnReadCheck waits till conn's fd is readable
func ConnReadCheck(conn net.Conn) error {
	var sysErr error

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("Not syscall.Conn")
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("Exception while getting rawConn: %s",
			err)
	}

	err = rawConn.Read(func(fd uintptr) bool {
		_, _, err := syscall.Recvfrom(int(fd), []byte{}, syscall.MSG_PEEK)
		if err != nil {
			if err == syscall.EAGAIN {
				return false
			}
			//assign unknown error to syserr which will be handled later.
			sysErr = fmt.Errorf("Unknown error from syscall.Recvfrom: %s",
				err)
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("Exception from rawConn.Read: %s",
			err)
	}
	return sysErr
}
