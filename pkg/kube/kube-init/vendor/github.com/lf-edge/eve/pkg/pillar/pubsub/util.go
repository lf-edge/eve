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

// DeepCopy returns the same type as what is passed as input
// Warning: only public fields will be exported
// Note why json marshalling is used:
// Type casting and associated type assertions in golang are only
// useful for atoms in the type system. Hence you can't do a type
// assertion and cast of a struct of internal fields. This coupled
// with pubsub needing to save a copy lead to doing deep copies.
// Golang doesn't have support for a deep copy. Once can build it
// oneself using reflect package, but it ends up doing the same thing
// as json encode+decode apart from the exported fields check.
func DeepCopy(log *base.LogObject, in interface{}) interface{} {
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

// ChannelWatch describe a channel to watch and the callback to call
type ChannelWatch struct {
	// Chan is the channel to watch for incoming data
	Chan reflect.Value
	// Callback is the function to call with that data (or empty if no data).
	// Return true to terminate MultiChannelWatch.
	Callback func(value interface{}) (exitWatch bool)
}

// MultiChannelWatch allows listening to several receiving channels of different types at the same time
// this way the pubsub subscriptions can be managed in an array and be listened to all at once without
// requiring to write a big select statement
func MultiChannelWatch(watches []ChannelWatch) {
	cases := make([]reflect.SelectCase, 0)
	for _, watch := range watches {
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: watch.Chan,
		})
	}

	for {
		index, value, _ := reflect.Select(cases)
		if value.CanInterface() {
			exit := watches[index].Callback(value.Interface())
			if exit {
				return
			}
		} else {
			exit := watches[index].Callback(struct{}{})
			if exit {
				return
			}
		}
	}
}

// WatchAndProcessSubChanges returns ChannelWatch for use with MultiChannelWatch,
// which simply watches for subscription changes and calls Subscription.ProcessChange()
// to process each.
func WatchAndProcessSubChanges(sub Subscription) ChannelWatch {
	return ChannelWatch{
		Chan: reflect.ValueOf(sub.MsgChan()),
		Callback: func(value interface{}) (exit bool) {
			change, ok := value.(Change)
			if ok {
				sub.ProcessChange(change)
			}
			return false
		},
	}
}
