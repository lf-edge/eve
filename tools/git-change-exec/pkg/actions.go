// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier:: Apache-2.0

package pkg

import (
	"reflect"
)

type opActionLine uint8

type ActionPath interface {
	MatchPath(path string) bool
}
type ActionDiff interface {
	MatchDiff(path string, ld LineDiff) bool
}
type Action interface {
	Do(actionToDos []ActionToDo) error
	Close()
}
type Ider interface {
	Id() string
}

func Id(i any) string {
	ider, ok := i.(Ider)
	if ok {
		return ider.Id()
	}
	ty := reflect.TypeOf(i)
	if ty.Name() == "" {
		ty = reflect.TypeOf(i).Elem()
	}
	return ty.Name()
}
