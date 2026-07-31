// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"reflect"
)

type opActionLine uint8

// ActionPath is implemented by actions that match on file paths.
type ActionPath interface {
	MatchPath(path string) bool
}

// ActionDiff is implemented by actions that match on line-level diffs.
type ActionDiff interface {
	MatchDiff(path string, ld LineDiff) bool
}

// Action is the interface for executable actions.
type Action interface {
	Do(actionToDos []ActionToDo) error
	Close()
}

// IDer is implemented by actions that provide a custom identifier.
type IDer interface {
	ID() string
}

// ID returns the identifier for an action, using IDer if available,
// otherwise falling back to the type name.
func ID(i any) string {
	ider, ok := i.(IDer)
	if ok {
		return ider.ID()
	}
	ty := reflect.TypeOf(i)
	if ty.Name() == "" {
		ty = reflect.TypeOf(i).Elem()
	}
	return ty.Name()
}
