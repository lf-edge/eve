// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"strings"

	uuid "github.com/satori/go.uuid"
)

// Really a constant
var nilUUID = uuid.UUID{}

// Stringer is a type constraint for anything that implements String() string.
type Stringer interface {
	String() string
}

// ToStrings converts a slice of Stringer values to a slice of strings.
func ToStrings[T Stringer](items []T) []string {
	strs := make([]string, len(items))
	for i, item := range items {
		strs[i] = item.String()
	}
	return strs
}

// JoinStrings joins a slice of Stringer values using the given separator.
func JoinStrings[T Stringer](items []T, sep string) string {
	return strings.Join(ToStrings(items), sep)
}
