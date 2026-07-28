// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// PersistType is type of persist we use
type PersistType uint8

// Enum of PersistType variants
const (
	PersistUnknown PersistType = iota
	PersistExt3
	PersistExt4
	PersistZFS
)

// ParsePersistType process provided string and returns PersistType
func ParsePersistType(persistFsString string) PersistType {
	switch persistFsString {
	case "ext3":
		return PersistExt3
	case "ext4":
		return PersistExt4
	case "zfs":
		return PersistZFS
	default:
		return PersistUnknown
	}
}

// returns string representation of PersistType
func (p PersistType) String() string {
	switch p {
	case PersistExt3:
		return "ext3"
	case PersistExt4:
		return "ext4"
	case PersistZFS:
		return "zfs"
	default:
		return ""
	}
}
