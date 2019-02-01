// This file is built only for linux
// +build linux

package types

import (
	"syscall"
)

func GetDefaultRouteTable() int {
	return syscall.RT_TABLE_MAIN
}
