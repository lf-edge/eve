// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import "syscall"

func getOsVersion() string {
	var uname syscall.Utsname

	syscall.Uname(&uname)
	b := make([]rune, len(uname.Release[:]))

	for i, v := range uname.Release {
		b[i] = rune(v)
	}

	return string(b)
}
