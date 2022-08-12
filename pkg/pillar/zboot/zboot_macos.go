// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Zboot mac OS specific calls

//go:build darwin
// +build darwin

package zboot

func zbootMount(devname string, target string, fstype string,
	flags MountFlags, data string) (err error) {
	// Dummy function to allow compilation on OSX
	return nil
}
