// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package logging

import (
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"
)

// GetMyStack is used to log stack traces at certain call sites
// Excludes ourselves
func GetMyStack() string {
	var output string
	const maximumCallerDepth = 25
	pcs := make([]uintptr, maximumCallerDepth)
	depth := runtime.Callers(0, pcs)
	frames := runtime.CallersFrames(pcs[:depth])

	output += "goroutine:\n"
	for f, again := frames.Next(); again; f, again = frames.Next() {
		// Exclude the top and bottom ones
		if strings.HasSuffix(f.Function, "runtime.Callers") ||
			strings.HasSuffix(f.Function, "runtime.main") {
			continue
		}
		// Exclude myself
		if strings.HasSuffix(f.Function, ".GetMyStack") {
			continue
		}
		output += fmt.Sprintf("%s()\n\t%s:%d\n", f.Function, f.File, f.Line)
	}
	return output
}

// NoSuitableAddrStr - the string to be used for checking the error message
// Since the golang net package does not export this, we have to define it here again
const NoSuitableAddrStr string = "no suitable address found"

// IsNoSuitableAddrErr - the function to check 'no suitable address' for http mainly
func IsNoSuitableAddrErr(err error) bool {
	e0, ok := err.(*url.Error)
	if !ok {
		return false
	}
	e1, ok := e0.Err.(*net.OpError)
	if !ok {
		return false
	}
	switch t := e1.Err.(type) {
	case *net.DNSError:
		// seen this in http and oci cases
		if strings.HasSuffix(t.Err, NoSuitableAddrStr) {
			return true
		}
	case *net.AddrError:
		// this was originally in send.go
		if t.Err == NoSuitableAddrStr {
			return true
		}
	default:
		return false
	}
	return false
}
