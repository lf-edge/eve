// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package logging

import (
	"fmt"
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
