// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"runtime"
	"strings"
)

// FuncNameFromStackTrace returns the name of the function at the given call stack depth.
// Parameters:
//
//	depth - the number of stack frames to skip:
//	        depth 0 = FuncNameFromStackTrace itself
//	        depth 1 = its caller
//	        depth 2 = caller's caller, etc.
func FuncNameFromStackTrace(depth int) string {
	pc, _, _, ok := runtime.Caller(depth)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}
	name := fn.Name()
	if idx := strings.LastIndex(name, "."); idx != -1 {
		name = name[idx+1:]
	}
	return name
}
