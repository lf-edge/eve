// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"fmt"
	"runtime"
	"strings"
)

// MemAllocationSite is the return value of GetMemProfile
type MemAllocationSite struct {
	InUseBytes   int64
	InUseObjects int64
	AllocBytes   int64
	AllocObjects int64
	PrintedStack string
}

// GetMemAllocationSites returns the non-zero allocation sites in the form of
// an array of strings; each string is for one allocation call site.
// If reportZeroInUse is set it also reports with zero InUse.
func GetMemAllocationSites(reportZeroInUse bool) (int, []MemAllocationSite) {
	var sites []MemAllocationSite

	// Determine how many sites we have
	nprof := 100
	prof := make([]runtime.MemProfileRecord, 100)
	var n = 0
	for {
		var ok bool
		n, ok = runtime.MemProfile(prof, reportZeroInUse)
		if ok {
			break
		}
		fmt.Printf("MemProfile failed for %d\n", nprof)
		nprof += 100
		prof = append(prof, make([]runtime.MemProfileRecord, 100)...)
	}
	for i := 0; i < n; i++ {
		site := MemAllocationSite{
			InUseBytes:   prof[i].InUseBytes(),
			InUseObjects: prof[i].InUseObjects(),
			AllocBytes:   prof[i].AllocBytes,
			AllocObjects: prof[i].AllocObjects,
		}
		frames := runtime.CallersFrames(prof[i].Stack())

		var lines string
		for {
			frame, more := frames.Next()
			// Don't print the entries inside the runtime
			// XXX
			if false && strings.Contains(frame.File, "runtime/") {
				if !more {
					break
				}
				continue
			}
			line := fmt.Sprintf("%s[%d] %s\n",
				frame.File, frame.Line, frame.Function)
			lines += line
			if !more {
				break
			}
		}
		site.PrintedStack = lines
		sites = append(sites, site)
	}
	return n, sites
}
