// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// maxAddrErrorsLen bounds what addrErrors reports: one or two failures with
// their addresses and a count of the rest. It leaves the content tree, the
// volume and the application built on top of it room within
// types.MaxErrorLen for what they add.
const maxAddrErrorsLen = 1024

// addrErrors collects the failure of each source address a download was
// tried from. The same failure from several addresses is reported once,
// with the addresses, and the report stays within maxAddrErrorsLen however
// many addresses failed: on a device with several management ports the
// error used to grow with their number, for every blob of an image.
type addrErrors struct {
	texts []string            // distinct failures, in order of first occurrence
	addrs map[string][]string // failure -> source addresses it came from
}

// add records that the download from addr, empty when no address applies,
// failed with err.
func (e *addrErrors) add(addr string, err error) {
	text := err.Error()
	if e.addrs == nil {
		e.addrs = make(map[string][]string)
	}
	if _, seen := e.addrs[text]; !seen {
		e.texts = append(e.texts, text)
		e.addrs[text] = nil
	}
	if addr != "" {
		e.addrs[text] = append(e.addrs[text], addr)
	}
}

func (e *addrErrors) empty() bool {
	return len(e.texts) == 0
}

// String lists the failures, each with the addresses it came from.
func (e *addrErrors) String() string {
	parts := make([]string, 0, len(e.texts))
	for _, text := range e.texts {
		if addrs := e.addrs[text]; len(addrs) > 0 {
			text += " (from " + strings.Join(addrs, ", ") + ")"
		}
		parts = append(parts, text)
	}
	return types.JoinMaxErrorStrings(parts, "\n", maxAddrErrorsLen)
}
