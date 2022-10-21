// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
// NOTE: cloned from pkg/pillar/utils/logging to avoid circular vendoring

package http

import (
	"net"
	"net/url"
	"strings"
)

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
