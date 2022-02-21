// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveConfDirs : directories where resolv.conf for an interface could be found.
var ResolveConfDirs = []string{"/run/dhcpcd/resolv.conf", "/run/wwan/resolv.conf"}

// IfnameToResolvConf : Look for a file created by dhcpcd
func IfnameToResolvConf(ifname string) string {
	for _, d := range ResolveConfDirs {
		filename := fmt.Sprintf("%s/%s.dhcp", d, ifname)
		_, err := os.Stat(filename)
		if err == nil {
			return filename
		}
	}
	return ""
}

// ResolvConfToIfname : Returns the name of the interface for which
// the given resolv.conf file was created.
func ResolvConfToIfname(resolvConf string) string {
	ext := filepath.Ext(resolvConf)
	if ext != ".dhcp" {
		return ""
	}
	for _, d := range ResolveConfDirs {
		if strings.HasPrefix(resolvConf, d) {
			return strings.TrimSuffix(filepath.Base(resolvConf), ext)
		}
	}
	return ""
}
