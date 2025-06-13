// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DhcpcdResolvConfDir : directory where dhcpcd stores resolv.conf
	// files separately for every interface (named <interface>.dhcp).
	DhcpcdResolvConfDir = "/run/dhcpcd/resolv.conf"
	// WwanResolvConfDir : directory where wwan microservice stores resolv.conf
	// files separately for every interface (named <interface>.dhcp).
	WwanResolvConfDir = "/run/wwan/resolv.conf"
)

// ResolveConfDirs : directories where resolv.conf for an interface could be found.
var ResolveConfDirs = []string{DhcpcdResolvConfDir, WwanResolvConfDir}

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
