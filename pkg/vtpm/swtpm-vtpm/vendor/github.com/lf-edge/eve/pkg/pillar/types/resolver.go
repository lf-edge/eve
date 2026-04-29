// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"path/filepath"
	"strings"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
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

// IfnameToResolvConf : Look for resolv.conf file(s) created by dhcpcd
// for a given interface.
func IfnameToResolvConf(ifname string) (filenames []string) {
	for _, d := range ResolveConfDirs {
		filename := fmt.Sprintf("%s/%s.dhcp", d, ifname)
		if fileutils.FileExists(nil, filename) {
			filenames = append(filenames, filename)
		}
		filename = fmt.Sprintf("%s/%s.dhcp6", d, ifname)
		if fileutils.FileExists(nil, filename) {
			filenames = append(filenames, filename)
		}
		filename = fmt.Sprintf("%s/%s.ra", d, ifname)
		if fileutils.FileExists(nil, filename) {
			filenames = append(filenames, filename)
		}
	}
	return filenames
}

// ResolvConfToIfname : Returns the name of the interface for which
// the given resolv.conf file was created.
func ResolvConfToIfname(resolvConf string) string {
	ext := filepath.Ext(resolvConf)
	if ext != ".dhcp" && ext != ".dhcp6" && ext != ".ra" {
		return ""
	}
	for _, d := range ResolveConfDirs {
		if strings.HasPrefix(resolvConf, d) {
			return strings.TrimSuffix(filepath.Base(resolvConf), ext)
		}
	}
	return ""
}
