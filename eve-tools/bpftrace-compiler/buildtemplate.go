// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// heavily inspired by github.com/linuxkit/linuxkit

import (
	"github.com/linuxkit/linuxkit/src/cmd/linuxkit/spec"
)

const (
	defaultPkgBuildYML = "build.yml"
	defaultPkgCommit   = "HEAD"
	defaultPkgTag      = "{{.Hash}}"
)

func createPackageResolver(replacements map[string]string) spec.PackageResolver {
	return func(pkgTmpl string) (tag string, err error) {
		replacement, found := replacements[pkgTmpl]
		if found {
			return replacement, nil
		}

		return pkgTmpl, nil
	}
}
