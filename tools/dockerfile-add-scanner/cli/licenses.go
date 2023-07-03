// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

// all of these taken from https://github.com/golang/pkgsite/blob/8996ff632abee854aef1b764ca0501f262f8f523/internal/licenses/licenses.go#L338
// which unfortunately is not exported. But fortunately is under BSD-style license.

var (
	fileNames = []string{
		"COPYING",
		"COPYING.md",
		"COPYING.markdown",
		"COPYING.txt",
		"LICENCE",
		"LICENCE.md",
		"LICENCE.markdown",
		"LICENCE.txt",
		"LICENSE",
		"LICENSE.md",
		"LICENSE.markdown",
		"LICENSE.txt",
		"LICENSE-2.0.txt",
		"LICENCE-2.0.txt",
		"LICENSE-APACHE",
		"LICENCE-APACHE",
		"LICENSE-APACHE-2.0.txt",
		"LICENCE-APACHE-2.0.txt",
		"LICENSE-MIT",
		"LICENCE-MIT",
		"LICENSE.MIT",
		"LICENCE.MIT",
		"LICENSE.code",
		"LICENCE.code",
		"LICENSE.docs",
		"LICENCE.docs",
		"LICENSE.rst",
		"LICENCE.rst",
		"MIT-LICENSE",
		"MIT-LICENCE",
		"MIT-LICENSE.md",
		"MIT-LICENCE.md",
		"MIT-LICENSE.markdown",
		"MIT-LICENCE.markdown",
		"MIT-LICENSE.txt",
		"MIT-LICENCE.txt",
		"MIT_LICENSE",
		"MIT_LICENCE",
		"UNLICENSE",
		"UNLICENCE",
	}
)

var licenseFileNames map[string]bool

func init() {
	licenseFileNames = make(map[string]bool)
	for _, name := range fileNames {
		licenseFileNames[name] = true
	}
}
