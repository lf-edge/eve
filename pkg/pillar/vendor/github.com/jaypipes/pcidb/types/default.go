//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

import (
	"os"
	"path/filepath"
)

const (
	DefaultChroot             = "/"
	DefaultCacheOnly          = false
	DefaultEnableNetworkFetch = false
)

var (
	DefaultCachePath = getCachePath()
)

func getCachePath() string {
	hdir, err := os.UserHomeDir()
	if err != nil {
		// os.UserHomeDir() returns an error when $HOME isn't set on Linux.
		// This is the only error os.UserHomeDir() returns, and we don't care
		// about it, so just ignore the error.
		//
		// https://github.com/jaypipes/pcidb/issues/38
		return ""
	}
	return filepath.Join(hdir, ".cache", "pci.ids")
}
