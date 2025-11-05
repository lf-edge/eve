//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package internal

import (
	"fmt"
	"os"
	"strconv"

	"github.com/jaypipes/pcidb/types"
)

func MergeOptions(opts ...*types.WithOption) *types.WithOption {
	// Grab options from the environs by default
	chroot := types.DefaultChroot
	if val, exists := os.LookupEnv(types.EnvVarChroot); exists {
		chroot = val
	}
	path := ""
	if val, exists := os.LookupEnv(types.EnvVarPath); exists {
		path = val
	}
	cacheOnly := types.DefaultCacheOnly
	if val, exists := os.LookupEnv(types.EnvVarCacheOnly); exists {
		if parsed, err := strconv.ParseBool(val); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"Failed parsing a bool from %s "+
					"environ value of %s",
				types.EnvVarCacheOnly, val,
			)
		} else if parsed {
			cacheOnly = parsed
		}
	}
	enableNetworkFetch := types.DefaultEnableNetworkFetch
	if val, exists := os.LookupEnv(types.EnvVarEnableNetworkFetch); exists {
		if parsed, err := strconv.ParseBool(val); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"Failed parsing a bool from %s environ value of %s",
				types.EnvVarEnableNetworkFetch, val,
			)
		} else if parsed {
			enableNetworkFetch = parsed
		}
	}

	merged := &types.WithOption{}
	for _, opt := range opts {
		if opt.Chroot != nil {
			merged.Chroot = opt.Chroot
		}
		if opt.CacheOnly != nil {
			merged.CacheOnly = opt.CacheOnly
		}
		if opt.EnableNetworkFetch != nil {
			merged.EnableNetworkFetch = opt.EnableNetworkFetch
		}
		if opt.Path != nil {
			merged.Path = opt.Path
		}
	}
	// Set the default value if missing from merged
	if merged.Chroot == nil {
		merged.Chroot = &chroot
	}
	if merged.CacheOnly == nil {
		merged.CacheOnly = &cacheOnly
	}
	if merged.EnableNetworkFetch == nil {
		merged.EnableNetworkFetch = &enableNetworkFetch
	}
	if merged.Path == nil {
		merged.Path = &path
	}
	return merged
}
