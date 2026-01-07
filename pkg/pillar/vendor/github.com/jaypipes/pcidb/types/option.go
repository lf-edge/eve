//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package types

var (
	trueVar = true
)

// WithOption is used to represent optionally-configured settings
type WithOption struct {
	// Chroot is the directory that pcidb uses when attempting to discover
	// pciids DB files
	Chroot *string
	// CacheOnly is mostly just useful for testing. It essentially disables
	// looking for any non ~/.cache/pci.ids filepaths (which is useful when we
	// want to test the fetch-from-network code paths
	CacheOnly *bool
	// CachePath overrides the pcidb cache path, which defaults to
	// $HOME/.cache/pci.ids
	CachePath *string
	// Enables fetching a pci-ids from a known location on the network if no
	// local pci-ids DB files can be found.
	EnableNetworkFetch *bool
	// Path points to the absolute path of a pci.ids file in a non-standard
	// location.
	Path *string
}

// WithChroot overrides the root directory used for discovery of pci-ids
// database files.
func WithChroot(dir string) *WithOption {
	return &WithOption{Chroot: &dir}
}

// WithCachePath overrides the directory that pcidb uses to look up
// pre-found/pre-fetching pci.ids database files.
func WithCachePath(path string) *WithOption {
	return &WithOption{CachePath: &path}
}

// WithCacheOnly disables lookup of pci.ids database files over the network and
// forces pcidb to only use any pre-cached pci.ids database files in its cache
// directory.
func WithCacheOnly() *WithOption {
	return &WithOption{CacheOnly: &trueVar}
}

// WithPath overrides the pci.ids database file discovery and points pcidb at a
// known location of a pci.ids or pci.ids.gz database file.
func WithPath(path string) *WithOption {
	return &WithOption{Path: &path}
}

// Backwards-compat
var WithDirectPath = WithPath

// WithEnableNetworkFetch enables the fetching of pci.ids database files over
// the Internet if a pci.ids database file cannot be found on the host
// filesystem or the pcidb cache directory.
func WithEnableNetworkFetch() *WithOption {
	return &WithOption{EnableNetworkFetch: &trueVar}
}
