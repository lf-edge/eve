//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package pcidb

import (
	"github.com/jaypipes/pcidb/internal"
	"github.com/jaypipes/pcidb/types"
)

type DB = types.DB
type Product = types.Product
type Vendor = types.Vendor
type Class = types.Class
type Subclass = types.Subclass
type ProgrammingInterface = types.ProgrammingInterface
type WithOption = types.WithOption

// WithChroot overrides the root directory used for discovery of pci-ids
// database files.
var WithChroot = types.WithChroot

// WithCachePath overrides the directory that pcidb uses to look up
// pre-found/pre-fetching pci.ids database files.
var WithCachePath = types.WithCachePath

// WithCacheOnly disables lookup of pci.ids database files over the network and
// forces pcidb to only use any pre-cached pci.ids database files in its cache
// directory.
var WithCacheOnly = types.WithCacheOnly

// WithPath overrides the pci.ids database file discovery and points pcidb at a
// known location of a pci.ids or pci.ids.gz database file.
var WithPath = types.WithPath

// DEPRECATED. Here for backwards-compat
var WithDirectPath = WithPath

// WithEnableNetworkFetch enables the fetching of pci.ids database files over
// the Internet if a pci.ids database file cannot be found on the host
// filesystem or the pcidb cache directory.
var WithEnableNetworkFetch = types.WithEnableNetworkFetch

// Backward-compat, please refer to the pcidb types.DB type definition
type PCIDB = types.DB

// New returns a pointer to a pcidb.DB struct which contains information you can
// use to query PCI vendor, product and class information.
//
// It accepts zero or more pointers to WithOption structs. If you want to
// modify the behaviour of pcidb, use one of the option modifiers when calling
// New.
//
// For example, to change the root directory that pcidb uses when discovering
// pciids DB files, call New(WithChroot("/my/root/override"))
func New(opts ...*types.WithOption) (*types.DB, error) {
	merged := internal.MergeOptions(opts...)
	f, err := internal.Discover(merged)
	if err != nil {
		return nil, err
	}
	return internal.FromReader(f), nil
}
