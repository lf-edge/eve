//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package internal

import (
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jaypipes/pcidb/types"
)

const (
	pciidsURI = "https://pci-ids.ucw.cz/v2.2/pci.ids.gz"
	userAgent = "golang-jaypipes-pcidb"
)

// Discover returns an io.Reader for an opened PCIIDS database file or gzipped
// database file. It examines the supplied context/options and determines where
// to find a PCIIDS database file, from a cached location, a supplied path
// override, one of a set of well-known filesystem locations (on Linux) or even
// fetching the canonical PCIIDS database file from the network (as a last
// resort and only when network fetching has been enabled with the
// PCIDB_ENABLE_NETWORK_FETCH=1 environment variable)
func Discover(opts *types.WithOption) (io.ReadCloser, error) {
	var foundPath string
	for _, fp := range searchPaths(opts) {
		if _, err := os.Stat(fp); err == nil {
			foundPath = fp
			break
		}
	}

	if foundPath == "" {
		if opts.EnableNetworkFetch != nil && !*opts.EnableNetworkFetch {
			return nil, types.ErrNoDB
		}
		var cachePath = types.DefaultCachePath
		if opts.CachePath != nil && *opts.CachePath != "" {
			cachePath = *opts.CachePath
		}
		if cachePath == "" {
			return nil, types.ErrNoPaths
		}
		// OK, so we didn't find any host-local copy of the pci-ids DB file. Let's
		// try fetching it from the network and storing it
		if err := cacheDBFile(cachePath); err != nil {
			return nil, err
		}
		foundPath = cachePath
	}
	f, err := os.Open(foundPath)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(foundPath, ".gz") {
		var zipReader *gzip.Reader
		if zipReader, err = gzip.NewReader(f); err != nil {
			return nil, err
		}
		return zipReader, nil
	}
	return f, nil
}

// Depending on the operating system, sets the context's searchPaths to a set
// of local filepaths to search for a pci.ids database file
func searchPaths(opts *types.WithOption) []string {
	// Look in direct path first, if set
	if opts.Path != nil && *opts.Path != "" {
		return []string{*opts.Path}
	}
	paths := []string{}
	// A set of filepaths we will first try to search for the pci-ids DB file
	// on the local machine. If we fail to find one, we'll try pulling the
	// latest pci-ids file from the network
	cachePath := types.DefaultCachePath
	if opts.CachePath != nil {
		cachePath = *opts.CachePath
	}
	paths = append(paths, cachePath)
	if opts.CacheOnly != nil && *opts.CacheOnly {
		return paths
	}

	rootPath := types.DefaultChroot
	if opts.Chroot != nil && *opts.Chroot != "" {
		rootPath = *opts.Chroot
	}

	if runtime.GOOS != "windows" {
		paths = append(
			paths,
			filepath.Join(rootPath, "usr", "share", "hwdata", "pci.ids"),
		)
		paths = append(
			paths,
			filepath.Join(rootPath, "usr", "share", "misc", "pci.ids"),
		)
		paths = append(
			paths,
			filepath.Join(rootPath, "usr", "share", "hwdata", "pci.ids.gz"),
		)
		paths = append(
			paths,
			filepath.Join(rootPath, "usr", "share", "misc", "pci.ids.gz"),
		)
	}
	return paths
}

func ensureDir(fp string) error {
	fpDir := filepath.Dir(fp)
	if _, err := os.Stat(fpDir); os.IsNotExist(err) {
		err = os.MkdirAll(fpDir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

// Pulls down the latest copy of the pci-ids file from the network and stores
// it in the local host filesystem
func cacheDBFile(cacheFilePath string) error {
	ensureDir(cacheFilePath)

	client := new(http.Client)
	request, err := http.NewRequest("GET", pciidsURI, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	f, err := os.Create(cacheFilePath)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(cacheFilePath)
		}
	}()
	defer f.Close()
	// write the gunzipped contents to our local cache file
	zr, err := gzip.NewReader(response.Body)
	if err != nil {
		return err
	}
	defer zr.Close()
	if _, err = io.Copy(f, zr); err != nil {
		return err
	}
	return err
}
