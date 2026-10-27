// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package memory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/zededa/ghw/internal/log"
	"github.com/zededa/ghw/pkg/linuxpath"
	"github.com/zededa/ghw/pkg/unitutil"
	"github.com/zededa/ghw/pkg/util"
)

func CachesForNode(ctx context.Context, nodeID int) ([]*Cache, error) {
	// The /sys/devices/node/nodeX directory contains a subdirectory called
	// 'cpuX' for each logical processor assigned to the node. Each of those
	// subdirectories containers a 'cache' subdirectory which contains a number
	// of subdirectories beginning with 'index' and ending in the cache's
	// internal 0-based identifier. Those subdirectories contain a number of
	// files, including 'shared_cpu_list', 'size', and 'type' which we use to
	// determine cache characteristics.
	paths := linuxpath.New(ctx)
	path := filepath.Join(
		paths.SysDevicesSystemNode,
		fmt.Sprintf("node%d", nodeID),
	)
	caches := make(map[string]*Cache)

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		filename := file.Name()
		if !strings.HasPrefix(filename, "cpu") {
			continue
		}
		if filename == "cpumap" || filename == "cpulist" {
			// There are two files in the node directory that start with 'cpu'
			// but are not subdirectories ('cpulist' and 'cpumap'). Ignore
			// these files.
			continue
		}
		// Grab the logical processor ID by cutting the integer from the
		// /sys/devices/system/node/nodeX/cpuX filename
		cpuPath := filepath.Join(path, filename)
		lpID, _ := strconv.Atoi(filename[3:])

		// Inspect the caches for each logical processor. There will be a
		// /sys/devices/system/node/nodeX/cpuX/cache directory containing a
		// number of directories beginning with the prefix "index" followed by
		// a number. The number indicates the level of the cache, which
		// indicates the "distance" from the processor. Each of these
		// directories contains information about the size of that level of
		// cache and the processors mapped to it.
		cachePath := filepath.Join(cpuPath, "cache")
		if _, err = os.Stat(cachePath); errors.Is(err, os.ErrNotExist) {
			continue
		}
		cacheDirFiles, err := os.ReadDir(cachePath)
		if err != nil {
			return nil, err
		}
		for _, cacheDirFile := range cacheDirFiles {
			cacheDirFileName := cacheDirFile.Name()
			if !strings.HasPrefix(cacheDirFileName, "index") {
				continue
			}
			dir := filepath.Join(cachePath, cacheDirFileName)
			c, err := readCacheIndex(dir)
			if err != nil {
				log.Warn(ctx, "cache %s: %s", dir, err)
				continue
			}

			// The cache information is repeated for each logical processor
			// sharing the cache, so keep one Cache object per instance. Keying
			// by the kernel's cache ID also merges caches shared across NUMA
			// nodes (e.g., L3 in Sub-NUMA Clustering) into one.
			key := cacheKey(c, dir, lpID)
			cache, exists := caches[key]
			if !exists {
				c.LogicalProcessors = make([]uint32, 0)
				cache = c
				caches[key] = cache
			}
			cache.LogicalProcessors = append(
				cache.LogicalProcessors,
				uint32(lpID),
			)
		}
	}

	cacheVals := make([]*Cache, len(caches))
	x := 0
	for _, c := range caches {
		// ensure the cache's processor set is sorted by logical process ID
		sort.Sort(SortByLogicalProcessorId(c.LogicalProcessors))
		cacheVals[x] = c
		x++
	}

	return cacheVals, nil
}

// cacheTypeFromSysfs maps the content of a cache's sysfs "type" file.
func cacheTypeFromSysfs(s string) CacheType {
	switch strings.TrimSpace(s) {
	case "Data":
		return CacheTypeData
	case "Instruction":
		return CacheTypeInstruction
	default:
		return CacheTypeUnified
	}
}

// Caches returns every cache instance of the host's online logical processors,
// read from /sys/devices/system/cpu/cpuN/cache: one entry per instance with
// all the logical processors sharing it, sorted by level, type and first
// logical processor. Instances are told apart by their kernel ID, or, where
// the kernel does not number them, by the set of logical processors sharing
// them. The error is only for a CPU directory that cannot be listed.
func Caches(ctx context.Context) ([]*Cache, error) {
	paths := linuxpath.New(ctx)
	cpuDirs, err := os.ReadDir(paths.SysDevicesSystemCPU)
	if err != nil {
		return nil, err
	}
	caches := map[string]*Cache{}
	for _, cpuDir := range cpuDirs {
		name := cpuDir.Name()
		id, err := strconv.ParseUint(strings.TrimPrefix(name, "cpu"), 10, 31)
		if err != nil || !strings.HasPrefix(name, "cpu") {
			continue
		}
		lpID := int(id)
		if online, err := util.ReadInt(filepath.Join(paths.SysDevicesSystemCPU, name, "online")); err == nil && online == 0 {
			continue
		}
		cacheDir := filepath.Join(paths.SysDevicesSystemCPU, name, "cache")
		indexes, err := os.ReadDir(cacheDir)
		if err != nil {
			continue
		}
		for _, index := range indexes {
			if !strings.HasPrefix(index.Name(), "index") {
				continue
			}
			dir := filepath.Join(cacheDir, index.Name())
			c, err := readCacheIndex(dir)
			if err != nil {
				log.Warn(ctx, "cache %s: %s", dir, err)
				continue
			}
			key := cacheKey(c, dir, lpID)
			cache, ok := caches[key]
			if !ok {
				cache = c
				caches[key] = cache
			}
			cache.LogicalProcessors = append(cache.LogicalProcessors, uint32(id))
		}
	}

	result := make([]*Cache, 0, len(caches))
	for _, c := range caches {
		sort.Sort(SortByLogicalProcessorId(c.LogicalProcessors))
		result = append(result, c)
	}
	sort.Sort(SortByCacheLevelTypeFirstProcessor(result))
	return result, nil
}

// cacheKey tells cache instances apart: by the kernel's ID, or, where the kernel
// does not number them, by the logical processors sharing the cache, read from
// dir. A cache whose sharing list is blank is logical processor lpID's own.
func cacheKey(c *Cache, dir string, lpID int) string {
	if c.ID >= 0 {
		return fmt.Sprintf("%d-%d-id%d", c.Level, c.Type, c.ID)
	}
	shared, _ := os.ReadFile(filepath.Join(dir, "shared_cpu_list"))
	cpus := strings.TrimSpace(string(shared))
	if cpus == "" {
		cpus = fmt.Sprintf("own%d", lpID)
	}
	return fmt.Sprintf("%d-%d-cpus%s", c.Level, c.Type, cpus)
}

// readCacheIndex reads the cache a cache/indexN directory describes: its level,
// type, kernel ID (-1 when the kernel does not number it) and size. The error
// is for a level that cannot be read or does not fit a Cache.
func readCacheIndex(dir string) (*Cache, error) {
	level, err := util.ReadInt(filepath.Join(dir, "level"))
	if err != nil {
		return nil, err
	}
	if level < 0 || level > math.MaxUint8 {
		return nil, fmt.Errorf("cache level %d is out of range", level)
	}
	typeContents, _ := os.ReadFile(filepath.Join(dir, "type"))
	id, err := util.ReadInt(filepath.Join(dir, "id"))
	if err != nil {
		id = -1
	}
	return &Cache{
		Level:     uint8(level),
		Type:      cacheTypeFromSysfs(string(typeContents)),
		ID:        id,
		SizeBytes: readCacheSize(dir),
	}, nil
}

// readCacheSize reads a cache's size, such as "32K", in bytes; 0 when it is
// not reported.
func readCacheSize(dir string) uint64 {
	data, err := os.ReadFile(filepath.Join(dir, "size"))
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	multiplier := uint64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		multiplier = uint64(unitutil.KB)
	case strings.HasSuffix(s, "M"):
		multiplier = uint64(unitutil.MB)
	case strings.HasSuffix(s, "G"):
		multiplier = uint64(unitutil.GB)
	}
	n, err := strconv.ParseUint(strings.TrimRight(s, "KMG"), 10, 64)
	if err != nil {
		return 0
	}
	return n * multiplier
}
