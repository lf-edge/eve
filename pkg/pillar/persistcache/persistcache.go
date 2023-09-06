// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package persistcache

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

type persistCache struct {
	sync.Mutex
	cache map[string][]byte
	root  string
}

const FileMask = 0755
const LockFileName = "persistcache.lock"

type InvalidKeyError struct{}

func (e *InvalidKeyError) Error() string {
	return "Key is invalid"
}

type InvalidValueError struct{}

func (e *InvalidValueError) Error() string {
	return "Value is invalid"
}

// New values from cache or creates path if there's none
func New(path string) (*persistCache, error) {
	pc := &persistCache{}
	pc.root = path
	pc.cache = make(map[string][]byte)

	if _, err := os.Stat(pc.root); os.IsNotExist(err) {
		if err := os.MkdirAll(pc.root, FileMask); err != nil {
			return nil, err
		}
		return pc, nil
	}

	err := filepath.WalkDir(pc.root, func(path string, di fs.DirEntry, err error) error {
		// We skip all directories
		if di.IsDir() {
			return nil
		}

		// lazy initialization
		pc.cache[di.Name()] = []byte{}

		return nil
	})

	return pc, err
}

func (pc *persistCache) loadObject(objName string) error {
	path := filepath.Join(pc.root, objName)
	val, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	pc.cache[filepath.Base(path)] = val

	return nil
}

// Get value from cache
func (pc *persistCache) Get(key string) ([]byte, error) {
	pc.Lock()
	defer pc.Unlock()

	if len(pc.cache[key]) == 0 {
		if err := pc.loadObject(key); err != nil {
			return []byte{}, err
		}
	}

	val, _ := pc.cache[key]

	return val, nil
}

// Create or update value in in-memory cache and filesystem
func (pc *persistCache) Put(key string, val []byte) (string, error) {
	pc.Lock()
	defer pc.Unlock()

	if !isValidKey(key) {
		return "", &InvalidKeyError{}
	}
	if !isValidValue(val) {
		return "", &InvalidValueError{}
	}

	// save file
	filepath := filepath.Join(pc.root, key)
	if err := fileutils.WriteRename(filepath, val); err != nil {
		return "", err
	}

	pc.cache[key] = val

	return filepath, nil
}

// Remove element from cache and filesystem
func (pc *persistCache) Delete(key string) error {
	pc.Lock()
	defer pc.Unlock()

	delete(pc.cache, key)
	return os.Remove(filepath.Join(pc.root, key))
}

func isValidKey(key string) bool {
	key = path.Clean(key)

	if strings.Contains(key, "/") {
		// in case of key being ../../../../../../etc/passwd
		return false
	} else if key == LockFileName {
		// because this filename is reserved for lock file which
		// is used to check if persistcache used by another program,
		// process
		return false
	}

	return true
}

func isValidValue(val []byte) bool {
	// because we lazy initialize values with empty slices
	// and it doesn't make sense create file with empty contents
	return len(val) != 0
}
