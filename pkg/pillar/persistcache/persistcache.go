// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package persistcache

import (
	"bytes"
	"crypto/sha256"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// PersistCache is main structure storing objects both
// in-memory and on file system
type PersistCache struct {
	sync.Mutex
	cache map[string]objectWrapper
	root  string
}

type objectWrapper struct {
	Val []byte
	Sha []byte
}

const fileMask = 0700

// InvalidKeyError returned when Get or Put are
// called with key which cannot be written or read
type InvalidKeyError struct{}

// Error returns error description string
func (e *InvalidKeyError) Error() string {
	return "Key is invalid"
}

// InvalidValueError returned when Put is
// called with empty value
type InvalidValueError struct{}

// Error returns error description string
func (e *InvalidValueError) Error() string {
	return "Value is invalid"
}

// New loads values from cache or creates path if there's none
func New(path string) (*PersistCache, error) {
	pc := &PersistCache{}
	pc.root = path
	pc.cache = make(map[string]objectWrapper)

	if _, err := os.Stat(pc.root); os.IsNotExist(err) {
		if err := os.MkdirAll(pc.root, fileMask); err != nil {
			return nil, err
		}
		return pc, nil
	}

	walkErr := filepath.WalkDir(pc.root, func(path string, di fs.DirEntry, err error) error {
		// We skip all directories
		if di.IsDir() {
			return nil
		}

		// if there is any problem with path we stop
		if err != nil {
			return err
		}

		sha, err := fileutils.ComputeShaFile(path)
		if err != nil {
			return err
		}

		// lazy initialization
		pc.cache[di.Name()] = objectWrapper{
			Val: []byte{},
			Sha: sha,
		}

		return nil
	})

	return pc, walkErr
}

// Get value from cache
func (pc *PersistCache) Get(key string) ([]byte, error) {
	pc.Lock()
	defer pc.Unlock()

	if len(pc.cache[key].Val) == 0 {
		if err := pc.loadObject(key); err != nil {
			return []byte{}, err
		}
	}

	obj := pc.cache[key]

	return obj.Val, nil
}

// Put creates or updates value in in-memory cache and filesystem
func (pc *PersistCache) Put(key string, val []byte) (string, error) {
	pc.Lock()
	defer pc.Unlock()

	if !isValidKey(key) {
		return "", &InvalidKeyError{}
	}
	if !isValidValue(val) {
		return "", &InvalidValueError{}
	}

	hash := sha256.New()
	hash.Write(val)

	newObj := objectWrapper{
		Val: val,
		Sha: hash.Sum(nil),
	}

	if _, ok := pc.cache[key]; ok {
		return pc.update(key, newObj)
	}

	return pc.create(key, newObj)
}

// Delete removes element from cache and filesystem
func (pc *PersistCache) Delete(key string) error {
	pc.Lock()
	defer pc.Unlock()

	delete(pc.cache, key)
	return os.Remove(filepath.Join(pc.root, key))
}

// Objects returns list objects stored in PersistCache
func (pc *PersistCache) Objects() []string {
	answer := make([]string, 0, len(pc.cache))

	for key := range pc.cache {
		answer = append(answer, key)
	}

	return answer
}

func (pc *PersistCache) loadObject(objName string) error {
	path := filepath.Join(pc.root, objName)

	val, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	sha, err := fileutils.ComputeShaFile(path)
	if err != nil {
		return err
	}

	pc.cache[filepath.Base(path)] = objectWrapper{
		Val: val,
		Sha: sha,
	}

	return nil
}

func (pc *PersistCache) update(key string, obj objectWrapper) (string, error) {
	if bytes.Equal(obj.Sha, pc.cache[key].Sha) {
		return filepath.Join(pc.root, key), nil
	}

	return pc.create(key, obj)
}

func (pc *PersistCache) create(key string, obj objectWrapper) (string, error) {
	filepath := filepath.Join(pc.root, key)

	if err := fileutils.WriteRename(filepath, obj.Val); err != nil {
		return "", err
	}

	pc.cache[key] = obj

	return filepath, nil
}

func isValidKey(key string) bool {
	key = path.Clean(key)

	return !strings.Contains(key, "/")
}

func isValidValue(val []byte) bool {
	// because we lazy initialize values with empty slices
	// and it doesn't make sense create file with empty contents
	return len(val) != 0
}
