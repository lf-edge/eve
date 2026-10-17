// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"sort"
)

// fileMeta records a live file's placement and logical length (in blocks).
type fileMeta struct {
	nblocks int
}

// model is the expected filesystem state reconstructed by replaying the op
// stream. The writer advances it as it applies ops; the verifier rebuilds it up
// to the committed index and then checks the on-disk tree against it.
//
// liveIDs and dirList are kept sorted so that op selection (which live file to
// delete, which scratch dir to remove) is a pure function of the PRNG draw and
// therefore identical in the writer and the verifier — Go map iteration order is
// randomized and must never drive a selection.
type model struct {
	cfg     Config
	files   map[uint64]fileMeta
	liveIDs []uint64
	deleted map[uint64]bool
	dirs    map[string]bool
	dirList []string
}

func newModel(cfg Config) *model {
	return &model{
		cfg:     cfg,
		files:   make(map[uint64]fileMeta),
		deleted: make(map[uint64]bool),
		dirs:    make(map[string]bool),
	}
}

// filePath returns the volume-relative path of a file (see filePathFor).
func (m *model) filePath(fileID uint64) string {
	return filePathFor(m.cfg, fileID)
}

func (m *model) addFile(fileID uint64, nblocks int) {
	if _, ok := m.files[fileID]; !ok {
		i := sort.Search(len(m.liveIDs), func(i int) bool { return m.liveIDs[i] >= fileID })
		m.liveIDs = append(m.liveIDs, 0)
		copy(m.liveIDs[i+1:], m.liveIDs[i:])
		m.liveIDs[i] = fileID
	}
	m.files[fileID] = fileMeta{nblocks: nblocks}
	delete(m.deleted, fileID)
}

func (m *model) removeFile(fileID uint64) {
	if _, ok := m.files[fileID]; !ok {
		return
	}
	delete(m.files, fileID)
	i := sort.Search(len(m.liveIDs), func(i int) bool { return m.liveIDs[i] >= fileID })
	if i < len(m.liveIDs) && m.liveIDs[i] == fileID {
		m.liveIDs = append(m.liveIDs[:i], m.liveIDs[i+1:]...)
	}
	m.deleted[fileID] = true
}

func (m *model) addDir(dir string) {
	if m.dirs[dir] {
		return
	}
	m.dirs[dir] = true
	i := sort.SearchStrings(m.dirList, dir)
	m.dirList = append(m.dirList, "")
	copy(m.dirList[i+1:], m.dirList[i:])
	m.dirList[i] = dir
}

func (m *model) removeDir(dir string) {
	if !m.dirs[dir] {
		return
	}
	delete(m.dirs, dir)
	i := sort.SearchStrings(m.dirList, dir)
	if i < len(m.dirList) && m.dirList[i] == dir {
		m.dirList = append(m.dirList[:i], m.dirList[i+1:]...)
	}
}

// apply advances the model by one op.
func (m *model) apply(o op) {
	switch o.typ {
	case opCreate:
		m.addFile(o.fileID, o.nblocks)
	case opDelete:
		m.removeFile(o.fileID)
	case opMkdir:
		m.addDir(o.dir)
	case opRmdir:
		m.removeDir(o.dir)
	}
}
